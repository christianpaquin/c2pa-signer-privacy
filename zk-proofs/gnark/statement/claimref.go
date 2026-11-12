package statement

// Claim references (spike for the claim privacy note, CLAIM-PRIVACY.md): a
// gadget that walks a private C2PA claim's CBOR and proves it references
// given assertions, that is, that its created_assertions array holds a
// hashed URI {"url": U, "hash": H} for each public (U, H). With the claim
// private, a verifier learns which assertions the original claim made only
// for those it is shown, each by its URL and the hash of its JUMBF superbox
// content (C2PA 2.5, §9.4.2.3), which the verifier computes itself.
//
// The walk tokenizes the whole claim, as CBOR, with a bounded stack: every
// item's header is read where the previous item ended, so a reference is
// accepted only as an actual entry of the top-level map's created_assertions
// array, never as bytes inside another field. The accepted profile (refused
// otherwise): only byte strings, text strings, arrays, and maps (major types
// 2-5); lengths in the short, 1-byte, or 2-byte forms; containers of fewer
// than 24 items; nesting up to claimMaxDepth; up to MaxTokens items; and
// exactly one created_assertions key.
//
// Each reference's hash algorithm must be SHA-256, as the claim declares it
// (C2PA 2.5, §10.2.2, §12.1): an entry's own "alg" overrides the claim's
// "alg", which applies otherwise; with neither, or another algorithm, the
// reference is refused, as are duplicate "alg" keys and a URL referenced by
// more than one entry. References occupy a fixed number of slots (MaxRefs),
// so that one circuit, and one key set, covers every disclosure count: slot
// 0, the hard binding, is always active; the others carry an active flag, and
// an inactive slot must be all zero.

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

const claimMaxDepth = 4 // the root map, created_assertions, an entry, its fields

// ClaimRefSizes are the gadget's limits.
type ClaimRefSizes struct {
	MaxClaim  int // the claim's bytes
	MaxTokens int // CBOR items walked (a real claim has 25)
	MaxURL    int // a reference's URL
	MaxRefs   int // reference slots: the hard binding, and up to MaxRefs-1 others
}

// DefaultClaimRefSizes: real claims are 377-384 bytes, 25 items, URLs of
// 41-43 bytes, and reference two assertions.
var DefaultClaimRefSizes = ClaimRefSizes{MaxClaim: 1024, MaxTokens: 64, MaxURL: 64, MaxRefs: 4}

// ClaimRef is a public reference slot: whether it is used, an assertion's URL
// (at most MaxURL bytes), and the SHA-256 of its JUMBF superbox content, in
// two 16-byte halves. An unused slot is all zero.
type ClaimRef struct {
	Active frontend.Variable
	URL    []frontend.Variable // zero-padded to MaxURL
	URLLen frontend.Variable
	Hash   [2]frontend.Variable
}

var (
	keyCreatedAssertions = append([]byte{0x60 + 18}, "created_assertions"...)
	keyURL               = append([]byte{0x63}, "url"...)
	keyHash              = append([]byte{0x64}, "hash"...)
	keyAlg               = append([]byte{0x63}, "alg"...)
	textSHA256           = append([]byte{0x66}, "sha256"...)
)

// assertClaimReferences walks the claim held in r (claimLen bytes from
// position 0) and asserts that its created_assertions array holds each
// active reference exactly once, with SHA-256 as its effective algorithm.
func assertClaimReferences(api frontend.API, r *reader, claimLen frontend.Variable, s ClaimRefSizes, refs []ClaimRef) {
	// Major type and additional information of a header byte.
	majorT, infoT := logderivlookup.New(api), logderivlookup.New(api)
	for b := 0; b < 256; b++ {
		majorT.Insert(b >> 5)
		infoT.Insert(b & 31)
	}
	small := cmp.NewBoundedComparator(api, big.NewInt(1<<9), false)
	isEq := r.isEq
	not := func(v frontend.Variable) frontend.Variable { return api.Sub(1, v) }

	// The slots: active flags are boolean, slot 0 (the hard binding) is
	// active, URLs fit the buffer, and an inactive slot is all zero.
	api.AssertIsEqual(refs[0].Active, 1)
	for _, ref := range refs {
		api.AssertIsBoolean(ref.Active)
		r.pos.AssertIsLessEq(ref.URLLen, s.MaxURL)
		inactive := not(ref.Active)
		api.AssertIsEqual(api.Mul(inactive, ref.URLLen), 0)
		api.AssertIsEqual(api.Mul(inactive, ref.Hash[0]), 0)
		api.AssertIsEqual(api.Mul(inactive, ref.Hash[1]), 0)
		for _, b := range ref.URL {
			api.AssertIsEqual(api.Mul(inactive, b), 0)
		}
		api.AssertIsEqual(api.Mul(ref.Active, r.pos.IsLess(ref.URLLen, 1)), 0) // an active URL is not empty
	}

	// The stack: remaining items per depth, and whether each level is a map.
	var rem, isMap [claimMaxDepth + 1]frontend.Variable
	rem[0], isMap[0] = 1, 0 // the root item
	for j := 1; j <= claimMaxDepth; j++ {
		rem[j], isMap[j] = 0, 0
	}
	depth := frontend.Variable(0)
	p := frontend.Variable(0)
	caKeys := frontend.Variable(0)    // created_assertions keys in the root map
	prevKeyCA := frontend.Variable(0) // the previous root-map key was created_assertions
	inCA := frontend.Variable(0)      // inside the created_assertions array
	prevKeyURL, prevKeyHash, prevKeyAlg := frontend.Variable(0), frontend.Variable(0), frontend.Variable(0)
	urlKeys, hashKeys, algKeys := frontend.Variable(0), frontend.Variable(0), frontend.Variable(0)
	elemAlgSHA := frontend.Variable(0)                                                                           // this entry's alg is sha256
	rootAlgKeys, prevRootKeyAlg, claimAlgSHA := frontend.Variable(0), frontend.Variable(0), frontend.Variable(0) // the claim's alg
	elemURL := make([]frontend.Variable, len(refs))
	elemHash := make([]frontend.Variable, len(refs))
	foundOwn := make([]frontend.Variable, len(refs))     // matched, with the entry's own alg sha256
	foundDefault := make([]frontend.Variable, len(refs)) // matched, with no alg of the entry's own
	urlCount := make([]frontend.Variable, len(refs))     // entries with the reference's URL
	for k := range refs {
		elemURL[k], elemHash[k], foundOwn[k], foundDefault[k], urlCount[k] = 0, 0, 0, 0, 0
	}

	level := func(arr [claimMaxDepth + 1]frontend.Variable, d frontend.Variable) frontend.Variable {
		v := frontend.Variable(0)
		for j := 0; j <= claimMaxDepth; j++ {
			v = api.Add(v, api.Mul(isEq(d, j), arr[j]))
		}
		return v
	}

	for t := 0; t < s.MaxTokens; t++ {
		active := not(api.IsZero(rem[0])) // the root item is not finished
		b0 := r.at(p)
		major, info := majorT.Lookup(b0)[0], infoT.Lookup(b0)[0]
		isBytes, isText, isArray, isMapT := isEq(major, 2), isEq(major, 3), isEq(major, 4), isEq(major, 5)
		r.assertIf(active, api.Add(isBytes, isText, isArray, isMapT), 1)
		short := small.IsLess(info, 24)
		one, two := isEq(info, 24), isEq(info, 25)
		r.assertIf(active, api.Add(short, one, two), 1)
		b1, b2 := r.at(api.Add(p, 1)), r.at(api.Add(p, 2))
		arg := api.Add(api.Mul(short, info), api.Mul(one, b1), api.Mul(two, api.Add(api.Mul(b1, 256), b2)))
		hl := api.Add(1, one, api.Mul(2, two))
		container := api.Add(isArray, isMapT)
		r.assertIf(api.Mul(active, container), short, 1) // containers of fewer than 24 items
		payload := api.Mul(api.Add(isBytes, isText), arg)
		next := api.Add(p, hl, payload)

		// Where this item sits: its depth, and whether it is a map key.
		d := depth
		remD, mapD := level(rem, d), level(isMap, d)
		// In a map of n pairs (2n items, counted down), keys come at even counts.
		isKey := api.Mul(mapD, keyParity(api, remD))
		atRoot1 := isEq(d, 1)
		atEntry := api.Mul(inCA, isEq(d, 3))

		// Root-map keys: created_assertions (exactly one).
		isCAKey := api.Mul(active, atRoot1, isKey, r.matches(p, keyCreatedAssertions))
		caKeys = api.Add(caKeys, isCAKey)
		// The claim's alg: at most one root key, a text value.
		isRootAlgKey := api.Mul(active, atRoot1, isKey, r.matches(p, keyAlg))
		rootAlgKeys = api.Add(rootAlgKeys, isRootAlgKey)
		isRootAlgValue := api.Mul(active, atRoot1, not(isKey), prevRootKeyAlg)
		r.assertIf(isRootAlgValue, isText, 1)
		claimAlgSHA = api.Add(claimAlgSHA, api.Mul(isRootAlgValue, r.matches(p, textSHA256)))
		// The value after the created_assertions key must be an array; it opens the walk of the entries.
		isCAValue := api.Mul(active, atRoot1, not(isKey), prevKeyCA)
		r.assertIf(isCAValue, isArray, 1)
		// Entries are maps.
		isEntry := api.Mul(active, inCA, isEq(d, 2))
		r.assertIf(isEntry, isMapT, 1)

		// Inside an entry: "url" and "hash" keys, then their values.
		isURLKey := api.Mul(active, atEntry, isKey, r.matches(p, keyURL))
		isHashKey := api.Mul(active, atEntry, isKey, r.matches(p, keyHash))
		isAlgKey := api.Mul(active, atEntry, isKey, r.matches(p, keyAlg))
		urlKeys = api.Add(urlKeys, isURLKey)
		hashKeys = api.Add(hashKeys, isHashKey)
		algKeys = api.Add(algKeys, isAlgKey)
		isAlgValue := api.Mul(active, atEntry, not(isKey), prevKeyAlg)
		r.assertIf(isAlgValue, isText, 1)
		elemAlgSHA = api.Add(elemAlgSHA, api.Mul(isAlgValue, r.matches(p, textSHA256)))
		isURLValue := api.Mul(active, atEntry, not(isKey), prevKeyURL)
		isHashValue := api.Mul(active, atEntry, not(isKey), prevKeyHash)
		r.assertIf(isURLValue, isText, 1)
		r.assertIf(isHashValue, api.Mul(isBytes, isEq(arg, 32), isEq(hl, 2)), 1)
		for k, ref := range refs {
			// The URL: the same length and bytes.
			same := isEq(arg, ref.URLLen)
			for i := 0; i < s.MaxURL; i++ {
				in := r.pos.IsLess(i, ref.URLLen)
				same = api.Mul(same, api.Add(not(in), api.Mul(in, isEq(r.at(api.Add(p, hl, i)), ref.URL[i]))))
			}
			elemURL[k] = api.Add(elemURL[k], api.Mul(isURLValue, same))
			// The hash: 32 bytes, as two 128-bit halves.
			h := [2]frontend.Variable{0, 0}
			for half := 0; half < 2; half++ {
				for i := 0; i < 16; i++ {
					h[half] = api.Add(api.Mul(h[half], 256), r.at(api.Add(p, 2, 16*half+i)))
				}
			}
			match := api.Mul(isEq(h[0], ref.Hash[0]), isEq(h[1], ref.Hash[1]))
			elemHash[k] = api.Add(elemHash[k], api.Mul(isHashValue, match))
		}

		// Track the previous key, at the levels that matter.
		prevKeyCA = api.Select(api.Mul(active, atRoot1), isCAKey, prevKeyCA)
		prevRootKeyAlg = api.Select(api.Mul(active, atRoot1), isRootAlgKey, prevRootKeyAlg)
		prevKeyAlg = api.Select(api.Mul(active, atEntry), isAlgKey, prevKeyAlg)
		prevKeyURL = api.Select(api.Mul(active, atEntry), isURLKey, prevKeyURL)
		prevKeyHash = api.Select(api.Mul(active, atEntry), isHashKey, prevKeyHash)

		// Update the stack. A container with items is pushed; any other item
		// (a leaf, or an empty container) completes, and completes its
		// parents in turn when they run out.
		push := api.Mul(active, container, not(api.IsZero(arg)))
		r.assertIf(push, small.IsLess(d, claimMaxDepth), 1)
		items := api.Select(isMapT, api.Mul(2, arg), arg)
		var newRem, newMap [claimMaxDepth + 1]frontend.Variable
		for j := 0; j <= claimMaxDepth; j++ {
			child := api.Mul(push, isEq(d, j-1)) // the pushed level
			newRem[j] = api.Select(child, items, rem[j])
			newMap[j] = api.Select(child, isMapT, isMap[j])
		}
		newDepth := api.Add(d, push)
		// A completed item decrements its level's count; levels reaching 0
		// complete their own item one level up, and so on.
		completes := api.Mul(active, not(push))
		cur := newDepth
		pending := completes
		for step := 0; step <= claimMaxDepth; step++ {
			for j := 0; j <= claimMaxDepth; j++ {
				here := api.Mul(pending, isEq(cur, j))
				newRem[j] = api.Sub(newRem[j], here)
			}
			remCur := level(newRem, cur)
			// An entry map finishing: the entry's references are counted.
			endsEntry := api.Mul(pending, inCA, isEq(cur, 3), api.IsZero(remCur))
			for k := range refs {
				matched := api.Mul(endsEntry, elemURL[k], elemHash[k])
				foundOwn[k] = api.Add(foundOwn[k], api.Mul(matched, algKeys, elemAlgSHA))
				foundDefault[k] = api.Add(foundDefault[k], api.Mul(matched, not(algKeys)))
				urlCount[k] = api.Add(urlCount[k], api.Mul(endsEntry, elemURL[k]))
				elemURL[k] = api.Select(endsEntry, 0, elemURL[k])
				elemHash[k] = api.Select(endsEntry, 0, elemHash[k])
			}
			// At most one url, one hash, and one alg per entry.
			api.AssertIsEqual(api.Mul(endsEntry, urlKeys, api.Sub(urlKeys, 1)), 0)
			api.AssertIsEqual(api.Mul(endsEntry, hashKeys, api.Sub(hashKeys, 1)), 0)
			api.AssertIsEqual(api.Mul(endsEntry, algKeys, api.Sub(algKeys, 1)), 0)
			urlKeys = api.Select(endsEntry, 0, urlKeys)
			hashKeys = api.Select(endsEntry, 0, hashKeys)
			algKeys = api.Select(endsEntry, 0, algKeys)
			elemAlgSHA = api.Select(endsEntry, 0, elemAlgSHA)
			// The created_assertions array finishing.
			endsCA := api.Mul(pending, inCA, isEq(cur, 2), api.IsZero(remCur))
			inCA = api.Select(endsCA, 0, inCA)
			// Pop if this level is done (and is not the root).
			pop := api.Mul(pending, api.IsZero(remCur), not(api.IsZero(cur)))
			cur = api.Sub(cur, pop)
			pending = pop
		}
		// Entering the created_assertions array.
		inCA = api.Select(api.Mul(isCAValue, push), 1, inCA)
		rem, isMap, depth = newRem, newMap, cur
		p = api.Select(active, next, p)
	}
	api.AssertIsEqual(rem[0], 0)   // the whole claim walked
	api.AssertIsEqual(p, claimLen) // and nothing after it
	api.AssertIsEqual(caKeys, 1)
	api.AssertIsEqual(api.Mul(rootAlgKeys, api.Sub(rootAlgKeys, 1)), 0) // at most one claim alg
	for k, ref := range refs {
		// Found once, with SHA-256 as its effective algorithm (its own, or
		// else the claim's), and its URL referenced by no other entry.
		found := api.Add(foundOwn[k], api.Mul(foundDefault[k], claimAlgSHA))
		r.assertIf(ref.Active, found, 1)
		r.assertIf(ref.Active, urlCount[k], 1)
	}
}

// keyParity is 1 when a map's remaining count is even (the next item is a key).
func keyParity(api frontend.API, rem frontend.Variable) frontend.Variable {
	bits := api.ToBinary(rem, 6)
	return api.Sub(1, bits[0])
}

// ClaimRefCircuit is the gadget alone, for its cost: the claim private, the
// references public.
type ClaimRefCircuit struct {
	Sizes    ClaimRefSizes `gnark:"-"`
	Claim    []frontend.Variable
	ClaimLen frontend.Variable
	Refs     []ClaimRef `gnark:",public"`
}

// NewClaimRefCircuit allocates the circuit, with its MaxRefs reference slots.
func NewClaimRefCircuit(s ClaimRefSizes) *ClaimRefCircuit {
	c := &ClaimRefCircuit{Sizes: s, Claim: make([]frontend.Variable, s.MaxClaim), Refs: make([]ClaimRef, s.MaxRefs)}
	for k := range c.Refs {
		c.Refs[k].URL = make([]frontend.Variable, s.MaxURL)
	}
	return c
}

func (c *ClaimRefCircuit) Define(api frontend.API) error {
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	r, _ := newByteReaderPad(api, bapi, c.Claim, c.Sizes.MaxURL+8)
	r.pos.AssertIsLessEq(c.ClaimLen, c.Sizes.MaxClaim)
	assertClaimReferences(api, r, c.ClaimLen, c.Sizes, c.Refs)
	return nil
}
