package statement

import (
	"crypto/sha256"
	"math/big"
	"os"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Minimal CBOR encoding for test claims (definite lengths, short forms).
func cborHead(major byte, n int) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	default:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	}
}
func cText(s string) []byte  { return append(cborHead(3, len(s)), s...) }
func cBytes(b []byte) []byte { return append(cborHead(2, len(b)), b...) }
func cArray(items ...[]byte) []byte {
	out := cborHead(4, len(items))
	for _, i := range items {
		out = append(out, i...)
	}
	return out
}

// cMap takes alternating keys and values, already encoded.
func cMap(kv ...[]byte) []byte {
	out := cborHead(5, len(kv)/2)
	for _, i := range kv {
		out = append(out, i...)
	}
	return out
}

func hashedURI(url string, h []byte) []byte {
	return cMap(cText("url"), cText(url), cText("hash"), cBytes(h))
}

const hardBindingURL = "self#jumbf=c2pa.assertions/c2pa.hash.data"
const actionsURL = "self#jumbf=c2pa.assertions/c2pa.actions.v2"

var (
	hardBindingHash = sha256.Sum256([]byte("the hard binding assertion"))
	actionsHash     = sha256.Sum256([]byte("the actions assertion"))
)

// testClaim builds a claim like the real ones, with the given
// created_assertions entries and an optional claim generator name.
func testClaim(generator string, entries ...[]byte) []byte {
	return cMap(
		cText("instanceID"), cText("ce00b058-a1ef-62f0-6bfd-4a942dcd0bd1"),
		cText("claim_generator_info"), cMap(cText("name"), cText(generator), cText("version"), cText("1:2")),
		cText("created_assertions"), cArray(entries...),
		cText("signature"), cText("self#jumbf=c2pa.signature"),
		cText("alg"), cText("sha256"),
	)
}

func defaultEntries() [][]byte {
	return [][]byte{hashedURI(hardBindingURL, hardBindingHash[:]), hashedURI(actionsURL, actionsHash[:])}
}

type ref struct {
	url  string
	hash []byte
}

var compiledClaimRef = sync.OnceValues(func() (constraint.ConstraintSystem, error) {
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, NewClaimRefCircuit(DefaultClaimRefSizes))
})

func claimRefCS(t *testing.T) constraint.ConstraintSystem {
	t.Helper()
	ccs, err := compiledClaimRef()
	if err != nil {
		t.Fatal(err)
	}
	return ccs
}

// claimRefAssignment assigns the claim and the references to the first
// slots, the others unused (all zero).
func claimRefAssignment(claim []byte, claimLen int, refs ...ref) *ClaimRefCircuit {
	s := DefaultClaimRefSizes
	c := NewClaimRefCircuit(s)
	for i := range c.Claim {
		if i < len(claim) {
			c.Claim[i] = claim[i]
		} else {
			c.Claim[i] = 0
		}
	}
	c.ClaimLen = claimLen
	for k := range c.Refs {
		var r ref
		if k < len(refs) {
			r = refs[k]
		}
		for i := range c.Refs[k].URL {
			if i < len(r.url) {
				c.Refs[k].URL[i] = r.url[i]
			} else {
				c.Refs[k].URL[i] = 0
			}
		}
		c.Refs[k].URLLen = len(r.url)
		c.Refs[k].Active = 0
		c.Refs[k].Hash = [2]frontend.Variable{0, 0}
		if k < len(refs) {
			c.Refs[k].Active = 1
			c.Refs[k].Hash = [2]frontend.Variable{new(big.Int).SetBytes(r.hash[:16]), new(big.Int).SetBytes(r.hash[16:])}
		}
	}
	return c
}

func claimRefSolved(t *testing.T, c *ClaimRefCircuit) bool {
	t.Helper()
	w, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return claimRefCS(t).IsSolved(w) == nil
}

func claimRefAccepts(t *testing.T, claim []byte, claimLen int, refs ...ref) bool {
	t.Helper()
	return claimRefSolved(t, claimRefAssignment(claim, claimLen, refs...))
}

var (
	hb = ref{hardBindingURL, hardBindingHash[:]}
	ac = ref{actionsURL, actionsHash[:]}
)

func TestClaimReferencesAreFound(t *testing.T) {
	claim := testClaim("Some Camera SDK", defaultEntries()...)
	for name, refs := range map[string][]ref{"the hard binding": {hb}, "the actions": {ac}} {
		if !claimRefAccepts(t, claim, len(claim), refs...) {
			t.Errorf("%s: rejected", name)
		}
	}
	if !claimRefAccepts(t, claim, len(claim), hb, ac) {
		t.Error("both: rejected")
	}
	// An entry with an alg field, and keys in the other order.
	other := cMap(cText("hash"), cBytes(hardBindingHash[:]), cText("alg"), cText("sha256"), cText("url"), cText(hardBindingURL))
	c2 := testClaim("Some Camera SDK", other)
	if !claimRefAccepts(t, c2, len(c2), hb) {
		t.Error("an entry with alg, hash before url: rejected")
	}
	t.Logf("claim reference gadget: %d constraints with %d reference slots (default sizes)", claimRefCS(t).GetNbConstraints(), DefaultClaimRefSizes.MaxRefs)
}

// A reference is accepted only as an entry of created_assertions, read where
// the walk finds it: not bytes inside another field, not another array.
func TestClaimReferencesAreStructural(t *testing.T) {
	fake := hashedURI(hardBindingURL, hardBindingHash[:])
	cases := map[string][]byte{
		// The entry's bytes inside the generator's name, not in created_assertions.
		"inside a text field": testClaim(string(fake), hashedURI(actionsURL, actionsHash[:])),
		"in gathered_assertions only": cMap(
			cText("instanceID"), cText("x"),
			cText("claim_generator_info"), cMap(cText("name"), cText("g")),
			cText("created_assertions"), cArray(hashedURI(actionsURL, actionsHash[:])),
			cText("gathered_assertions"), cArray(fake),
			cText("signature"), cText("self#jumbf=c2pa.signature"),
		),
		"two created_assertions keys": cMap(
			cText("created_assertions"), cArray(hashedURI(actionsURL, actionsHash[:])),
			cText("created_assertions"), cArray(fake),
		),
		"an entry with two url keys": testClaim("g", cMap(cText("url"), cText(hardBindingURL), cText("url"), cText(actionsURL), cText("hash"), cBytes(hardBindingHash[:]))),
		"another hash":               testClaim("g", hashedURI(hardBindingURL, actionsHash[:])),
		"a longer URL":               testClaim("g", hashedURI(hardBindingURL+"x", hardBindingHash[:])),
		"a shorter URL":              testClaim("g", hashedURI(hardBindingURL[:len(hardBindingURL)-1], hardBindingHash[:])),
		"a 31-byte hash":             testClaim("g", hashedURI(hardBindingURL, hardBindingHash[:31])),
		"created_assertions a map":   cMap(cText("created_assertions"), cMap(cText("url"), cText(hardBindingURL), cText("hash"), cBytes(hardBindingHash[:]))),
		"an integer":                 append([]byte{0xa1}, append(cText("n"), 0x01)...),
		// An entry that is not a map, beside a valid one.
		"an entry that is not a map": testClaim("g", cText("not an entry"), hashedURI(hardBindingURL, hardBindingHash[:])),
		// created_assertions nested in another field, not at the root.
		"created_assertions nested": cMap(
			cText("instanceID"), cText("x"),
			cText("claim_generator_info"), cMap(cText("name"), cText("g"), cText("created_assertions"), cArray(fake)),
			cText("signature"), cText("self#jumbf=c2pa.signature"),
		),
	}
	for name, claim := range cases {
		if claimRefAccepts(t, claim, len(claim), hb) {
			t.Errorf("%s: accepted", name)
		}
	}
	// The length must be the encoding's: no trailing bytes, no truncation.
	claim := testClaim("g", defaultEntries()...)
	padded := append(append([]byte{}, claim...), 0x60)
	if claimRefAccepts(t, padded, len(padded), hb) {
		t.Error("a trailing item: accepted")
	}
	if claimRefAccepts(t, claim, len(claim)-1, hb) {
		t.Error("a truncated length: accepted")
	}
}

// Real claims (CLAIM-PRIVACY.md): C2PA_ZK_CLAIMS is a comma-separated list of
// claim.cbor files; each must reference its hard binding, whose hash is given
// as claim.cbor's sibling claim.hb (hex is not needed: the raw 32 bytes).
func TestRealClaims(t *testing.T) {
	list := os.Getenv("C2PA_ZK_CLAIMS")
	if list == "" {
		t.Skip("set C2PA_ZK_CLAIMS=a.claim.cbor[,...] with a.claim.hb holding the hard binding's hash")
	}
	for _, f := range splitComma(list) {
		claim, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		h, err := os.ReadFile(f[:len(f)-len(".cbor")] + ".hb")
		if err != nil {
			t.Fatal(err)
		}
		if !claimRefAccepts(t, claim, len(claim), ref{hardBindingURL, h}) {
			t.Errorf("%s: its hard binding reference was not found", f)
		} else {
			t.Logf("%s (%d bytes): the hard binding reference found", f, len(claim))
		}
		wrong := append([]byte{}, h...)
		wrong[0] ^= 1
		if claimRefAccepts(t, claim, len(claim), ref{hardBindingURL, wrong}) {
			t.Errorf("%s: another hash accepted", f)
		}
	}
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

// URLs are compared whole: a public URL is at most MaxURL bytes, and must
// have the encoded URL's length (PR #43 review).
func TestClaimReferenceURLsAreCompared(t *testing.T) {
	max := DefaultClaimRefSizes.MaxURL
	prefix := "self#jumbf=c2pa.assertions/c2pa.hash.data"
	long := prefix + string(make([]byte, 0))
	for len(long) < max {
		long += "x"
	}
	claim := testClaim("g", hashedURI(long, hardBindingHash[:]))
	if !claimRefAccepts(t, claim, len(claim), ref{long, hardBindingHash[:]}) {
		t.Errorf("a %d-byte URL (the limit): rejected", max)
	}
	// A longer URL whose first MaxURL bytes match, with a different suffix.
	actual, forged := long+"actual", long+"forged"
	c2 := testClaim("g", hashedURI(actual, hardBindingHash[:]))
	c := claimRefAssignment(c2, len(c2), ref{forged[:max], hardBindingHash[:]})
	c.Refs[0].URLLen = len(forged)
	if claimRefSolved(t, c) {
		t.Error("a URL beyond the limit, its first bytes equal: accepted")
	}
	// Equal lengths within the limit, different last byte.
	c3 := testClaim("g", hashedURI(long[:max-1]+"a", hardBindingHash[:]))
	if claimRefAccepts(t, c3, len(c3), ref{long[:max-1] + "b", hardBindingHash[:]}) {
		t.Error("a different last byte: accepted")
	}
}

// The effective hash algorithm must be SHA-256: the entry's own alg, or else
// the claim's (C2PA 2.5, §10.2.2, §12.1; PR #43 review).
func TestClaimReferenceAlgorithms(t *testing.T) {
	entry := func(alg string) []byte {
		if alg == "" {
			return hashedURI(hardBindingURL, hardBindingHash[:])
		}
		return cMap(cText("url"), cText(hardBindingURL), cText("hash"), cBytes(hardBindingHash[:]), cText("alg"), cText(alg))
	}
	claimWith := func(claimAlg string, entries ...[]byte) []byte {
		kv := [][]byte{cText("instanceID"), cText("x"), cText("claim_generator_info"), cMap(cText("name"), cText("g")),
			cText("created_assertions"), cArray(entries...), cText("signature"), cText("self#jumbf=c2pa.signature")}
		if claimAlg != "" {
			kv = append(kv, cText("alg"), cText(claimAlg))
		}
		return cMap(kv...)
	}
	accepted := map[string][]byte{
		"inherited sha256":                           claimWith("sha256", entry("")),
		"the entry's sha256":                         claimWith("", entry("sha256")),
		"the entry's sha256 over the claim's sha384": claimWith("sha384", entry("sha256")),
	}
	refused := map[string][]byte{
		"the entry's sha384": claimWith("sha256", entry("sha384")),
		"inherited sha384":   claimWith("sha384", entry("")),
		"no algorithm":       claimWith("", entry("")),
		"two claim algs": cMap(cText("instanceID"), cText("x"), cText("created_assertions"), cArray(entry("")),
			cText("alg"), cText("sha256"), cText("alg"), cText("sha384")),
		"two entry algs": claimWith("sha256", cMap(cText("url"), cText(hardBindingURL), cText("hash"), cBytes(hardBindingHash[:]), cText("alg"), cText("sha256"), cText("alg"), cText("sha256"))),
		"a non-text alg": claimWith("", cMap(cText("url"), cText(hardBindingURL), cText("hash"), cBytes(hardBindingHash[:]), cText("alg"), cBytes([]byte("sha256")))),
		"the URL twice":  claimWith("sha256", entry(""), cMap(cText("url"), cText(hardBindingURL), cText("hash"), cBytes(actionsHash[:]), cText("alg"), cText("sha384"))),
	}
	for name, claim := range accepted {
		if !claimRefAccepts(t, claim, len(claim), hb) {
			t.Errorf("%s: rejected", name)
		}
	}
	for name, claim := range refused {
		if claimRefAccepts(t, claim, len(claim), hb) {
			t.Errorf("%s: accepted", name)
		}
	}
}

// One circuit covers every disclosure count: slot 0 (the hard binding) is
// always used, the others are optional, and an unused slot is all zero.
func TestClaimReferenceSlots(t *testing.T) {
	extra := func(name string) ([]byte, ref) {
		h := sha256.Sum256([]byte(name))
		url := "self#jumbf=c2pa.assertions/" + name
		return hashedURI(url, h[:]), ref{url, h[:]}
	}
	e1, r1 := extra("c2pa.thumbnail.claim")
	e2, r2 := extra("stds.exif")
	claim := testClaim("g", hashedURI(hardBindingURL, hardBindingHash[:]), hashedURI(actionsURL, actionsHash[:]), e1, e2)
	for name, refs := range map[string][]ref{"none optional": {hb}, "one optional": {hb, ac}, "three optional": {hb, ac, r1, r2}} {
		if !claimRefAccepts(t, claim, len(claim), refs...) {
			t.Errorf("%s: rejected", name)
		}
	}
	for name, change := range map[string]func(c *ClaimRefCircuit){
		"slot 0 unused":                    func(c *ClaimRefCircuit) { c.Refs[0].Active = 0 },
		"an unused slot with a URL length": func(c *ClaimRefCircuit) { c.Refs[2].URLLen = 3 },
		"an unused slot with a hash":       func(c *ClaimRefCircuit) { c.Refs[2].Hash[1] = 1 },
		"an unused slot with a URL byte":   func(c *ClaimRefCircuit) { c.Refs[2].URL[0] = 's' },
		"an active flag of 2":              func(c *ClaimRefCircuit) { c.Refs[1].Active = 2 },
		"an active empty URL":              func(c *ClaimRefCircuit) { c.Refs[2].Active = 1 },
	} {
		c := claimRefAssignment(claim, len(claim), hb, ac)
		change(c)
		if claimRefSolved(t, c) {
			t.Errorf("%s: accepted", name)
		}
	}
}
