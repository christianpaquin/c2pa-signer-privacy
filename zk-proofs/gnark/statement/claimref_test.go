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

var compiledClaimRef sync.Map // number of refs -> constraint.ConstraintSystem

func claimRefCS(t *testing.T, n int) constraint.ConstraintSystem {
	t.Helper()
	if v, ok := compiledClaimRef.Load(n); ok {
		return v.(constraint.ConstraintSystem)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, NewClaimRefCircuit(DefaultClaimRefSizes, n))
	if err != nil {
		t.Fatal(err)
	}
	compiledClaimRef.Store(n, ccs)
	return ccs
}

func claimRefAccepts(t *testing.T, claim []byte, claimLen int, refs ...ref) bool {
	t.Helper()
	s := DefaultClaimRefSizes
	c := NewClaimRefCircuit(s, len(refs))
	for i := range c.Claim {
		if i < len(claim) {
			c.Claim[i] = claim[i]
		} else {
			c.Claim[i] = 0
		}
	}
	c.ClaimLen = claimLen
	for k, r := range refs {
		for i := range c.Refs[k].URL {
			if i < len(r.url) {
				c.Refs[k].URL[i] = r.url[i]
			} else {
				c.Refs[k].URL[i] = 0
			}
		}
		c.Refs[k].URLLen = len(r.url)
		c.Refs[k].Hash = [2]frontend.Variable{new(big.Int).SetBytes(r.hash[:16]), new(big.Int).SetBytes(r.hash[16:])}
	}
	w, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return claimRefCS(t, len(refs)).IsSolved(w) == nil
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
	t.Logf("claim reference gadget: %d constraints for one reference, %d for two (default sizes)",
		claimRefCS(t, 1).GetNbConstraints(), claimRefCS(t, 2).GetNbConstraints())
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
