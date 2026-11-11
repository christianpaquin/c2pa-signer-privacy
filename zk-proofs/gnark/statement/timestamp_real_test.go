package statement

import (
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Tokens from real or fixture assets, at the default sizes: C2PA_ZK_TOKENS is
// a comma-separated list of token.der:tsa-ca.der (the token as stored in
// sigTst2, and its TSA's issuing CA). Each must satisfy the gadget in its
// UTC day's window.
func TestTokensFromAssets(t *testing.T) {
	list := os.Getenv("C2PA_ZK_TOKENS")
	if list == "" {
		t.Skip("set C2PA_ZK_TOKENS=token.der:tsa-ca.der[,...]")
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, NewTokenCircuit(DefaultTokenSizes))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("token gadget: %d constraints at the default sizes", ccs.GetNbConstraints())
	for _, pair := range strings.Split(list, ",") {
		files := strings.Split(pair, ":")
		token, err := os.ReadFile(files[0])
		if err != nil {
			t.Fatal(err)
		}
		caDER, err := os.ReadFile(files[1])
		if err != nil {
			t.Fatal(err)
		}
		parts, err := ParseToken(token)
		if err != nil {
			t.Fatal(err)
		}
		genTime, imprint, err := TokenTime(parts)
		if err != nil {
			t.Fatal(err)
		}
		c := NewTokenCircuit(DefaultTokenSizes)
		if c.Token, err = AssignToken(parts, DefaultTokenSizes); err != nil {
			t.Fatal(err)
		}
		if c.TSACAKey, err = TokenCAKey(caDER); err != nil {
			t.Fatal(err)
		}
		t1, t2 := Window(genTime, 86400)
		c.T1, c.T2 = t1, t2
		c.Imprint = [2]frontend.Variable{new(big.Int).SetBytes(imprint[:16]), new(big.Int).SetBytes(imprint[16:])}
		w, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := ccs.IsSolved(w); err != nil {
			t.Errorf("%s: %v", files[0], err)
		} else {
			t.Logf("%s: accepted (attributes %d B, TSTInfo %d B)", files[0], len(parts.SignedAttrs), len(parts.TSTInfo))
		}
	}
}
