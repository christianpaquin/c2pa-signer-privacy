package statement

// The statement with both the issuer and the time-stamp token hidden (roadmap
// I6, HIDING-THE-TIME-STAMP.md, T1): the hidden-issuer statement, with the
// token verified in the circuit (verifyToken) instead of disclosed. The time
// and the imprint become private; the token's genTime must lie in the public
// half-open window [T1, T2), and its imprint must be the one the circuit
// computes over the original signature. The TSA CA's key is private and proven
// a leaf of the TSA tree (role TSA, leaf tag 4) whose root is public.

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"

	"c2pa-zk-gnark/issuertree"
)

// HiddenAllCircuit is the statement hiding the issuer and the token; build it
// with NewHiddenAllCircuit.
type HiddenAllCircuit struct {
	Sizes      Sizes      `gnark:"-"`
	TokenSizes TokenSizes `gnark:"-"`

	// Public inputs.
	Claim    []frontend.Variable `gnark:",public"`
	ClaimLen frontend.Variable   `gnark:",public"`
	Root     frontend.Variable   `gnark:",public"` // the issuer tree (role issuer)
	TSARoot  frontend.Variable   `gnark:",public"` // the TSA tree (role TSA)
	T1       frontend.Variable   `gnark:",public"` // the window [T1, T2), Unix seconds
	T2       frontend.Variable   `gnark:",public"`

	// Private inputs: the hidden-issuer statement's, with the time and the
	// imprint now private; the token; the TSA CA's key, validity, and path.
	Time         frontend.Variable // genTime
	Imprint      [2]frontend.Variable
	SigStructure []frontend.Variable
	ProtectedLen frontend.Variable
	ClaimSig     []frontend.Variable
	CASig        ecdsa.Signature[emulated.P384Fr]
	CAKey        ecdsa.PublicKey[emulated.P384Fp, emulated.P384Fr]
	CANotBefore  frontend.Variable
	CANotAfter   frontend.Variable
	Siblings     [issuertree.Depth]frontend.Variable
	IndexBits    [issuertree.Depth]frontend.Variable

	Token          TokenInputs
	TSACAKey       ecdsa.PublicKey[emulated.P384Fp, emulated.P384Fr]
	TSACANotBefore frontend.Variable
	TSACANotAfter  frontend.Variable
	TSASiblings    [issuertree.Depth]frontend.Variable
	TSAIndexBits   [issuertree.Depth]frontend.Variable
}

// NewHiddenAllCircuit allocates a circuit (or an assignment) for the given sizes.
func NewHiddenAllCircuit(s Sizes, ts TokenSizes) *HiddenAllCircuit {
	return &HiddenAllCircuit{
		Sizes:        s,
		TokenSizes:   ts,
		Claim:        make([]frontend.Variable, s.claimElements()),
		SigStructure: make([]frontend.Variable, s.sigStructureLen()),
		ClaimSig:     make([]frontend.Variable, signatureLen),
		Token:        NewTokenInputs(ts),
	}
}

func (c *HiddenAllCircuit) Define(api frontend.API) error {
	// The statement, with the signer certificate's validity at the private
	// time and the countersignature's hash equal to the private imprint.
	if err := define(api, &shared{c.Sizes, c.Claim, c.ClaimLen, c.Time, c.Imprint, c.SigStructure, c.ProtectedLen, c.ClaimSig, &c.CASig}, &c.CAKey); err != nil {
		return err
	}
	if err := assertMember(api, issuertree.RoleIssuer, &c.CAKey, c.CANotBefore, c.CANotAfter, c.Time, c.Siblings, c.IndexBits, c.Root); err != nil {
		return err
	}

	// The token: genTime is the private time, and its imprint the private
	// imprint; the TSA CA is in the TSA tree and valid at genTime.
	genTime, imprint, err := verifyToken(api, c.TokenSizes, &c.Token, &c.TSACAKey)
	if err != nil {
		return err
	}
	api.AssertIsEqual(genTime, c.Time)
	for half := 0; half < 2; half++ {
		v := frontend.Variable(0)
		for _, b := range imprint[16*half : 16*half+16] {
			v = api.Add(api.Mul(v, 256), b)
		}
		api.AssertIsEqual(v, c.Imprint[half])
	}
	if err := assertMember(api, issuertree.RoleTSA, &c.TSACAKey, c.TSACANotBefore, c.TSACANotAfter, genTime, c.TSASiblings, c.TSAIndexBits, c.TSARoot); err != nil {
		return err
	}
	assertInWindow(api, genTime, c.T1, c.T2)
	return nil
}
