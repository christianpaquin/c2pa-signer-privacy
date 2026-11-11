package statement

// The hidden-issuer statement (roadmap H4, HIDING-THE-ISSUER.md): the same
// statement as Circuit, except that the issuing CA's key is private and proven
// to be a leaf of the issuer tree (package issuertree, tree format 1), whose
// root is public, and that the CA's validity period, from the leaf, contains t.

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/poseidon2"
	stdbits "github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"

	"c2pa-zk-gnark/issuertree"
)

// HiddenIssuerCircuit is the statement with the issuing CA hidden among the
// leaves of an issuer tree; build it with NewHiddenIssuerCircuit.
type HiddenIssuerCircuit struct {
	Sizes Sizes `gnark:"-"`

	// Public inputs: as Circuit's, with the issuer tree's root in place of
	// the CA's key.
	Claim    []frontend.Variable  `gnark:",public"`
	ClaimLen frontend.Variable    `gnark:",public"`
	Root     frontend.Variable    `gnark:",public"`
	Time     frontend.Variable    `gnark:",public"`
	Imprint  [2]frontend.Variable `gnark:",public"`

	// Private inputs: Circuit's, and the CA's key, validity, and Merkle path.
	SigStructure []frontend.Variable
	ProtectedLen frontend.Variable
	ClaimSig     []frontend.Variable
	CASig        ecdsa.Signature[emulated.P384Fr]
	CAKey        ecdsa.PublicKey[emulated.P384Fp, emulated.P384Fr]
	CANotBefore  frontend.Variable
	CANotAfter   frontend.Variable
	Siblings     [issuertree.Depth]frontend.Variable
	IndexBits    [issuertree.Depth]frontend.Variable // the leaf index, least significant bit first
}

// NewHiddenIssuerCircuit allocates a circuit (or an assignment) for the given sizes.
func NewHiddenIssuerCircuit(s Sizes) *HiddenIssuerCircuit {
	return &HiddenIssuerCircuit{
		Sizes:        s,
		Claim:        make([]frontend.Variable, s.claimElements()),
		SigStructure: make([]frontend.Variable, s.sigStructureLen()),
		ClaimSig:     make([]frontend.Variable, signatureLen),
	}
}

func (c *HiddenIssuerCircuit) Define(api frontend.API) error {
	if err := define(api, &shared{c.Sizes, c.Claim, c.ClaimLen, c.Time, c.Imprint, c.SigStructure, c.ProtectedLen, c.ClaimSig, &c.CASig}, &c.CAKey); err != nil {
		return err
	}

	// The CA's validity contains t (both below 2^64, as in the leaf).
	stdbits.ToBinary(api, c.CANotBefore, stdbits.WithNbDigits(64))
	stdbits.ToBinary(api, c.CANotAfter, stdbits.WithNbDigits(64))
	validity := cmp.NewBoundedComparator(api, new(big.Int).Lsh(big.NewInt(1), 64), false)
	validity.AssertIsLessEq(c.CANotBefore, c.Time)
	validity.AssertIsLessEq(c.Time, c.CANotAfter)

	// The leaf: the key's canonical coordinates as 128-bit limbs (the
	// verification above used the key modulo p, which these encode).
	fp, err := emulated.NewField[emulated.P384Fp](api)
	if err != nil {
		return err
	}
	limbs := func(e *emulated.Element[emulated.P384Fp]) []frontend.Variable {
		bits := fp.ToBitsCanonical(e) // least significant first, 384 bits
		if len(bits) != 384 {
			panic(fmt.Sprintf("expected 384 bits, got %d", len(bits)))
		}
		return []frontend.Variable{
			stdbits.FromBinary(api, bits[256:384]),
			stdbits.FromBinary(api, bits[128:256]),
			stdbits.FromBinary(api, bits[0:128]),
		}
	}
	inputs := []frontend.Variable{1, issuertree.FormatVersion, issuertree.KeyTypeP384}
	inputs = append(inputs, limbs(&c.CAKey.X)...)
	inputs = append(inputs, limbs(&c.CAKey.Y)...)
	inputs = append(inputs, c.CANotBefore, c.CANotAfter)
	cur, err := hash(api, inputs...)
	if err != nil {
		return err
	}

	// The path to the root.
	for d := 0; d < issuertree.Depth; d++ {
		bit := c.IndexBits[d]
		api.AssertIsBoolean(bit)
		left := api.Select(bit, c.Siblings[d], cur)
		right := api.Select(bit, cur, c.Siblings[d])
		if cur, err = hash(api, 2, left, right); err != nil {
			return err
		}
	}
	api.AssertIsEqual(cur, c.Root)
	return nil
}

// hash is the tree's H: Poseidon2 (gnark's default parameters for the field),
// Merkle-Damgard over the given elements.
func hash(api frontend.API, elements ...frontend.Variable) (frontend.Variable, error) {
	h, err := poseidon2.New(api)
	if err != nil {
		return nil, err
	}
	h.Write(elements...)
	return h.Sum(), nil
}
