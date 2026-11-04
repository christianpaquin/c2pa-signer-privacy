package main

// The E1 primitive circuits. Each is a standalone statement, with no
// certificate parsing:
//
//   - ecdsa-*: ECDSA verification of a given message digest under a public key
//     (the issuing CA's key is public, as in the anonymization circuit).
//   - sha*:    a hash over a private message of fixed length, equal to a public digest.
//   - ca-*:    "a CA signature over a TBS": hash the private TBS bytes and verify
//     the CA's ECDSA signature over the digest under the public CA key.

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

// EcdsaCircuit verifies a signature over a digest given as a scalar.
type EcdsaCircuit[Fp, Fr emulated.FieldParams] struct {
	Pub ecdsa.PublicKey[Fp, Fr] `gnark:",public"`
	Sig ecdsa.Signature[Fr]
	Msg emulated.Element[Fr]
}

func (c *EcdsaCircuit[Fp, Fr]) Define(api frontend.API) error {
	c.Pub.Verify(api, sw_emulated.GetCurveParams[Fp](), &c.Msg, &c.Sig)
	return nil
}

// HashCircuit hashes In and checks the result against the public Digest.
type HashCircuit struct {
	Alg    string `gnark:"-"`
	In     []uints.U8
	Digest []uints.U8 `gnark:",public"`
}

func (c *HashCircuit) Define(api frontend.API) error {
	digest, err := hashBytes(api, c.Alg, c.In)
	if err != nil {
		return err
	}
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	for i := range c.Digest {
		bapi.AssertIsEqual(digest[i], c.Digest[i])
	}
	return nil
}

// CaSignatureCircuit verifies the CA's signature over the TBS bytes.
type CaSignatureCircuit[Fp, Fr emulated.FieldParams] struct {
	Alg string `gnark:"-"`
	Pub ecdsa.PublicKey[Fp, Fr] `gnark:",public"`
	Sig ecdsa.Signature[Fr]
	Tbs []uints.U8
}

func (c *CaSignatureCircuit[Fp, Fr]) Define(api frontend.API) error {
	digest, err := hashBytes(api, c.Alg, c.Tbs)
	if err != nil {
		return err
	}
	msg, err := digestToScalar[Fr](api, digest)
	if err != nil {
		return err
	}
	c.Pub.Verify(api, sw_emulated.GetCurveParams[Fp](), msg, &c.Sig)
	return nil
}

func hashBytes(api frontend.API, alg string, in []uints.U8) ([]uints.U8, error) {
	switch alg {
	case "sha256":
		h, err := sha2.New(api)
		if err != nil {
			return nil, err
		}
		h.Write(in)
		return h.Sum(), nil
	case "sha384":
		u, err := uints.New[uints.U64](api)
		if err != nil {
			return nil, err
		}
		return sum384(u, in), nil
	}
	return nil, fmt.Errorf("unknown hash %q", alg)
}

// digestToScalar interprets a big-endian digest as the ECDSA message scalar.
// For both pairs measured (SHA-256 with P-256, SHA-384 with P-384) the digest
// is as long as the group order, so no truncation applies; the value may
// exceed the order, which the emulated arithmetic reduces.
func digestToScalar[Fr emulated.FieldParams](api frontend.API, digest []uints.U8) (*emulated.Element[Fr], error) {
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return nil, err
	}
	fr, err := emulated.NewField[Fr](api)
	if err != nil {
		return nil, err
	}
	var bits []frontend.Variable // least significant first
	for i := len(digest) - 1; i >= 0; i-- {
		bits = append(bits, bapi.ToBits(digest[i])...)
	}
	return fr.FromBits(bits...), nil
}
