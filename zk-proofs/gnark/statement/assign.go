package statement

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

// Public is what the verifier derives from the anonymized asset: the claim,
// the issuing CA certificate (from x5chain, validated against the trust
// list), and the time-stamp token's attested time and message imprint.
type Public struct {
	Claim      []byte `json:"claim"`
	IssuerCert []byte `json:"issuer_certificate"`
	Time       int64  `json:"time"`
	Imprint    []byte `json:"imprint"`
}

// Inputs are the prover's: the public values and the original signature's
// private parts, as rebuilt from the signed asset (original_signature.rs).
type Inputs struct {
	Public
	Protected []byte `json:"protected"` // the original protected header
	Signature []byte `json:"signature"` // the original claim signature, r || s
}

// Assign builds the full assignment. It checks only what it needs to build
// the witness; the circuit enforces the statement.
func Assign(in Inputs, s Sizes) (*Circuit, error) {
	c, err := AssignPublic(in.Public, s)
	if err != nil {
		return nil, err
	}
	p := in.Protected
	if len(p) < 256 || len(p) > s.MaxProtected {
		return nil, fmt.Errorf("protected header is %d bytes; the circuit takes 256 to %d", len(p), s.MaxProtected)
	}
	if len(in.Signature) != signatureLen {
		return nil, fmt.Errorf("claim signature is %d bytes, not %d (ES256 r || s)", len(in.Signature), signatureLen)
	}
	leaf, err := signerCertificate(p)
	if err != nil {
		return nil, err
	}
	caSig, err := certificateSignature(leaf)
	if err != nil {
		return nil, err
	}

	sig := SigStructure(p, in.Claim)
	for i := range c.SigStructure {
		if i < len(sig) {
			c.SigStructure[i] = sig[i]
		} else {
			c.SigStructure[i] = 0
		}
	}
	c.ProtectedLen = len(p)
	for i, b := range in.Signature {
		c.ClaimSig[i] = b
	}
	c.CASig = gnarkecdsa.Signature[emulated.P384Fr]{
		R: emulated.ValueOf[emulated.P384Fr](caSig.R),
		S: emulated.ValueOf[emulated.P384Fr](caSig.S),
	}
	return c, nil
}

// AssignPublic builds the public part of the assignment (the private part is
// zero), as the verifier does.
func AssignPublic(pub Public, s Sizes) (*Circuit, error) {
	if len(pub.Claim) < 24 || len(pub.Claim) > s.MaxClaim {
		return nil, fmt.Errorf("claim is %d bytes; the circuit takes 24 to %d", len(pub.Claim), s.MaxClaim)
	}
	if len(pub.Imprint) != 32 {
		return nil, fmt.Errorf("imprint is %d bytes, not 32 (SHA-256)", len(pub.Imprint))
	}
	ca, err := x509.ParseCertificate(pub.IssuerCert)
	if err != nil {
		return nil, fmt.Errorf("issuing CA certificate: %w", err)
	}
	key, ok := ca.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P384() {
		return nil, fmt.Errorf("issuing CA key is not P-384")
	}

	c := NewCircuit(s)
	padded := make([]byte, len(c.Claim)*claimChunk)
	copy(padded, pub.Claim)
	for k := range c.Claim {
		c.Claim[k] = new(big.Int).SetBytes(padded[k*claimChunk : (k+1)*claimChunk])
	}
	c.ClaimLen = len(pub.Claim)
	c.CAKey = gnarkecdsa.PublicKey[emulated.P384Fp, emulated.P384Fr]{
		X: emulated.ValueOf[emulated.P384Fp](key.X),
		Y: emulated.ValueOf[emulated.P384Fp](key.Y),
	}
	c.Time = pub.Time
	c.Imprint = [2]frontend.Variable{new(big.Int).SetBytes(pub.Imprint[:16]), new(big.Int).SetBytes(pub.Imprint[16:])}
	for i := range c.SigStructure {
		c.SigStructure[i] = 0
	}
	c.ProtectedLen = 0
	for i := range c.ClaimSig {
		c.ClaimSig[i] = 0
	}
	c.CASig = gnarkecdsa.Signature[emulated.P384Fr]{R: emulated.ValueOf[emulated.P384Fr](0), S: emulated.ValueOf[emulated.P384Fr](0)}
	return c, nil
}

// SigStructure is ["Signature1", protected, h”, claim], CBOR-encoded with
// the header lengths the circuit expects (protected 256 bytes or more).
func SigStructure(protected, claim []byte) []byte {
	out := append([]byte{}, sigContext...)
	out = append(out, 0x59, byte(len(protected)>>8), byte(len(protected)))
	out = append(out, protected...)
	out = append(out, 0x40)
	if len(claim) < 256 {
		out = append(out, 0x58, byte(len(claim)))
	} else {
		out = append(out, 0x59, byte(len(claim)>>8), byte(len(claim)))
	}
	return append(out, claim...)
}

// Countersignature is the v2 time stamp's countersignature structure,
// ["CounterSignature", protected, h”, bstr(bstr(signature))].
func Countersignature(protected, signature []byte) []byte {
	out := append([]byte{}, csContext...)
	out = append(out, 0x59, byte(len(protected)>>8), byte(len(protected)))
	out = append(out, protected...)
	out = append(out, 0x40, 0x58, byte(len(signature)+2), 0x58, byte(len(signature)))
	return append(out, signature...)
}

// signerCertificate is the first x5chain entry of a protected header laid
// out as the circuit expects: {1: -7, 33: [certificate, ...]}.
func signerCertificate(p []byte) ([]byte, error) {
	if !bytes.HasPrefix(p, protectedStart) || p[5] < 0x81 || p[5] > 0x97 || p[6] != 0x59 {
		return nil, fmt.Errorf("protected header is not {1: ES256, 33: [certificate, ...]} with a certificate of 256 bytes or more")
	}
	n := int(p[7])<<8 | int(p[8])
	if 9+n > len(p) {
		return nil, fmt.Errorf("signer certificate runs past the protected header")
	}
	return p[9 : 9+n], nil
}

// certificateSignature is the issuer's ECDSA signature on a certificate.
func certificateSignature(der []byte) (struct{ R, S *big.Int }, error) {
	var cert struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	var sig struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &cert); err != nil || len(rest) != 0 {
		return sig, fmt.Errorf("signer certificate is not a certificate: %v", err)
	}
	if rest, err := asn1.Unmarshal(cert.Signature.Bytes, &sig); err != nil || len(rest) != 0 {
		return sig, fmt.Errorf("signer certificate's signature is not ECDSA: %v", err)
	}
	return sig, nil
}
