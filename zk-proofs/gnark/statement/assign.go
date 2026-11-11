package statement

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"

	"c2pa-zk-gnark/issuertree"
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
	// The original time-stamp token (sigTst2), for the statement that hides
	// it (I6); the other statements do not use it.
	TimeStampToken []byte `json:"time_stamp_token,omitempty"`
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

// HiddenPublic is what the verifier supplies for the hidden-issuer statement:
// as Public, with the root of an issuer tree it approves (hex) in place of the
// issuing CA's certificate.
type HiddenPublic struct {
	Claim   []byte `json:"claim"`
	Root    string `json:"issuer_root"`
	Time    int64  `json:"time"`
	Imprint []byte `json:"imprint"`
}

// AssignHidden builds the full hidden-issuer assignment: the statement's
// inputs, the issuing CA's key, and its membership proof in the tree.
func AssignHidden(in Inputs, tree *issuertree.Tree, s Sizes) (*HiddenIssuerCircuit, error) {
	full, err := Assign(in, s)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(in.IssuerCert)
	proof, err := tree.Prove(hex.EncodeToString(sum[:]))
	if err != nil {
		return nil, fmt.Errorf("the issuing CA is not in the issuer tree: %w", err)
	}
	c := NewHiddenIssuerCircuit(s)
	copy(c.Claim, full.Claim)
	c.ClaimLen = full.ClaimLen
	c.Root = tree.Root()
	c.Time = full.Time
	c.Imprint = full.Imprint
	copy(c.SigStructure, full.SigStructure)
	c.ProtectedLen = full.ProtectedLen
	copy(c.ClaimSig, full.ClaimSig)
	c.CASig = full.CASig
	c.CAKey = full.CAKey
	c.CANotBefore = proof.CA.NotBefore
	c.CANotAfter = proof.CA.NotAfter
	for d := 0; d < issuertree.Depth; d++ {
		c.Siblings[d] = proof.Siblings[d]
		c.IndexBits[d] = (proof.Index >> d) & 1
	}
	return c, nil
}

// ParseRoot reads an issuer tree's root: canonical lowercase hex (no
// prefix, no leading zeros), below the curve's scalar field modulus. Any other
// spelling is refused, so that each root has exactly one form, as the
// verifier's approved-root policy compares them; a root at or above the
// modulus would otherwise be reduced into the field, an alias of another.
func ParseRoot(text string, curve ecc.ID) (*big.Int, error) {
	if !canonicalHex.MatchString(text) {
		return nil, fmt.Errorf("issuer_root %q is not canonical lowercase hex", text)
	}
	root, _ := new(big.Int).SetString(text, 16)
	if root.Cmp(curve.ScalarField()) >= 0 {
		return nil, fmt.Errorf("issuer_root is not below the %s scalar field modulus", curve)
	}
	return root, nil
}

var canonicalHex = regexp.MustCompile(`^(0|[1-9a-f][0-9a-f]*)$`)

// AssignHiddenPublic builds the public part of the hidden-issuer assignment
// (the private part is zero), as the verifier does, for the key set's curve.
func AssignHiddenPublic(pub HiddenPublic, s Sizes, curve ecc.ID) (*HiddenIssuerCircuit, error) {
	root, err := ParseRoot(pub.Root, curve)
	if err != nil {
		return nil, err
	}
	// The claim, time, and imprint checks and encodings are Circuit's; the
	// issuer certificate is not used.
	if len(pub.Claim) < 24 || len(pub.Claim) > s.MaxClaim {
		return nil, fmt.Errorf("claim is %d bytes; the circuit takes 24 to %d", len(pub.Claim), s.MaxClaim)
	}
	if len(pub.Imprint) != 32 {
		return nil, fmt.Errorf("imprint is %d bytes, not 32 (SHA-256)", len(pub.Imprint))
	}
	c := NewHiddenIssuerCircuit(s)
	padded := make([]byte, len(c.Claim)*claimChunk)
	copy(padded, pub.Claim)
	for k := range c.Claim {
		c.Claim[k] = new(big.Int).SetBytes(padded[k*claimChunk : (k+1)*claimChunk])
	}
	c.ClaimLen = len(pub.Claim)
	c.Root = root
	c.Time = pub.Time
	c.Imprint = [2]frontend.Variable{new(big.Int).SetBytes(pub.Imprint[:16]), new(big.Int).SetBytes(pub.Imprint[16:])}
	for i := range c.SigStructure {
		c.SigStructure[i] = 0
	}
	c.ProtectedLen = 0
	for i := range c.ClaimSig {
		c.ClaimSig[i] = 0
	}
	zeroFr := emulated.ValueOf[emulated.P384Fr](0)
	zeroFp := emulated.ValueOf[emulated.P384Fp](0)
	c.CASig = gnarkecdsa.Signature[emulated.P384Fr]{R: zeroFr, S: zeroFr}
	c.CAKey = gnarkecdsa.PublicKey[emulated.P384Fp, emulated.P384Fr]{X: zeroFp, Y: zeroFp}
	c.CANotBefore, c.CANotAfter = 0, 0
	for d := 0; d < issuertree.Depth; d++ {
		c.Siblings[d], c.IndexBits[d] = 0, 0
	}
	return c, nil
}
