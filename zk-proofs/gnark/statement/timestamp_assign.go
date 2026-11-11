package statement

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"

	"c2pa-zk-gnark/issuertree"
)

// TokenParts are a time-stamp token's parts the gadget takes, as the prover
// extracts them (ParseToken).
type TokenParts struct {
	SignedAttrs []byte // DER, with the SET OF tag (the signature's preimage)
	TSTInfo     []byte
	TSACert     []byte // the TSA certificate (DER)
	TSASig      []byte // r || s
}

var (
	oidSignedData  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidCTTSTInfo   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

// ParseToken extracts the gadget's parts from an RFC 3161 TimeStampToken (a
// CMS ContentInfo), or a TimeStampResp holding one. It checks only what it
// needs to find them; the circuit enforces the contract.
func ParseToken(der []byte) (TokenParts, error) {
	var parts TokenParts
	var top asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &top); err != nil || len(rest) != 0 {
		return parts, fmt.Errorf("token is not one DER value: %v", err)
	}
	// A TimeStampResp is SEQUENCE { status SEQUENCE, timeStampToken }; a
	// ContentInfo starts with an OID.
	var first asn1.RawValue
	if _, err := asn1.Unmarshal(top.Bytes, &first); err == nil && first.Tag == asn1.TagSequence {
		var resp struct {
			Status asn1.RawValue
			Token  asn1.RawValue
		}
		if _, err := asn1.Unmarshal(der, &resp); err != nil {
			return parts, fmt.Errorf("malformed TimeStampResp: %v", err)
		}
		der = resp.Token.FullBytes
	}
	var ci struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue // [0] EXPLICIT SignedData
	}
	if rest, err := asn1.Unmarshal(der, &ci); err != nil || len(rest) != 0 || !ci.Type.Equal(oidSignedData) {
		return parts, fmt.Errorf("token is not a CMS SignedData: %v", err)
	}
	var sd struct {
		Version int
		Digests asn1.RawValue
		Encap   struct {
			Type    asn1.ObjectIdentifier
			Content asn1.RawValue // [0] EXPLICIT OCTET STRING
		}
		Certificates asn1.RawValue   `asn1:"optional,tag:0"`
		CRLs         asn1.RawValue   `asn1:"optional,tag:1"`
		SignerInfos  []asn1.RawValue `asn1:"set"`
	}
	if ci.Content.Class != asn1.ClassContextSpecific || ci.Content.Tag != 0 {
		return parts, fmt.Errorf("token is not a CMS SignedData")
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return parts, fmt.Errorf("malformed SignedData: %v", err)
	}
	var octets asn1.RawValue
	if !sd.Encap.Type.Equal(oidCTTSTInfo) || sd.Encap.Content.Class != asn1.ClassContextSpecific || sd.Encap.Content.Tag != 0 {
		return parts, fmt.Errorf("the token's content is not a TSTInfo")
	}
	if rest, err := asn1.Unmarshal(sd.Encap.Content.Bytes, &octets); err != nil || len(rest) != 0 || octets.Tag != asn1.TagOctetString {
		return parts, fmt.Errorf("the token's content is not a TSTInfo: %v", err)
	}
	parts.TSTInfo = octets.Bytes
	if len(sd.SignerInfos) != 1 {
		return parts, fmt.Errorf("the token has %d signers, not 1", len(sd.SignerInfos))
	}
	var si struct {
		Version     int
		SID         asn1.RawValue
		Digest      pkix.AlgorithmIdentifier
		SignedAttrs asn1.RawValue `asn1:"optional,tag:0"`
		SigAlg      pkix.AlgorithmIdentifier
		Signature   []byte
		Unsigned    asn1.RawValue `asn1:"optional,tag:1"`
	}
	if _, err := asn1.Unmarshal(sd.SignerInfos[0].FullBytes, &si); err != nil {
		return parts, fmt.Errorf("malformed SignerInfo: %v", err)
	}
	if len(si.SignedAttrs.FullBytes) == 0 {
		return parts, fmt.Errorf("the token has no signed attributes")
	}
	if !si.SigAlg.Algorithm.Equal(oidECDSASHA256) {
		return parts, fmt.Errorf("the TSA's signature is not ECDSA with SHA-256")
	}
	// The signature covers the attributes with the SET OF tag (RFC 5652 §5.4).
	parts.SignedAttrs = append([]byte{0x31}, si.SignedAttrs.FullBytes[1:]...)
	var rs struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(si.Signature, &rs); err != nil || len(rest) != 0 {
		return parts, fmt.Errorf("the TSA's signature is not ECDSA: %v", err)
	}
	if rs.R.BitLen() > 256 || rs.S.BitLen() > 256 {
		return parts, fmt.Errorf("the TSA's signature is not P-256")
	}
	parts.TSASig = append(rs.R.FillBytes(make([]byte, 32)), rs.S.FillBytes(make([]byte, 32))...)

	// The TSA certificate: the token's certificate whose key verifies the signature.
	digest := sha256.Sum256(parts.SignedAttrs)
	for rest := sd.Certificates.Bytes; len(rest) > 0; {
		var raw asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &raw); err != nil {
			return parts, fmt.Errorf("malformed certificate in the token: %v", err)
		}
		cert, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			continue
		}
		if key, ok := cert.PublicKey.(*ecdsa.PublicKey); ok && key.Curve == elliptic.P256() && ecdsa.Verify(key, digest[:], rs.R, rs.S) {
			parts.TSACert = raw.FullBytes
			return parts, nil
		}
	}
	return parts, fmt.Errorf("the token does not carry a P-256 TSA certificate whose key verifies its signature")
}

// AssignToken builds the gadget's inputs from a token's parts.
func AssignToken(parts TokenParts, s TokenSizes) (TokenInputs, error) {
	tk := NewTokenInputs(s)
	if len(parts.SignedAttrs) > s.MaxSignedAttrs {
		return tk, fmt.Errorf("signed attributes are %d bytes; the circuit takes up to %d", len(parts.SignedAttrs), s.MaxSignedAttrs)
	}
	if len(parts.TSTInfo) > s.MaxTSTInfo {
		return tk, fmt.Errorf("TSTInfo is %d bytes; the circuit takes up to %d", len(parts.TSTInfo), s.MaxTSTInfo)
	}
	// Read structurally, not with x509.ParseCertificate: the circuit decides
	// what a valid TSA certificate is.
	var cert struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if rest, err := asn1.Unmarshal(parts.TSACert, &cert); err != nil || len(rest) != 0 {
		return tk, fmt.Errorf("TSA certificate is not a certificate: %v", err)
	}
	tbs := cert.TBS.FullBytes
	if len(tbs) < 256 || len(tbs) > s.MaxTSATBS {
		return tk, fmt.Errorf("TSA certificate TBS is %d bytes; the circuit takes 256 to %d", len(tbs), s.MaxTSATBS)
	}
	if len(parts.TSASig) != signatureLen {
		return tk, fmt.Errorf("TSA signature is %d bytes, not %d", len(parts.TSASig), signatureLen)
	}
	caSig, err := certificateSignature(parts.TSACert)
	if err != nil {
		return tk, fmt.Errorf("TSA certificate: %w", err)
	}
	set := func(dst []frontend.Variable, src []byte) {
		for i := range dst {
			if i < len(src) {
				dst[i] = src[i]
			} else {
				dst[i] = 0
			}
		}
	}
	set(tk.SignedAttrs, parts.SignedAttrs)
	set(tk.TSTInfo, parts.TSTInfo)
	set(tk.TSATBS, tbs)
	set(tk.TSASig, parts.TSASig)
	tk.SignedAttrsLen = len(parts.SignedAttrs)
	tk.TSTInfoLen = len(parts.TSTInfo)
	tk.TSACASig = gnarkecdsa.Signature[emulated.P384Fr]{
		R: emulated.ValueOf[emulated.P384Fr](caSig.R),
		S: emulated.ValueOf[emulated.P384Fr](caSig.S),
	}
	return tk, nil
}

// TokenCAKey is the P-384 key of the TSA CA certificate (DER), as the
// gadget's public input in TokenCircuit.
func TokenCAKey(caDER []byte) (gnarkecdsa.PublicKey[emulated.P384Fp, emulated.P384Fr], error) {
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return gnarkecdsa.PublicKey[emulated.P384Fp, emulated.P384Fr]{}, err
	}
	key, ok := ca.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P384() {
		return gnarkecdsa.PublicKey[emulated.P384Fp, emulated.P384Fr]{}, fmt.Errorf("TSA CA key is not P-384")
	}
	return gnarkecdsa.PublicKey[emulated.P384Fp, emulated.P384Fr]{
		X: emulated.ValueOf[emulated.P384Fp](key.X),
		Y: emulated.ValueOf[emulated.P384Fp](key.Y),
	}, nil
}

// TokenTime reads TSTInfo's genTime (Unix seconds) and imprint, for the
// prover's public inputs (the window) and checks.
func TokenTime(parts TokenParts) (int64, []byte, error) {
	var info struct {
		Version        int
		Policy         asn1.ObjectIdentifier
		MessageImprint struct {
			Algorithm pkix.AlgorithmIdentifier
			Digest    []byte
		}
		Serial  *big.Int
		GenTime time.Time     `asn1:"generalized"`
		Rest    asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(parts.TSTInfo, &info); err != nil {
		return 0, nil, fmt.Errorf("malformed TSTInfo: %v", err)
	}
	return info.GenTime.Unix(), info.MessageImprint.Digest, nil
}

// Window is the half-open window [t1, t2) of the given granularity (seconds)
// containing t, aligned to multiples of the granularity from the Unix epoch
// (for a day, UTC days; HIDING-THE-TIME-STAMP.md, T3).
func Window(t, granularity int64) (int64, int64) {
	t1 := t - t%granularity
	return t1, t1 + granularity
}

// HiddenAllPublic is what the verifier supplies for the statement hiding the
// issuer and the token: the claim, the roots of an issuer tree and a TSA tree
// it approves (canonical hex), and the window [T1, T2).
type HiddenAllPublic struct {
	Claim      []byte `json:"claim"`
	IssuerRoot string `json:"issuer_root"`
	TSARoot    string `json:"tsa_root"`
	T1         int64  `json:"t1"`
	T2         int64  `json:"t2"`
}

// AssignHiddenAll builds the full assignment of the statement hiding the
// issuer and the token: the statement's inputs (whose time and imprint must
// be the token's), the issuing CA's membership in the issuer tree, the token,
// and its TSA CA's membership in the TSA tree, with the window [t1, t2).
func AssignHiddenAll(in Inputs, issuers, tsas *issuertree.Tree, t1, t2 int64, s Sizes, ts TokenSizes) (*HiddenAllCircuit, error) {
	if issuers.Role != issuertree.RoleIssuer || tsas.Role != issuertree.RoleTSA {
		return nil, fmt.Errorf("the trees' roles are %s and %s, not issuer and tsa", issuers.Role, tsas.Role)
	}
	hidden, err := AssignHidden(in, issuers, s)
	if err != nil {
		return nil, err
	}
	parts, err := ParseToken(in.TimeStampToken)
	if err != nil {
		return nil, fmt.Errorf("time-stamp token: %w", err)
	}
	genTime, imprint, err := TokenTime(parts)
	if err != nil {
		return nil, err
	}
	if genTime != in.Time || !bytes.Equal(imprint, in.Imprint) {
		return nil, fmt.Errorf("the token's genTime and imprint are not the inputs' time and imprint")
	}
	if !(t1 <= genTime && genTime < t2) {
		return nil, fmt.Errorf("genTime %d is not in the window [%d, %d)", genTime, t1, t2)
	}
	tk, err := AssignToken(parts, ts)
	if err != nil {
		return nil, err
	}
	proof, err := tsaMembership(parts.TSACert, tsas, genTime)
	if err != nil {
		return nil, err
	}

	c := NewHiddenAllCircuit(s, ts)
	copy(c.Claim, hidden.Claim)
	c.ClaimLen = hidden.ClaimLen
	c.Root = hidden.Root
	c.TSARoot = tsas.Root()
	c.T1, c.T2 = t1, t2
	c.Time = hidden.Time
	c.Imprint = hidden.Imprint
	copy(c.SigStructure, hidden.SigStructure)
	c.ProtectedLen = hidden.ProtectedLen
	copy(c.ClaimSig, hidden.ClaimSig)
	c.CASig, c.CAKey = hidden.CASig, hidden.CAKey
	c.CANotBefore, c.CANotAfter = hidden.CANotBefore, hidden.CANotAfter
	c.Siblings, c.IndexBits = hidden.Siblings, hidden.IndexBits
	c.Token = tk
	c.TSACAKey = gnarkecdsa.PublicKey[emulated.P384Fp, emulated.P384Fr]{
		X: emulated.ValueOf[emulated.P384Fp](proof.CA.X),
		Y: emulated.ValueOf[emulated.P384Fp](proof.CA.Y),
	}
	c.TSACANotBefore, c.TSACANotAfter = proof.CA.NotBefore, proof.CA.NotAfter
	for d := 0; d < issuertree.Depth; d++ {
		c.TSASiblings[d] = proof.Siblings[d]
		c.TSAIndexBits[d] = (proof.Index >> d) & 1
	}
	return c, nil
}

// tsaMembership finds the TSA tree's entry whose key signed the TSA
// certificate (ECDSA-SHA384) and whose validity contains genTime, and returns
// its membership proof.
func tsaMembership(tsaCert []byte, tsas *issuertree.Tree, genTime int64) (issuertree.Proof, error) {
	var cert struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(tsaCert, &cert); err != nil {
		return issuertree.Proof{}, fmt.Errorf("TSA certificate: %v", err)
	}
	sig, err := certificateSignature(tsaCert)
	if err != nil {
		return issuertree.Proof{}, err
	}
	digest := sha512.Sum384(cert.TBS.FullBytes)
	for _, e := range tsas.Entries {
		key := &ecdsa.PublicKey{Curve: elliptic.P384(), X: e.X, Y: e.Y}
		if e.NotBefore <= genTime && genTime <= e.NotAfter && ecdsa.Verify(key, digest[:], sig.R, sig.S) {
			return tsas.Prove(e.CertSHA256s[0])
		}
	}
	return issuertree.Proof{}, fmt.Errorf("no CA in the TSA tree, valid at genTime, signed the TSA certificate")
}

// AssignHiddenAllPublic builds the public part of the assignment (the private
// part is zero), as the verifier does, for the key set's curve.
func AssignHiddenAllPublic(pub HiddenAllPublic, s Sizes, ts TokenSizes, curve ecc.ID) (*HiddenAllCircuit, error) {
	root, err := ParseRoot(pub.IssuerRoot, curve)
	if err != nil {
		return nil, err
	}
	tsaRoot, err := ParseRoot(pub.TSARoot, curve)
	if err != nil {
		return nil, fmt.Errorf("tsa_root: %w", err)
	}
	if !(0 <= pub.T1 && pub.T1 < pub.T2 && pub.T2 < 1<<timeBits) {
		return nil, fmt.Errorf("the window [%d, %d) is not an interval of Unix seconds below 2^%d", pub.T1, pub.T2, timeBits)
	}
	hidden, err := AssignHiddenPublic(HiddenPublic{Claim: pub.Claim, Root: pub.IssuerRoot, Time: 0, Imprint: make([]byte, 32)}, s, curve)
	if err != nil {
		return nil, err
	}
	c := NewHiddenAllCircuit(s, ts)
	copy(c.Claim, hidden.Claim)
	c.ClaimLen = hidden.ClaimLen
	c.Root, c.TSARoot = root, tsaRoot
	c.T1, c.T2 = pub.T1, pub.T2
	c.Time, c.Imprint = 0, [2]frontend.Variable{0, 0}
	copy(c.SigStructure, hidden.SigStructure)
	c.ProtectedLen = 0
	copy(c.ClaimSig, hidden.ClaimSig)
	c.CASig, c.CAKey = hidden.CASig, hidden.CAKey
	c.CANotBefore, c.CANotAfter = 0, 0
	zeroFp, zeroFr := emulated.ValueOf[emulated.P384Fp](0), emulated.ValueOf[emulated.P384Fr](0)
	for _, v := range [][]frontend.Variable{c.Token.SignedAttrs, c.Token.TSTInfo, c.Token.TSATBS, c.Token.TSASig} {
		for i := range v {
			v[i] = 0
		}
	}
	c.Token.SignedAttrsLen, c.Token.TSTInfoLen = 0, 0
	c.Token.TSACASig = gnarkecdsa.Signature[emulated.P384Fr]{R: zeroFr, S: zeroFr}
	c.TSACAKey = gnarkecdsa.PublicKey[emulated.P384Fp, emulated.P384Fr]{X: zeroFp, Y: zeroFp}
	c.TSACANotBefore, c.TSACANotAfter = 0, 0
	for d := 0; d < issuertree.Depth; d++ {
		c.Siblings[d], c.IndexBits[d], c.TSASiblings[d], c.TSAIndexBits[d] = 0, 0, 0, 0
	}
	return c, nil
}
