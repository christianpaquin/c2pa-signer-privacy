package statement

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
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
