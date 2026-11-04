package statement

// Test fixtures: a P-384 issuing CA, a P-256 signer certificate built field by
// field (so tests can produce certificates the x509 package would refuse to
// create, such as duplicate or hidden extensions), a protected header, a
// claim, the ES256 claim signature, and the v2 time stamp's imprint.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

var (
	oidEKU             = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidBC              = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKU              = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidSKI             = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAIA             = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidEmailProtection = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidC2PAClaimSign   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62558, 2, 1}
	oidPrivate         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
)

type fixtureOptions struct {
	purposes           []asn1.ObjectIdentifier // default: email protection and C2PA claim signing
	noEKU              bool                    // omit the extended key usage extension
	duplicateEKU       bool                    // a second extended key usage extension
	hiddenEKU          bool                    // a full EKU extension inside a private extension's value
	isCA               bool                    // basic constraints cA TRUE
	basicConstraints   []byte                  // this basic constraints value instead (DER)
	noBasicConstraints bool                    // omit the basic constraints extension
	claimLen           int                     // default 377
}

type fixture struct {
	in                  Inputs
	notBefore, notAfter time.Time
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func name(cn string) pkix.RDNSequence {
	return pkix.Name{Country: []string{"US"}, Organization: []string{"Fixture PKI"}, CommonName: cn}.ToRDNSequence()
}

func newFixture(t *testing.T, opt fixtureOptions) *fixture {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fixture Issuing CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour * 365),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&leafKey.PublicKey)

	purposes := opt.purposes
	if purposes == nil {
		purposes = []asn1.ObjectIdentifier{oidEmailProtection, oidC2PAClaimSign}
	}
	eku := pkix.Extension{Id: oidEKU, Value: mustMarshal(t, purposes)}
	bc := []byte{0x30, 0x00}
	if opt.isCA {
		bc = []byte{0x30, 0x03, 0x01, 0x01, 0xff}
	}
	if opt.basicConstraints != nil {
		bc = opt.basicConstraints
	}
	var extensions []pkix.Extension
	if !opt.noBasicConstraints {
		extensions = append(extensions, pkix.Extension{Id: oidBC, Critical: true, Value: bc})
	}
	extensions = append(extensions, []pkix.Extension{
		{Id: oidKU, Critical: true, Value: mustMarshal(t, asn1.BitString{Bytes: []byte{0xc0}, BitLength: 2})},
		{Id: oidSKI, Value: mustMarshal(t, make([]byte, 20))},
		{Id: oidAIA, Value: mustMarshal(t, []string{"http://ocsp.example.invalid/", "http://pki.example.invalid/ca.crt"})},
	}...)
	if !opt.noEKU && !opt.hiddenEKU {
		extensions = append(extensions, eku)
	}
	if opt.duplicateEKU {
		extensions = append(extensions, pkix.Extension{Id: oidEKU, Value: mustMarshal(t, []asn1.ObjectIdentifier{oidEmailProtection})})
	}
	if opt.hiddenEKU {
		extensions = append(extensions, pkix.Extension{Id: oidPrivate, Value: mustMarshal(t, eku)})
	}

	notBefore := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	notAfter := notBefore.Add(90 * 24 * time.Hour)
	tbs := struct {
		Version    int `asn1:"optional,explicit,default:0,tag:0"`
		Serial     *big.Int
		Algorithm  pkix.AlgorithmIdentifier
		Issuer     pkix.RDNSequence
		Validity   struct{ NotBefore, NotAfter time.Time }
		Subject    pkix.RDNSequence
		SPKI       asn1.RawValue
		Extensions []pkix.Extension `asn1:"optional,explicit,tag:3"`
	}{
		Version: 2, Serial: big.NewInt(0x1234567890), Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA384},
		Issuer: name("Fixture Issuing CA"), Subject: name("Fixture Signer"), SPKI: asn1.RawValue{FullBytes: spki},
		Extensions: extensions,
	}
	tbs.Validity.NotBefore, tbs.Validity.NotAfter = notBefore, notAfter
	tbsDER := mustMarshal(t, tbs)
	digest := sha512.Sum384(tbsDER)
	caSig, err := ecdsa.SignASN1(rand.Reader, caKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	leafDER := mustMarshal(t, struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbsDER}, pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA384}, asn1.BitString{Bytes: caSig, BitLength: 8 * len(caSig)}})

	protected := append([]byte{}, protectedStart...)
	protected = append(protected, 0x82, 0x59, byte(len(leafDER)>>8), byte(len(leafDER)))
	protected = append(protected, leafDER...)
	protected = append(protected, 0x59, byte(len(caDER)>>8), byte(len(caDER)))
	protected = append(protected, caDER...)

	claimLen := opt.claimLen
	if claimLen == 0 {
		claimLen = 377
	}
	claim := make([]byte, claimLen)
	for i := range claim {
		claim[i] = byte(0xa0 + i*7)
	}

	sigDigest := sha256.Sum256(SigStructure(protected, claim))
	r, s, err := ecdsa.Sign(rand.Reader, leafKey, sigDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	imprint := sha256.Sum256(Countersignature(protected, signature))

	return &fixture{
		in: Inputs{
			Public: Public{
				Claim: claim, IssuerCert: caDER, Time: notBefore.Add(time.Hour).Unix(), Imprint: imprint[:],
			},
			Protected: protected,
			Signature: signature,
		},
		notBefore: notBefore,
		notAfter:  notAfter,
	}
}
