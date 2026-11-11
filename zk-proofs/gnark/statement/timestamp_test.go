package statement

// Tests of the token gadget (HIDING-THE-TIME-STAMP.md, T2 and T3): tokens
// built field by field, so that each test can produce a token a TSA would
// not, and each rejection names one part of the verification contract.

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
	"sync"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

var compiledToken = map[ecc.ID]*compiledCircuit{ecc.BN254: {}, ecc.BLS12_381: {}}

func tokenCircuitOn(t *testing.T, curve ecc.ID) *compiledCircuit {
	t.Helper()
	c := compiledToken[curve]
	c.once.Do(func() {
		c.ccs, c.err = frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, NewTokenCircuit(DefaultTokenSizes))
	})
	if c.err != nil {
		t.Fatal(c.err)
	}
	return c
}

func tlv(tag byte, content ...[]byte) []byte {
	var body []byte
	for _, c := range content {
		body = append(body, c...)
	}
	n := len(body)
	switch {
	case n < 128:
		return append([]byte{tag, byte(n)}, body...)
	case n < 256:
		return append([]byte{tag, 0x81, byte(n)}, body...)
	default:
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, body...)
	}
}

func oidDER(t *testing.T, oid asn1.ObjectIdentifier) []byte { return mustMarshal(t, oid) }

var (
	oidAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidSHA256            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidTimeStamping      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidCodeSigning       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
)

// tokenOptions change one thing from a valid token.
type tokenOptions struct {
	attributes  func(ct, md, other []byte) [][]byte // the signed attributes, from the valid three
	signWithA0  bool                                // the attributes tagged [0], as in the SignerInfo, signed and supplied so
	tstInfo     func(imprint []byte, genTime string) []byte
	genTime     time.Time               // default: a fixed time in the TSA certificate's validity
	ekus        []asn1.ObjectIdentifier // default: time stamping only
	ekuCritical *bool                   // default: true
	noEKU       bool                    // omit the EKU extension
	extraEKU    bool                    // a second EKU extension
	isCA        bool                    // basic constraints cA TRUE
	otherCA     bool                    // the TSA certificate signed by another CA than the public one
	validity    *[2]time.Time           // the TSA certificate's validity
	changeTST   bool                    // TSTInfo changed after the attributes were made
	changeSig   bool                    // the TSA's signature changed
	changeCASig bool                    // the TSA CA's signature changed
}

type tokenFixture struct {
	parts   TokenParts
	caDER   []byte
	genTime int64
	imprint []byte
}

var tokenCAs = sync.OnceValue(func() [2]*ecdsa.PrivateKey {
	a, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	b, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	return [2]*ecdsa.PrivateKey{a, b}
})

// The default genTime: 2026-11-11 14:23:05 UTC.
var defaultGenTime = time.Date(2026, 11, 11, 14, 23, 5, 0, time.UTC)

func newToken(t *testing.T, opt tokenOptions) *tokenFixture {
	t.Helper()
	caKey := tokenCAs()[0]
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Token Test TSA CA"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	// The TSA certificate, field by field.
	tsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&tsaKey.PublicKey)
	ekus := opt.ekus
	if ekus == nil {
		ekus = []asn1.ObjectIdentifier{oidTimeStamping}
	}
	critical := opt.ekuCritical == nil || *opt.ekuCritical
	bc := []byte{0x30, 0x00}
	if opt.isCA {
		bc = []byte{0x30, 0x03, 0x01, 0x01, 0xff}
	}
	extensions := []pkix.Extension{
		{Id: oidBC, Critical: true, Value: bc},
		{Id: oidKU, Critical: true, Value: mustMarshal(t, asn1.BitString{Bytes: []byte{0xc0}, BitLength: 2})},
		{Id: oidSKI, Value: mustMarshal(t, make([]byte, 20))},
	}
	if !opt.noEKU {
		extensions = append(extensions, pkix.Extension{Id: oidEKU, Critical: critical, Value: mustMarshal(t, ekus)})
	}
	if opt.extraEKU {
		extensions = append(extensions, pkix.Extension{Id: oidEKU, Critical: true, Value: mustMarshal(t, []asn1.ObjectIdentifier{oidTimeStamping})})
	}
	validity := [2]time.Time{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)}
	if opt.validity != nil {
		validity = *opt.validity
	}
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
		Version: 2, Serial: big.NewInt(0x5151), Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA384},
		Issuer: name("Token Test TSA CA"), Subject: name("Token Test Time Stamping Authority"), SPKI: asn1.RawValue{FullBytes: spki},
		Extensions: extensions,
	}
	tbs.Validity.NotBefore, tbs.Validity.NotAfter = validity[0], validity[1]
	tbsDER := mustMarshal(t, tbs)
	signer := caKey
	if opt.otherCA {
		signer = tokenCAs()[1]
	}
	tbsDigest := sha512.Sum384(tbsDER)
	caSig, err := ecdsa.SignASN1(rand.Reader, signer, tbsDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	if opt.changeCASig {
		caSig = changedSignature(t, caSig)
	}
	tsaDER := mustMarshal(t, struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbsDER}, pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA384}, asn1.BitString{Bytes: caSig, BitLength: 8 * len(caSig)}})

	// TSTInfo.
	genTime := opt.genTime
	if genTime.IsZero() {
		genTime = defaultGenTime
	}
	imprint := sha256.Sum256([]byte("the original signature's countersignature structure"))
	gen := genTime.UTC().Format("20060102150405Z")
	var tst []byte
	if opt.tstInfo != nil {
		tst = opt.tstInfo(imprint[:], gen)
	} else {
		tst = defaultTSTInfo(t, imprint[:], gen)
	}
	digest := sha256.Sum256(tst)
	if opt.changeTST {
		tst = append([]byte{}, tst...)
		tst[len(tst)-1] ^= 1
	}

	// The signed attributes.
	ct := tlv(0x30, oidDER(t, oidAttrContentType), tlv(0x31, oidDER(t, oidCTTSTInfo)))
	md := tlv(0x30, oidDER(t, oidAttrMessageDigest), tlv(0x31, tlv(0x04, digest[:])))
	other := tlv(0x30, oidDER(t, oidAttrSigningCertV2), tlv(0x31, tlv(0x30, tlv(0x30, tlv(0x30, tlv(0x04, make([]byte, 32)))))))
	attrs := [][]byte{ct, md, other}
	if opt.attributes != nil {
		attrs = opt.attributes(ct, md, other)
	}
	tag := byte(0x31)
	if opt.signWithA0 {
		tag = 0xa0
	}
	signedAttrs := tlv(tag, attrs...)
	attrsDigest := sha256.Sum256(signedAttrs)
	r, s, err := ecdsa.Sign(rand.Reader, tsaKey, attrsDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	if opt.changeSig {
		sig[40] ^= 1
	}
	return &tokenFixture{
		parts:   TokenParts{SignedAttrs: signedAttrs, TSTInfo: tst, TSACert: tsaDER, TSASig: sig},
		caDER:   caDER,
		genTime: genTime.Unix(),
		imprint: imprint[:],
	}
}

func defaultTSTInfo(t *testing.T, imprint []byte, genTime string) []byte {
	return tstInfoWith(t, []byte{0x02, 0x01, 0x01}, tlv(0x30, oidDER(t, oidSHA256)), imprint, genTime)
}

func tstInfoWith(t *testing.T, version, algID, imprint []byte, genTime string) []byte {
	return tlv(0x30,
		version,
		oidDER(t, asn1.ObjectIdentifier{1, 2, 3, 4}), // policy
		tlv(0x30, algID, tlv(0x04, imprint)),
		tlv(0x02, []byte{0x35, 0x55, 0xb1, 0xd3, 0x21, 0x72, 0x31, 0xda}), // serialNumber
		tlv(0x18, []byte(genTime)),
		tlv(0x30, tlv(0x02, []byte{0x0a})), // accuracy
	)
}

// changedSignature changes one bit of an ASN.1 ECDSA signature's s.
func changedSignature(t *testing.T, der []byte) []byte {
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &rs); err != nil {
		t.Fatal(err)
	}
	rs.S.Xor(rs.S, big.NewInt(1))
	return mustMarshal(t, rs)
}

// tokenAssignment assigns the gadget for a token in the window [t1, t2).
func tokenAssignment(t *testing.T, f *tokenFixture, t1, t2 int64) *TokenCircuit {
	t.Helper()
	c := NewTokenCircuit(DefaultTokenSizes)
	var err error
	if c.Token, err = AssignToken(f.parts, DefaultTokenSizes); err != nil {
		t.Fatal(err)
	}
	if c.TSACAKey, err = TokenCAKey(f.caDER); err != nil {
		t.Fatal(err)
	}
	c.T1, c.T2 = t1, t2
	c.Imprint = [2]frontend.Variable{new(big.Int).SetBytes(f.imprint[:16]), new(big.Int).SetBytes(f.imprint[16:])}
	return c
}

func tokenSolved(t *testing.T, curve ecc.ID, c *TokenCircuit) bool {
	t.Helper()
	w, err := frontend.NewWitness(c, curve.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return tokenCircuitOn(t, curve).ccs.IsSolved(w) == nil
}

// inDay assigns a token in its UTC day's window.
func inDay(t *testing.T, f *tokenFixture) *TokenCircuit {
	t1, t2 := Window(f.genTime, 86400)
	return tokenAssignment(t, f, t1, t2)
}

func TestTokenIsAccepted(t *testing.T) {
	forEachCurve(t, func(t *testing.T, curve ecc.ID) {
		if !tokenSolved(t, curve, inDay(t, newToken(t, tokenOptions{}))) {
			t.Fatal("valid token rejected")
		}
		// The imprint's algorithm with NULL parameters is SHA-256 too.
		withNull := newToken(t, tokenOptions{tstInfo: func(imprint []byte, gen string) []byte {
			return tstInfoWith(t, []byte{0x02, 0x01, 0x01}, tlv(0x30, oidDER(t, oidSHA256), []byte{0x05, 0x00}), imprint, gen)
		}})
		if !tokenSolved(t, curve, inDay(t, withNull)) {
			t.Fatal("SHA-256 with NULL parameters rejected")
		}
		t.Logf("%d constraints at the default sizes", tokenCircuitOn(t, curve).ccs.GetNbConstraints())
	})
}

// The contract (T2): the signed attributes.
func TestTokenSignedAttributesContract(t *testing.T) {
	forEachCurve(t, func(t *testing.T, curve ecc.ID) {
		tc := func(t *testing.T) []byte { return oidDER(t, oidCTTSTInfo) }
		cases := map[string]tokenOptions{
			"no contentType":   {attributes: func(ct, md, o []byte) [][]byte { return [][]byte{md, o} }},
			"two contentTypes": {attributes: func(ct, md, o []byte) [][]byte { return [][]byte{ct, md, ct} }},
			"contentType with two values": {attributes: func(ct, md, o []byte) [][]byte {
				return [][]byte{tlv(0x30, oidDER(t, oidAttrContentType), tlv(0x31, tc(t), tc(t))), md, o}
			}},
			"contentType of another type": {attributes: func(ct, md, o []byte) [][]byte {
				return [][]byte{tlv(0x30, oidDER(t, oidAttrContentType), tlv(0x31, oidDER(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}))), md, o}
			}},
			"no messageDigest":   {attributes: func(ct, md, o []byte) [][]byte { return [][]byte{ct, o} }},
			"two messageDigests": {attributes: func(ct, md, o []byte) [][]byte { return [][]byte{ct, md, md} }},
			"messageDigest with two values": {attributes: func(ct, md, o []byte) [][]byte {
				v := md[len(md)-34:]
				return [][]byte{ct, tlv(0x30, oidDER(t, oidAttrMessageDigest), tlv(0x31, v, v)), o}
			}},
			"messageDigest of other bytes": {attributes: func(ct, md, o []byte) [][]byte {
				other := sha256.Sum256([]byte("other"))
				return [][]byte{ct, tlv(0x30, oidDER(t, oidAttrMessageDigest), tlv(0x31, tlv(0x04, other[:]))), o}
			}},
			"an attribute with more than an OID and values": {attributes: func(ct, md, o []byte) [][]byte {
				return [][]byte{ct, md, tlv(0x30, oidDER(t, oidAttrSigningCertV2), tlv(0x31), []byte{0x05, 0x00})}
			}},
			"attributes signed with the [0] tag": {signWithA0: true},
			"a changed TSA signature":            {changeSig: true},
		}
		for name, opt := range cases {
			if tokenSolved(t, curve, inDay(t, newToken(t, opt))) {
				t.Errorf("%s: accepted", name)
			}
		}
		// Other attributes are ignored, in any order.
		reordered := newToken(t, tokenOptions{attributes: func(ct, md, o []byte) [][]byte { return [][]byte{o, md, ct} }})
		if !tokenSolved(t, curve, inDay(t, reordered)) {
			t.Error("attributes in another order: rejected")
		}
	})
}

// The contract (T2): TSTInfo.
func TestTokenTSTInfoContract(t *testing.T) {
	forEachCurve(t, func(t *testing.T, curve ecc.ID) {
		cases := map[string]tokenOptions{
			"TSTInfo changed after signing": {changeTST: true},
			"version 2": {tstInfo: func(imprint []byte, gen string) []byte {
				return tstInfoWith(t, []byte{0x02, 0x01, 0x02}, tlv(0x30, oidDER(t, oidSHA256)), imprint, gen)
			}},
			"a SHA-384 imprint algorithm": {tstInfo: func(imprint []byte, gen string) []byte {
				return tstInfoWith(t, []byte{0x02, 0x01, 0x01}, tlv(0x30, oidDER(t, oidSHA384)), imprint, gen)
			}},
			"genTime with fractional seconds": {tstInfo: func(imprint []byte, gen string) []byte {
				return tstInfoWith(t, []byte{0x02, 0x01, 0x01}, tlv(0x30, oidDER(t, oidSHA256)), imprint, gen[:14]+".5Z")
			}},
			"genTime in the 2100s": {tstInfo: func(imprint []byte, gen string) []byte {
				return tstInfoWith(t, []byte{0x02, 0x01, 0x01}, tlv(0x30, oidDER(t, oidSHA256)), imprint, "21"+gen[2:])
			}},
		}
		for name, opt := range cases {
			if tokenSolved(t, curve, inDay(t, newToken(t, opt))) {
				t.Errorf("%s: accepted", name)
			}
		}
		// The public imprint must be TSTInfo's.
		c := inDay(t, newToken(t, tokenOptions{}))
		c.Imprint[1] = new(big.Int).Add(c.Imprint[1].(*big.Int), big.NewInt(1))
		if tokenSolved(t, curve, c) {
			t.Error("another imprint: accepted")
		}
	})
}

// The contract (T2): the TSA certificate and the TSA CA.
func TestTokenTSACertificateContract(t *testing.T) {
	forEachCurve(t, func(t *testing.T, curve ecc.ID) {
		no := false
		cases := map[string]tokenOptions{
			"EKU not critical":             {ekuCritical: &no},
			"EKU with another purpose too": {ekus: []asn1.ObjectIdentifier{oidTimeStamping, oidCodeSigning}},
			"EKU without time stamping":    {ekus: []asn1.ObjectIdentifier{oidCodeSigning}},
			"no EKU":                       {noEKU: true},
			"two EKU extensions":           {extraEKU: true},
			"a CA certificate":             {isCA: true},
			"issued by another CA":         {otherCA: true},
			"a changed CA signature":       {changeCASig: true},
			"not yet valid at genTime":     {validity: &[2]time.Time{defaultGenTime.Add(time.Second), defaultGenTime.Add(time.Hour)}},
			"expired at genTime":           {validity: &[2]time.Time{defaultGenTime.Add(-time.Hour), defaultGenTime.Add(-time.Second)}},
		}
		for name, opt := range cases {
			if tokenSolved(t, curve, inDay(t, newToken(t, opt))) {
				t.Errorf("%s: accepted", name)
			}
		}
		// Validity boundaries are inclusive.
		for _, v := range [][2]time.Time{{defaultGenTime, defaultGenTime.Add(time.Hour)}, {defaultGenTime.Add(-time.Hour), defaultGenTime}} {
			v := v
			if !tokenSolved(t, curve, inDay(t, newToken(t, tokenOptions{validity: &v}))) {
				t.Errorf("genTime at a validity boundary %v: rejected", v)
			}
		}
	})
}

// The window (T3): half-open, [t1, t2).
func TestTokenWindowIsHalfOpen(t *testing.T) {
	forEachCurve(t, func(t *testing.T, curve ecc.ID) {
		midnight := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
		f := newToken(t, tokenOptions{genTime: midnight})
		g := f.genTime
		for name, w := range map[string][2]int64{
			"midnight, in the day it starts": {g, g + 86400},
			"a one-second window":            {g, g + 1},
		} {
			if !tokenSolved(t, curve, tokenAssignment(t, f, w[0], w[1])) {
				t.Errorf("%s: rejected", name)
			}
		}
		for name, w := range map[string][2]int64{
			"midnight, in the day it ends": {g - 86400, g},
			"genTime = t2 (one second)":    {g - 1, g},
			"genTime before t1":            {g + 1, g + 2},
			"an empty window":              {g, g},
		} {
			if tokenSolved(t, curve, tokenAssignment(t, f, w[0], w[1])) {
				t.Errorf("%s: accepted", name)
			}
		}
		// Window aligns to UTC days.
		if t1, t2 := Window(g, 86400); t1 != g || t2 != g+86400 {
			t.Errorf("Window(midnight) = [%d, %d)", t1, t2)
		}
		if t1, _ := Window(g-1, 86400); t1 != g-86400 {
			t.Errorf("Window(23:59:59) starts at %d", t1)
		}
	})
}

func TestParseTokenRefusesWhatItCannotUse(t *testing.T) {
	if _, err := ParseToken([]byte{0x30, 0x00}); err == nil {
		t.Fatal("an empty SEQUENCE was parsed as a token")
	}
	if _, err := ParseToken(append(newToken(t, tokenOptions{}).parts.SignedAttrs, 0)); err == nil {
		t.Fatal("signed attributes were parsed as a token")
	}
	f := newToken(t, tokenOptions{})
	big := f.parts
	big.TSTInfo = make([]byte, DefaultTokenSizes.MaxTSTInfo+1)
	if _, err := AssignToken(big, DefaultTokenSizes); err == nil {
		t.Fatal("an oversized TSTInfo was assigned")
	}
}

// genTime must be a date that exists: a day beyond its month's length is not
// normalized into the next month (HIDING-THE-TIME-STAMP.md, T2).
func TestTokenGenTimeIsACalendarDate(t *testing.T) {
	forEachCurve(t, func(t *testing.T, curve ecc.ID) {
		wide := [2]time.Time{time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)}
		// A token whose genTime is the given digits, in the window of the
		// date they would normalize to.
		check := func(digits string, y, m, d int) bool {
			normalized := time.Date(y, time.Month(m), d, 12, 0, 0, 0, time.UTC)
			f := newToken(t, tokenOptions{validity: &wide, genTime: normalized, tstInfo: func(imprint []byte, _ string) []byte {
				return tstInfoWith(t, []byte{0x02, 0x01, 0x01}, tlv(0x30, oidDER(t, oidSHA256)), imprint, digits)
			}})
			return tokenSolved(t, curve, inDay(t, f))
		}
		for name, c := range map[string]struct {
			digits  string
			y, m, d int
		}{
			"February 29 in a common year": {"20260229120000Z", 2026, 2, 29},
			"February 30":                  {"20280230120000Z", 2028, 2, 30},
			"February 31":                  {"20260231120000Z", 2026, 2, 31},
			"April 31":                     {"20260431120000Z", 2026, 4, 31},
			"November 31":                  {"20261131120000Z", 2026, 11, 31},
		} {
			if check(c.digits, c.y, c.m, c.d) {
				t.Errorf("%s: accepted", name)
			}
		}
		for name, c := range map[string]struct {
			digits  string
			y, m, d int
		}{
			"February 29 in a leap year":   {"20280229120000Z", 2028, 2, 29},
			"February 28 in a common year": {"20260228120000Z", 2026, 2, 28},
			"December 31":                  {"20261231120000Z", 2026, 12, 31},
			"April 30":                     {"20260430120000Z", 2026, 4, 30},
		} {
			if !check(c.digits, c.y, c.m, c.d) {
				t.Errorf("%s: rejected", name)
			}
		}
	})
}

// The window's endpoints are integers in [0, 2^34): field elements that would
// wrap around (p - 1 acting as -1) or larger values are rejected.
func TestTokenWindowEndpointsAreBounded(t *testing.T) {
	forEachCurve(t, func(t *testing.T, curve ecc.ID) {
		f := newToken(t, tokenOptions{})
		g := f.genTime
		pMinus1 := new(big.Int).Sub(curve.ScalarField(), big.NewInt(1))
		limit := new(big.Int).Lsh(big.NewInt(1), timeBits)
		assign := func(t1, t2 any) *TokenCircuit {
			c := tokenAssignment(t, f, 0, 0)
			c.T1, c.T2 = t1, t2
			return c
		}
		for name, c := range map[string]*TokenCircuit{
			"t1 = p - 1": assign(pMinus1, g+1),
			"t2 = p - 1": assign(g, pMinus1),
			"t2 = 2^34":  assign(g, limit),
			"t1 = 2^34":  assign(limit, g+1),
		} {
			if tokenSolved(t, curve, c) {
				t.Errorf("%s: accepted", name)
			}
		}
		if !tokenSolved(t, curve, assign(0, new(big.Int).Sub(limit, big.NewInt(1)))) {
			t.Error("the widest window in range: rejected")
		}
	})
}
