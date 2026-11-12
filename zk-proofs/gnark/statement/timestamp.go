package statement

// The hidden time-stamp token (roadmap I6, HIDING-THE-TIME-STAMP.md): a gadget
// that verifies an RFC 3161 token's parts in the circuit, under the note's
// verification contract (T2), and returns its genTime and imprint.
//
// Private inputs (TokenInputs): the signed attributes, DER-encoded with the
// SET OF tag (the signature's preimage, RFC 5652 §5.4); TSTInfo; the TSA
// certificate's TBS; the TSA's ES256 signature (r || s); and the TSA CA's
// ECDSA-SHA384 signature over that TBS. The gadget proves, with every field
// read by walking the DER structure within these objects:
//
//   - the signed attributes are a SET OF attributes, each exactly an OID and a
//     SET of values, with exactly one contentType attribute, whose single value
//     is id-ct-TSTInfo, and exactly one messageDigest attribute, whose single
//     value is a 32-byte OCTET STRING; other attributes are ignored;
//   - messageDigest is the SHA-256 of TSTInfo's exact encoding;
//   - TSTInfo is version 1, its imprint's algorithm is SHA-256 (with or
//     without NULL parameters), and its genTime is a GeneralizedTime of the
//     form 20YYMMDDHHMMSSZ (whole seconds, years 2000-2049);
//   - the TSA's key signed (ES256) the SHA-256 of the signed attributes;
//   - walking the TSA certificate's TBS: a v3 certificate whose subject key is
//     P-256, whose validity contains genTime, with exactly one extended key
//     usage extension, critical, whose only purpose is time stamping (RFC
//     3161 §2.3), and which is not a CA;
//   - the given TSA CA key signed that TBS (ECDSA P-384, SHA-384).
//
// Deliberately not checked (a reduced profile, T2): signingCertificateV2,
// the TSA certificate's other extensions, and TSTInfo's fields after genTime.

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

// TokenSizes are the gadget's maximum input lengths (HIDING-THE-TIME-STAMP.md, T2).
type TokenSizes struct {
	MaxSignedAttrs   int // the signed attributes, SET OF tag included
	MaxTSTInfo       int
	MaxTSATBS        int // the TSA certificate's TBSCertificate, DER header included
	MaxAttributes    int // signed attributes walked
	MaxTSAExtensions int // the TSA certificate's extensions walked
}

// DefaultTokenSizes: a real token has 137 bytes of signed attributes (3
// attributes), a 98-byte TSTInfo, and a 652-byte TSA TBS.
var DefaultTokenSizes = TokenSizes{MaxSignedAttrs: 256, MaxTSTInfo: 256, MaxTSATBS: 1024, MaxAttributes: 8, MaxTSAExtensions: 16}

// tokenPad is how many zero bytes follow each buffer in its lookup table, so
// that reads just past an object's end (headers of inactive loop steps, fixed
// patterns) stay in the table.
const tokenPad = 48

var (
	// 06 09 1.2.840.113549.1.9.3 (contentType)
	oidContentType = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03}
	// 06 09 1.2.840.113549.1.9.4 (messageDigest)
	oidMessageDigest = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04}
	// The contentType value set: exactly one OID, id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4).
	contentTypeTSTInfo = []byte{0x31, 0x0d, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04}
	// The messageDigest value set: exactly one 32-byte OCTET STRING.
	messageDigestValue = []byte{0x31, 0x22, 0x04, 0x20}
	// TSTInfo's version, INTEGER 1.
	tstVersion = []byte{0x02, 0x01, 0x01}
	// The imprint's AlgorithmIdentifier, SHA-256, without and with NULL parameters.
	sha256AlgID     = []byte{0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}
	sha256AlgIDNull = []byte{0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00}
	// The time-stamping-only extended key usage value: SEQUENCE { id-kp-timeStamping }.
	ekuTimeStampingOnly = []byte{0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08}
)

// TokenInputs are the token's parts, private inputs of the statements that
// hide it; allocate them with NewTokenInputs.
type TokenInputs struct {
	SignedAttrs    []frontend.Variable // zero-padded
	SignedAttrsLen frontend.Variable
	TSTInfo        []frontend.Variable // zero-padded
	TSTInfoLen     frontend.Variable
	TSATBS         []frontend.Variable // zero-padded
	TSASig         []frontend.Variable // r || s, 64 bytes
	TSACASig       ecdsa.Signature[emulated.P384Fr]
}

// NewTokenInputs allocates the token's inputs for the given sizes.
func NewTokenInputs(s TokenSizes) TokenInputs {
	return TokenInputs{
		SignedAttrs: make([]frontend.Variable, s.MaxSignedAttrs),
		TSTInfo:     make([]frontend.Variable, s.MaxTSTInfo),
		TSATBS:      make([]frontend.Variable, s.MaxTSATBS),
		TSASig:      make([]frontend.Variable, signatureLen),
	}
}

// newByteReader range-checks bytes, indexes them (with tokenPad zero bytes
// after) for lookups, and returns the reader and the bytes.
func newByteReader(api frontend.API, bapi *uints.Bytes, in []frontend.Variable) (*reader, []uints.U8) {
	return newByteReaderPad(api, bapi, in, tokenPad)
}

// newByteReaderPad is newByteReader with pad zero bytes after the input.
func newByteReaderPad(api frontend.API, bapi *uints.Bytes, in []frontend.Variable, pad int) (*reader, []uints.U8) {
	r := &reader{
		api:   api,
		table: logderivlookup.New(api),
		pos:   cmp.NewBoundedComparator(api, big.NewInt(1<<16), false),
		small: cmp.NewBoundedComparator(api, big.NewInt(1<<9), false),
	}
	out := make([]uints.U8, len(in))
	for i, v := range in {
		out[i] = bapi.ValueOf(v)
		r.table.Insert(v)
	}
	for i := 0; i < pad; i++ {
		r.table.Insert(0)
	}
	return r, out
}

// verifyToken is the gadget: it checks the token against tsaCAKey and
// returns genTime (Unix seconds) and the imprint (SHA-256, 32 bytes).
func verifyToken(api frontend.API, s TokenSizes, tk *TokenInputs, tsaCAKey *ecdsa.PublicKey[emulated.P384Fp, emulated.P384Fr]) (frontend.Variable, []frontend.Variable, error) {
	if len(tk.SignedAttrs) != s.MaxSignedAttrs || len(tk.TSTInfo) != s.MaxTSTInfo || len(tk.TSATBS) != s.MaxTSATBS || len(tk.TSASig) != signatureLen {
		return nil, nil, fmt.Errorf("token inputs not allocated for their sizes")
	}
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return nil, nil, err
	}

	// ---- Signed attributes --------------------------------------------------
	ra, attrs := newByteReader(api, bapi, tk.SignedAttrs)
	ra.pos.AssertIsLessEq(tk.SignedAttrsLen, s.MaxSignedAttrs)
	api.AssertIsEqual(ra.at(0), 0x31) // SET OF, as hashed (not the [0] of the SignerInfo)
	setLen, setHL := ra.header(0, 1)
	api.AssertIsEqual(api.Add(setHL, setLen), tk.SignedAttrsLen)
	cur, end := frontend.Variable(setHL), api.Add(setHL, setLen)
	ctCount, mdCount, mdPos := frontend.Variable(0), frontend.Variable(0), frontend.Variable(0)
	for k := 0; k < s.MaxAttributes; k++ {
		active := ra.pos.IsLess(cur, end)
		// Attribute ::= SEQUENCE { attrType OID, attrValues SET OF AttributeValue }
		ra.assertIf(active, ra.at(cur), 0x30)
		aLen, aHL := ra.header(cur, active)
		aEnd := api.Add(cur, aHL, aLen)
		oid := api.Add(cur, aHL)
		ra.assertIf(active, ra.at(oid), 0x06)
		oidLen := ra.at(api.Add(oid, 1))
		ra.assertIf(active, ra.small.IsLess(oidLen, 128), 1)
		values := api.Add(oid, 2, oidLen)
		ra.assertIf(active, ra.at(values), 0x31)
		vLen, vHL := ra.header(values, active)
		ra.assertIf(active, api.Add(values, vHL, vLen), aEnd) // exactly the OID and the values
		isCT := api.Mul(active, ra.matches(oid, oidContentType))
		isMD := api.Mul(active, ra.matches(oid, oidMessageDigest))
		ra.assertIf(isCT, ra.matches(values, contentTypeTSTInfo), 1)
		ra.assertIf(isMD, ra.matches(values, messageDigestValue), 1)
		ctCount = api.Add(ctCount, isCT)
		mdCount = api.Add(mdCount, isMD)
		mdPos = api.Add(mdPos, api.Mul(isMD, api.Add(values, len(messageDigestValue))))
		cur = api.Select(active, aEnd, cur)
	}
	api.AssertIsEqual(cur, end) // no more attributes than the gadget walks
	api.AssertIsEqual(ctCount, 1)
	api.AssertIsEqual(mdCount, 1)

	// ---- TSTInfo ------------------------------------------------------------
	rt, tst := newByteReader(api, bapi, tk.TSTInfo)
	rt.timeTables()
	rt.pos.AssertIsLessEq(tk.TSTInfoLen, s.MaxTSTInfo)
	api.AssertIsEqual(rt.at(0), 0x30)
	tLen, tHL := rt.header(0, 1)
	tEnd := api.Add(tHL, tLen)
	api.AssertIsEqual(tEnd, tk.TSTInfoLen)
	p := frontend.Variable(tHL)
	api.AssertIsEqual(rt.matches(p, tstVersion), 1)
	p = rt.skip(api.Add(p, len(tstVersion)), 0x06) // policy
	api.AssertIsEqual(rt.at(p), 0x30)              // messageImprint
	miLen, miHL := rt.header(p, 1)
	mi := api.Add(p, miHL)
	plain, withNull := rt.matches(mi, sha256AlgID), rt.matches(mi, sha256AlgIDNull)
	api.AssertIsEqual(api.Add(plain, withNull), 1)
	octet := api.Add(mi, len(sha256AlgID), api.Mul(withNull, 2))
	api.AssertIsEqual(rt.matches(octet, []byte{0x04, 0x20}), 1)
	p = api.Add(p, miHL, miLen)
	api.AssertIsEqual(api.Add(octet, 34), p) // the imprint is exactly the algorithm and the digest
	imprint := make([]frontend.Variable, 32)
	for i := range imprint {
		imprint[i] = rt.at(api.Add(octet, 2, i))
	}
	p = rt.skip(p, 0x02) // serialNumber
	// genTime: GeneralizedTime "20YYMMDDHHMMSSZ"
	api.AssertIsEqual(rt.matches(p, []byte{0x18, 0x0f, '2', '0'}), 1)
	genTime := rt.utcTime(api.Add(p, 4))
	rt.assertDayInMonth(api.Add(p, 4))
	api.AssertIsEqual(rt.at(api.Add(p, 16)), 'Z')
	rt.pos.AssertIsLessEq(api.Add(p, 17), tEnd) // genTime lies within TSTInfo

	// messageDigest = SHA-256(TSTInfo)
	h, err := sha2.New(api)
	if err != nil {
		return nil, nil, err
	}
	h.Write(tst)
	tstDigest := h.FixedLengthSum(tk.TSTInfoLen)
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(bapi.Value(tstDigest[i]), ra.at(api.Add(mdPos, i)))
	}

	// ---- The TSA certificate's TBS ------------------------------------------
	rc, tbs := newByteReader(api, bapi, tk.TSATBS)
	rc.timeTables()
	api.AssertIsEqual(rc.at(0), 0x30)
	api.AssertIsEqual(rc.at(1), 0x82)
	tbsLen := api.Add(4, api.Mul(rc.at(2), 256), rc.at(3))
	rc.pos.AssertIsLessEq(tbsLen, s.MaxTSATBS)
	for i, b := range tbsVersion {
		api.AssertIsEqual(rc.at(4+i), b)
	}
	q := frontend.Variable(4 + len(tbsVersion))
	q = rc.skip(q, 0x02) // serialNumber
	q = rc.skip(q, 0x30) // signature algorithm
	q = rc.skip(q, 0x30) // issuer
	notBefore, notAfter, err := rc.validity(q)
	if err != nil {
		return nil, nil, err
	}
	q = api.Add(q, 32)
	q = rc.skip(q, 0x30) // subject
	tsaKey, err := rc.p256Key(bapi, q)
	if err != nil {
		return nil, nil, err
	}
	q = api.Add(q, spkiLen)
	ekuPos, ekuLen, ekuCritical, bcPos, bcLen, bcPresent := rc.tsaExtensions(q, tbsLen, s.MaxTSAExtensions)
	api.AssertIsEqual(ekuCritical, 1)
	api.AssertIsEqual(ekuLen, len(ekuTimeStampingOnly))
	api.AssertIsEqual(rc.matches(ekuPos, ekuTimeStampingOnly), 1)
	rc.notCA(bcPos, bcLen, bcPresent)
	timeCmp := cmp.NewBoundedComparator(api, big.NewInt(1<<34), false)
	timeCmp.AssertIsLessEq(notBefore, genTime)
	timeCmp.AssertIsLessEq(genTime, notAfter)

	// The TSA CA signed the TBS (ECDSA P-384, SHA-384).
	tbsDigest, err := sum384(api, tbs, tbsLen)
	if err != nil {
		return nil, nil, err
	}
	caMsg, err := digestToScalar[emulated.P384Fr](api, tbsDigest)
	if err != nil {
		return nil, nil, err
	}
	tsaCAKey.Verify(api, sw_emulated.GetCurveParams[emulated.P384Fp](), caMsg, &tk.TSACASig)

	// ---- The TSA's signature (ES256) over the signed attributes -------------
	h2, err := sha2.New(api)
	if err != nil {
		return nil, nil, err
	}
	h2.Write(attrs)
	attrsDigest := h2.FixedLengthSum(tk.SignedAttrsLen)
	msg, err := digestToScalar[emulated.P256Fr](api, attrsDigest)
	if err != nil {
		return nil, nil, err
	}
	sigBytes := make([]uints.U8, signatureLen)
	for i, v := range tk.TSASig {
		sigBytes[i] = bapi.ValueOf(v)
	}
	fr, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		return nil, nil, err
	}
	rS, sS := bytesToElement(bapi, fr, sigBytes[:32]), bytesToElement(bapi, fr, sigBytes[32:])
	fr.AssertIsInRange(rS)
	fr.AssertIsInRange(sS)
	tsaKey.Verify(api, sw_emulated.GetCurveParams[emulated.P256Fp](), msg, &ecdsa.Signature[emulated.P256Fr]{R: *rS, S: *sS})

	return genTime, imprint, nil
}

// tsaExtensions walks the [3] extensions at p, which must end the TBS, as
// extensions does, and also returns whether the (single) extended key usage
// extension is critical. (A separate function: changing extensions would
// change the existing statements' constraint systems, and so their keys.)
func (r *reader) tsaExtensions(p, tbsEnd frontend.Variable, maxExtensions int) (ekuPos, ekuLen, ekuCritical, bcPos, bcLen, bcPresent frontend.Variable) {
	api := r.api
	api.AssertIsEqual(r.at(p), 0xa3)
	l, hl := r.header(p, 1)
	api.AssertIsEqual(api.Add(p, hl, l), tbsEnd)
	seq := api.Add(p, hl)
	api.AssertIsEqual(r.at(seq), 0x30)
	l, hl = r.header(seq, 1)
	cur := api.Add(seq, hl)
	end := api.Add(cur, l)
	api.AssertIsEqual(end, tbsEnd)

	ekuCount, bcCount := frontend.Variable(0), frontend.Variable(0)
	ekuPos, ekuLen, ekuCritical, bcPos, bcLen = 0, 0, 0, 0, 0
	for k := 0; k < maxExtensions; k++ {
		active := r.pos.IsLess(cur, end)
		// Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
		r.assertIf(active, r.at(cur), 0x30)
		extLen, extHL := r.header(cur, active)
		extEnd := api.Add(cur, extHL, extLen)
		oid := api.Add(cur, extHL)
		r.assertIf(active, r.at(oid), 0x06)
		oidLen := r.at(api.Add(oid, 1))
		r.assertIf(active, r.small.IsLess(oidLen, 128), 1)
		q := api.Add(oid, 2, oidLen)
		hasBoolean := api.Mul(active, r.isEq(r.at(q), 0x01))
		r.assertIf(hasBoolean, r.at(api.Add(q, 1)), 0x01)
		// DER encodes TRUE as FF; FALSE is the default and must be omitted.
		r.assertIf(hasBoolean, r.at(api.Add(q, 2)), 0xff)
		value := api.Add(q, api.Mul(3, hasBoolean))
		r.assertIf(active, r.at(value), 0x04)
		valueLen, valueHL := r.header(value, active)
		valuePos := api.Add(value, valueHL)
		r.assertIf(active, api.Add(valuePos, valueLen), extEnd)

		isEKU := api.Mul(active, r.isEq(oidLen, 3), r.matches(api.Add(oid, 2), oidExtKeyUsage))
		isBC := api.Mul(active, r.isEq(oidLen, 3), r.matches(api.Add(oid, 2), oidBasicConstraints))
		ekuCount = api.Add(ekuCount, isEKU)
		bcCount = api.Add(bcCount, isBC)
		ekuPos = api.Add(ekuPos, api.Mul(isEKU, valuePos))
		ekuLen = api.Add(ekuLen, api.Mul(isEKU, valueLen))
		ekuCritical = api.Add(ekuCritical, api.Mul(isEKU, hasBoolean))
		bcPos = api.Add(bcPos, api.Mul(isBC, valuePos))
		bcLen = api.Add(bcLen, api.Mul(isBC, valueLen))

		cur = api.Select(active, extEnd, cur)
	}
	api.AssertIsEqual(cur, end) // no more extensions than the circuit walks
	api.AssertIsEqual(ekuCount, 1)
	api.AssertIsEqual(api.Mul(bcCount, api.Sub(bcCount, 1)), 0) // at most one
	return ekuPos, ekuLen, ekuCritical, bcPos, bcLen, bcCount
}

// TokenCircuit is the gadget alone, for tests and its cost: public the TSA
// CA's key, the window [T1, T2), and the imprint; private the token.
type TokenCircuit struct {
	Sizes TokenSizes `gnark:"-"`

	TSACAKey ecdsa.PublicKey[emulated.P384Fp, emulated.P384Fr] `gnark:",public"`
	T1       frontend.Variable                                 `gnark:",public"`
	T2       frontend.Variable                                 `gnark:",public"`
	Imprint  [2]frontend.Variable                              `gnark:",public"`

	Token TokenInputs
}

// NewTokenCircuit allocates a TokenCircuit (or an assignment).
func NewTokenCircuit(s TokenSizes) *TokenCircuit {
	return &TokenCircuit{Sizes: s, Token: NewTokenInputs(s)}
}

func (c *TokenCircuit) Define(api frontend.API) error {
	genTime, imprint, err := verifyToken(api, c.Sizes, &c.Token, &c.TSACAKey)
	if err != nil {
		return err
	}
	assertInWindow(api, genTime, c.T1, c.T2)
	for half := 0; half < 2; half++ {
		v := frontend.Variable(0)
		for _, b := range imprint[16*half : 16*half+16] {
			v = api.Add(api.Mul(v, 256), b)
		}
		api.AssertIsEqual(v, c.Imprint[half])
	}
	return nil
}

// timeBits bounds the window's public endpoints: Unix seconds in [0, 2^34),
// up to the year 2514. genTime is below 2^32 by construction (2000-2049).
const timeBits = 34

// assertInWindow asserts t1 <= t < t2, a half-open window
// (HIDING-THE-TIME-STAMP.md, T3). The endpoints are public field elements: each
// is first constrained to [0, 2^timeBits), so that the comparisons are between
// integers (a field element such as p - 1 would otherwise act as -1).
func assertInWindow(api frontend.API, t, t1, t2 frontend.Variable) {
	bits.ToBinary(api, t1, bits.WithNbDigits(timeBits))
	bits.ToBinary(api, t2, bits.WithNbDigits(timeBits))
	c := cmp.NewBoundedComparator(api, big.NewInt(1<<timeBits), false)
	c.AssertIsLessEq(t1, t)
	c.AssertIsLessEq(api.Add(t, 1), t2)
}

// assertDayInMonth asserts that the day of the YYMMDD digits at p exists in
// its month (28 to 31 days, February 29 in leap years). The shared utcTime
// bounds the day to 1-31 only; the check is the token path's own, so that the
// existing statements' constraint systems, and keys, are unchanged. utcTime
// has already range-checked the digits and bounded the year and month.
func (r *reader) assertDayInMonth(p frontend.Variable) {
	api := r.api
	digit := func(i int) frontend.Variable { return api.Sub(r.at(api.Add(p, i)), '0') }
	two := func(i int) frontend.Variable { return api.Add(api.Mul(digit(i), 10), digit(i+1)) }
	year, month, day := two(0), two(2), two(4)
	monthDays := logderivlookup.New(api)
	for _, d := range []int{0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31} {
		monthDays.Insert(d)
	}
	february := r.isEq(month, 2)
	last := api.Add(monthDays.Lookup(month)[0], api.Mul(february, r.leapYear.Lookup(year)[0]))
	r.small.AssertIsLessEq(day, last)
}
