// Package statement is the third-party anonymization statement (roadmap E2b;
// THIRD-PARTY-STATEMENT.md) as a gnark circuit.
//
// Public: the claim (packed, with its length), the issuing CA's P-384 key, the
// time t, and the time stamp's message imprint. Private: the claim
// signature's Sig_structure (which holds the protected header, and in it the
// signer certificate), the claim signature, and the CA's signature over the
// signer certificate's TBS. The circuit proves:
//
//   - the Sig_structure is ["Signature1", P, h”, claim] for the public claim;
//   - P is {1: ES256, 33: [signer certificate, ...]};
//   - the CA's key signed the certificate's TBS (ECDSA P-384, SHA-384);
//   - walking the TBS's DER structure: it is a v3 certificate whose subject key
//     is P-256, whose validity contains t, which has exactly one extended key
//     usage extension, including C2PA claim signing, and which is not a CA
//     (basic constraints absent or cA false);
//   - that key signed the Sig_structure (ES256);
//   - the imprint is SHA-256(["CounterSignature", P, h”, bstr(bstr(r || s))]),
//     binding a sigTst2 time stamp to the original signature.
//
// The verifier checks off-circuit that the CA chains to the trust list at t,
// that the time-stamp token is valid and trusted and attests t and the
// imprint, and that the claim is the asset's (with its hard binding).
package statement

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

// Circuit is the statement for given Sizes; build it with NewCircuit.
type Circuit struct {
	Sizes Sizes `gnark:"-"`

	// Public inputs, all derived by the verifier from the anonymized asset.
	Claim    []frontend.Variable                               `gnark:",public"` // 31 bytes per element, big-endian, zero-padded
	ClaimLen frontend.Variable                                 `gnark:",public"`
	CAKey    ecdsa.PublicKey[emulated.P384Fp, emulated.P384Fr] `gnark:",public"`
	Time     frontend.Variable                                 `gnark:",public"` // Unix seconds
	Imprint  [2]frontend.Variable                              `gnark:",public"` // SHA-256, two 16-byte halves

	// Private inputs.
	SigStructure []frontend.Variable // the Sig_structure's bytes, zero-padded
	ProtectedLen frontend.Variable
	ClaimSig     []frontend.Variable // r || s, 64 bytes
	CASig        ecdsa.Signature[emulated.P384Fr]
}

// NewCircuit allocates a circuit (or an assignment) for the given sizes.
func NewCircuit(s Sizes) *Circuit {
	return &Circuit{
		Sizes:        s,
		Claim:        make([]frontend.Variable, s.claimElements()),
		SigStructure: make([]frontend.Variable, s.sigStructureLen()),
		ClaimSig:     make([]frontend.Variable, signatureLen),
	}
}

// reader indexes the Sig_structure for lookups at positions computed in the
// circuit, and provides the DER and comparison helpers the walk needs.
type reader struct {
	api   frontend.API
	table logderivlookup.Table
	pos   *cmp.BoundedComparator // positions and lengths, < 2^16
	small *cmp.BoundedComparator // byte values
	// UTCTime conversion tables, indexed by the two-digit year and the month.
	yearStart, leapYear, monthStart logderivlookup.Table
}

// at is the byte at position i. A position outside the table makes the
// constraint system unsatisfiable.
func (r *reader) at(i frontend.Variable) frontend.Variable { return r.table.Lookup(i)[0] }

func (r *reader) isEq(a, b frontend.Variable) frontend.Variable { return r.api.IsZero(r.api.Sub(a, b)) }

// assertIf asserts a == b when cond is 1.
func (r *reader) assertIf(cond, a, b frontend.Variable) {
	r.api.AssertIsEqual(r.api.Mul(cond, r.api.Sub(a, b)), 0)
}

// matches is 1 when the bytes at p... equal want.
func (r *reader) matches(p frontend.Variable, want []byte) frontend.Variable {
	all := frontend.Variable(1)
	for i, b := range want {
		all = r.api.Mul(all, r.isEq(r.at(r.api.Add(p, i)), b))
	}
	return all
}

// header decodes the DER tag-length header at p when active: the length in
// short form, or in long form with one or two length bytes (81 xx, 82 xx xx).
// It returns the content length and the header length.
func (r *reader) header(p, active frontend.Variable) (length, headerLen frontend.Variable) {
	api := r.api
	b1, b2, b3 := r.at(api.Add(p, 1)), r.at(api.Add(p, 2)), r.at(api.Add(p, 3))
	short := r.small.IsLess(b1, 128)
	long1 := r.isEq(b1, 0x81)
	long2 := r.isEq(b1, 0x82)
	r.assertIf(active, api.Add(short, long1, long2), 1)
	length = api.Add(api.Mul(short, b1), api.Mul(long1, b2), api.Mul(long2, api.Add(api.Mul(b2, 256), b3)))
	headerLen = api.Add(2, long1, api.Mul(2, long2))
	return
}

// skip asserts the DER element at p has the given tag and returns the position after it.
func (r *reader) skip(p frontend.Variable, tag byte) frontend.Variable {
	r.api.AssertIsEqual(r.at(p), tag)
	length, headerLen := r.header(p, 1)
	return r.api.Add(p, headerLen, length)
}

func (c *Circuit) Define(api frontend.API) error {
	s := c.Sizes
	if len(c.SigStructure) != s.sigStructureLen() || len(c.Claim) != s.claimElements() || len(c.ClaimSig) != signatureLen {
		return fmt.Errorf("circuit not allocated for its sizes")
	}
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	r := &reader{
		api:   api,
		table: logderivlookup.New(api),
		pos:   cmp.NewBoundedComparator(api, big.NewInt(1<<16), false),
		small: cmp.NewBoundedComparator(api, big.NewInt(1<<9), false),
	}
	r.timeTables()
	// Every Sig_structure byte is range-checked, then indexed for lookups.
	sig := make([]uints.U8, len(c.SigStructure))
	for i, v := range c.SigStructure {
		sig[i] = bapi.ValueOf(v)
		r.table.Insert(v)
	}
	S := c.SigStructure

	// ---- Sig_structure prefix and the protected header's layout ----------
	for i, b := range sigContext {
		api.AssertIsEqual(S[i], b)
	}
	api.AssertIsEqual(S[sigPrefixLen], 0x59)
	pLen := c.ProtectedLen
	api.AssertIsEqual(api.Add(api.Mul(S[sigPrefixLen+1], 256), S[sigPrefixLen+2]), pLen)
	r.pos.AssertIsLessEq(256, pLen)
	r.pos.AssertIsLessEq(pLen, s.MaxProtected)

	for i, b := range protectedStart {
		api.AssertIsEqual(S[protectedOffset+i], b)
	}
	// x5chain: an array of 1 to 23 certificates (bounds checked on the raw
	// byte on both sides: a subtracted value could wrap around).
	r.small.AssertIsLessEq(0x81, S[protectedOffset+5])
	r.small.AssertIsLessEq(S[protectedOffset+5], 0x97)
	api.AssertIsEqual(S[protectedOffset+6], 0x59) // the first is a byte string of 256 bytes or more
	leafLen := api.Add(api.Mul(S[protectedOffset+7], 256), S[protectedOffset+8])
	api.AssertIsEqual(S[leafOffset], 0x30)
	api.AssertIsEqual(S[leafOffset+1], 0x82)
	api.AssertIsEqual(leafLen, api.Add(4, api.Mul(S[leafOffset+2], 256), S[leafOffset+3]))
	api.AssertIsEqual(S[tbsOffset], 0x30)
	api.AssertIsEqual(S[tbsOffset+1], 0x82)
	tbsLen := api.Add(4, api.Mul(S[tbsOffset+2], 256), S[tbsOffset+3])
	tbsEnd := api.Add(tbsOffset, tbsLen)
	r.pos.AssertIsLessEq(tbsLen, s.MaxTBS)
	r.pos.AssertIsLessEq(tbsEnd, api.Add(leafOffset, leafLen))                         // the TBS lies in the certificate,
	r.pos.AssertIsLessEq(api.Add(leafOffset, leafLen), api.Add(protectedOffset, pLen)) // which lies in P

	// ---- The CA's signature over the TBS (ECDSA P-384, SHA-384) ----------
	tbsDigest, err := sum384(api, sig[tbsOffset:tbsOffset+s.MaxTBS], tbsLen)
	if err != nil {
		return err
	}
	caMsg, err := digestToScalar[emulated.P384Fr](api, tbsDigest)
	if err != nil {
		return err
	}
	c.CAKey.Verify(api, sw_emulated.GetCurveParams[emulated.P384Fp](), caMsg, &c.CASig)

	// ---- Walk the TBS ----------------------------------------------------
	for i, b := range tbsVersion {
		api.AssertIsEqual(S[tbsContentOffset+i], b)
	}
	p := frontend.Variable(tbsContentOffset + len(tbsVersion))
	p = r.skip(p, 0x02) // serialNumber
	p = r.skip(p, 0x30) // signature algorithm
	p = r.skip(p, 0x30) // issuer
	notBefore, notAfter, err := r.validity(p)
	if err != nil {
		return err
	}
	p = api.Add(p, 32)
	p = r.skip(p, 0x30) // subject
	leafKey, err := r.p256Key(bapi, p)
	if err != nil {
		return err
	}
	p = api.Add(p, spkiLen)
	ekuPos, ekuLen, bcPos, bcLen, bcPresent := r.extensions(p, tbsEnd, s.MaxExtensions)
	r.claimSigningEKU(ekuPos, ekuLen, s.MaxEKUs)
	r.notCA(bcPos, bcLen, bcPresent)

	timeCmp := cmp.NewBoundedComparator(api, big.NewInt(1<<34), false)
	timeCmp.AssertIsLessEq(notBefore, c.Time)
	timeCmp.AssertIsLessEq(c.Time, notAfter)

	// ---- The claim, after P ------------------------------------------------
	afterP := api.Add(protectedOffset, pLen)
	api.AssertIsEqual(r.at(afterP), 0x40) // external_aad = h''
	h := api.Add(afterP, 1)
	claimLen := c.ClaimLen
	r.pos.AssertIsLessEq(24, claimLen)
	r.pos.AssertIsLessEq(claimLen, s.MaxClaim)
	short := r.pos.IsLess(claimLen, 256)
	h0, h1, h2 := r.at(h), r.at(api.Add(h, 1)), r.at(api.Add(h, 2))
	r.assertIf(short, h0, 0x58)
	r.assertIf(short, h1, claimLen)
	long := api.Sub(1, short)
	r.assertIf(long, h0, 0x59)
	r.assertIf(long, api.Add(api.Mul(h1, 256), h2), claimLen)
	claimOffset := api.Add(h, 2, long)
	claim, err := unpackClaim(api, c.Claim, s.MaxClaim)
	if err != nil {
		return err
	}
	for j := 0; j < s.MaxClaim; j++ {
		in := r.pos.IsLess(j, claimLen)
		r.assertIf(in, r.at(api.Add(claimOffset, j)), claim[j])
		api.AssertIsEqual(api.Mul(api.Sub(1, in), claim[j]), 0) // canonical packing: zeros past the end
	}

	// ---- The claim signature (ES256 over the Sig_structure) ---------------
	hasher, err := sha2.New(api)
	if err != nil {
		return err
	}
	hasher.Write(sig)
	sigDigest := hasher.FixedLengthSum(api.Add(claimOffset, claimLen))
	sigMsg, err := digestToScalar[emulated.P256Fr](api, sigDigest)
	if err != nil {
		return err
	}
	sigBytes := make([]uints.U8, signatureLen)
	for i, v := range c.ClaimSig {
		sigBytes[i] = bapi.ValueOf(v)
	}
	fr, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		return err
	}
	rS, sS := bytesToElement(bapi, fr, sigBytes[:32]), bytesToElement(bapi, fr, sigBytes[32:])
	fr.AssertIsInRange(rS)
	fr.AssertIsInRange(sS)
	leafKey.Verify(api, sw_emulated.GetCurveParams[emulated.P256Fp](), sigMsg, &ecdsa.Signature[emulated.P256Fr]{R: *rS, S: *sS})

	// ---- The time stamp's imprint over the countersignature structure -----
	return c.imprint(api, bapi, r, sig, pLen)
}

// validity reads the Validity at p (two UTCTimes, YYMMDDHHMMSSZ) and returns
// notBefore and notAfter as Unix seconds.
func (r *reader) validity(p frontend.Variable) (frontend.Variable, frontend.Variable, error) {
	fixed := map[int]byte{0: 0x30, 1: 0x1e, 2: 0x17, 3: 0x0d, 16: 0x5a, 17: 0x17, 18: 0x0d, 31: 0x5a}
	for off, b := range fixed {
		r.api.AssertIsEqual(r.at(r.api.Add(p, off)), b)
	}
	notBefore := r.utcTime(r.api.Add(p, 4))
	notAfter := r.utcTime(r.api.Add(p, 19))
	return notBefore, notAfter, nil
}

// p256Key checks the P-256 SubjectPublicKeyInfo at p and returns its key.
func (r *reader) p256Key(bapi *uints.Bytes, p frontend.Variable) (*ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr], error) {
	for i, b := range p256SPKIPrefix {
		r.api.AssertIsEqual(r.at(r.api.Add(p, i)), b)
	}
	key := make([]uints.U8, 64)
	for i := range key {
		key[i] = bapi.ValueOf(r.at(r.api.Add(p, len(p256SPKIPrefix)+i)))
	}
	fp, err := emulated.NewField[emulated.P256Fp](r.api)
	if err != nil {
		return nil, err
	}
	pub := ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{X: *bytesToElement(bapi, fp, key[:32]), Y: *bytesToElement(bapi, fp, key[32:])}
	curve, err := sw_emulated.New[emulated.P256Fp, emulated.P256Fr](r.api, sw_emulated.GetCurveParams[emulated.P256Fp]())
	if err != nil {
		return nil, err
	}
	point := sw_emulated.AffinePoint[emulated.P256Fp](pub)
	curve.AssertIsOnCurve(&point)
	return &pub, nil
}

// extensions walks the [3] extensions at p, which must end the TBS, and
// returns where the (single) extended key usage value and the basic
// constraints value (if any) lie, with their lengths.
func (r *reader) extensions(p, tbsEnd frontend.Variable, maxExtensions int) (ekuPos, ekuLen, bcPos, bcLen, bcPresent frontend.Variable) {
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
	ekuPos, ekuLen, bcPos, bcLen = 0, 0, 0, 0
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
		critical := api.Mul(active, r.isEq(r.at(q), 0x01))
		r.assertIf(critical, r.at(api.Add(q, 1)), 0x01)
		value := api.Add(q, api.Mul(3, critical))
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
		bcPos = api.Add(bcPos, api.Mul(isBC, valuePos))
		bcLen = api.Add(bcLen, api.Mul(isBC, valueLen))

		cur = api.Select(active, extEnd, cur)
	}
	api.AssertIsEqual(cur, end) // no more extensions than the circuit walks
	api.AssertIsEqual(ekuCount, 1)
	api.AssertIsEqual(api.Mul(bcCount, api.Sub(bcCount, 1)), 0) // at most one
	return ekuPos, ekuLen, bcPos, bcLen, bcCount
}

// claimSigningEKU asserts the extended key usage value at pos is a sequence of
// purposes that includes C2PA claim signing.
func (r *reader) claimSigningEKU(pos, length frontend.Variable, maxEKUs int) {
	api := r.api
	api.AssertIsEqual(r.at(pos), 0x30)
	l, hl := r.header(pos, 1)
	api.AssertIsEqual(api.Add(hl, l), length)
	cur := api.Add(pos, hl)
	end := api.Add(cur, l)
	found := frontend.Variable(0)
	for m := 0; m < maxEKUs; m++ {
		active := r.pos.IsLess(cur, end)
		r.assertIf(active, r.at(cur), 0x06)
		oidLen := r.at(api.Add(cur, 1))
		r.assertIf(active, r.small.IsLess(oidLen, 128), 1)
		match := api.Mul(active, r.isEq(oidLen, len(oidClaimSigning)), r.matches(api.Add(cur, 2), oidClaimSigning))
		found = api.Add(found, match)
		cur = api.Select(active, api.Add(cur, 2, oidLen), cur)
	}
	api.AssertIsEqual(cur, end) // no more purposes than the circuit walks
	api.AssertIsEqual(api.IsZero(found), 0)
}

// notCA asserts that basic constraints, if present at pos (its extension
// value, length bytes long), does not set cA.
//
//	BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
//
// The sequence is decoded like every other field (short or long-form
// length) and must fill the extension value. Its content is empty (not a
// CA), starts with an INTEGER (pathLenConstraint only: not a CA), or starts
// with a BOOLEAN of length 1, which must be false. Anything else is rejected:
// throughout the walk, an encoding the circuit does not recognize must fail
// the check, never pass it.
func (r *reader) notCA(pos, length, present frontend.Variable) {
	api := r.api
	r.assertIf(present, r.at(pos), 0x30)
	seqLen, seqHL := r.header(pos, present)
	r.assertIf(present, api.Add(seqHL, seqLen), length)
	content := api.Add(pos, seqHL)
	nonEmpty := api.Mul(present, api.Sub(1, api.IsZero(seqLen)))
	tag := r.at(content)
	isBoolean, isInteger := r.isEq(tag, 0x01), r.isEq(tag, 0x02)
	r.assertIf(nonEmpty, api.Add(isBoolean, isInteger), 1)
	boolean := api.Mul(nonEmpty, isBoolean)
	r.assertIf(boolean, r.pos.IsLess(2, seqLen), 1)   // the BOOLEAN lies within the sequence
	r.assertIf(boolean, r.at(api.Add(content, 1)), 1) // of length 1
	isCA := api.Mul(boolean, api.Sub(1, api.IsZero(r.at(api.Add(content, 2)))))
	api.AssertIsEqual(isCA, 0)
}

// imprint asserts the public imprint is the SHA-256 of the countersignature
// structure ["CounterSignature", P, h”, bstr(bstr(r || s))], built from the
// Sig_structure's P and the claim signature.
func (c *Circuit) imprint(api frontend.API, bapi *uints.Bytes, r *reader, sig []uints.U8, pLen frontend.Variable) error {
	s := c.Sizes
	cs := make([]uints.U8, s.countersignatureLen())
	for i, b := range csContext {
		cs[i] = uints.NewU8(b)
	}
	copy(cs[csPrefixLen:csProtectedOffset], sig[sigPrefixLen:protectedOffset]) // 59 Lp Lp

	tail := logderivlookup.New(api)
	for _, b := range []byte{0x40, 0x58, 0x42, 0x58, 0x40} {
		tail.Insert(b)
	}
	for _, v := range c.ClaimSig {
		tail.Insert(v)
	}
	tail.Insert(0) // index csTailLen: past the end
	for i := 0; i < s.MaxProtected+csTailLen; i++ {
		inP := r.pos.IsLess(i, pLen)
		offset := api.Sub(i, pLen)
		inTail := api.Mul(api.Sub(1, inP), r.pos.IsLess(api.Select(inP, 0, offset), csTailLen))
		tailByte := bapi.ValueOf(tail.Lookup(api.Select(inTail, offset, csTailLen))[0])
		var pByte uints.U8
		pByte = sig[protectedOffset+i] // in range: the Sig_structure holds at least csTailLen bytes past P
		cs[csProtectedOffset+i] = bapi.Select(inP, pByte, tailByte)
	}
	hasher, err := sha2.New(api)
	if err != nil {
		return err
	}
	hasher.Write(cs)
	digest := hasher.FixedLengthSum(api.Add(csProtectedOffset, pLen, csTailLen))
	for half := 0; half < 2; half++ {
		v := frontend.Variable(0)
		for _, b := range digest[16*half : 16*half+16] {
			v = api.Add(api.Mul(v, 256), bapi.Value(b))
		}
		api.AssertIsEqual(v, c.Imprint[half])
	}
	return nil
}

// unpackClaim splits the public claim elements into maxClaim bytes; each
// element holds 31 bytes, big-endian.
func unpackClaim(api frontend.API, elements []frontend.Variable, maxClaim int) ([]frontend.Variable, error) {
	var out []frontend.Variable
	for _, e := range elements {
		b := bits.ToBinary(api, e, bits.WithNbDigits(8*claimChunk))
		for k := claimChunk - 1; k >= 0; k-- {
			out = append(out, bits.FromBinary(api, b[8*k:8*k+8]))
		}
	}
	// Bytes past maxClaim (padding of the last element) must be zero.
	for _, v := range out[maxClaim:] {
		api.AssertIsEqual(v, 0)
	}
	return out[:maxClaim], nil
}

// bytesToElement interprets big-endian bytes as an emulated field element.
func bytesToElement[F emulated.FieldParams](bapi *uints.Bytes, f *emulated.Field[F], b []uints.U8) *emulated.Element[F] {
	var bs []frontend.Variable // least significant first
	for i := len(b) - 1; i >= 0; i-- {
		bs = append(bs, bapi.ToBits(b[i])...)
	}
	return f.FromBits(bs...)
}

// digestToScalar interprets a big-endian digest as an ECDSA message scalar.
// The digests used (SHA-256 for P-256, SHA-384 for P-384) are as long as the
// group order, so no truncation applies; the emulated arithmetic reduces.
func digestToScalar[Fr emulated.FieldParams](api frontend.API, digest []uints.U8) (*emulated.Element[Fr], error) {
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return nil, err
	}
	fr, err := emulated.NewField[Fr](api)
	if err != nil {
		return nil, err
	}
	return bytesToElement(bapi, fr, digest), nil
}

// timeTables builds the UTCTime lookup tables: for two-digit years 00-49
// (2000-2049; RFC 5280 maps 50-99 to the 1900s, which are refused), the days
// from 1970-01-01 to January 1 and whether the year is a leap year; for months
// 1-12, the days before the month in a common year.
func (r *reader) timeTables() {
	r.yearStart, r.leapYear, r.monthStart = logderivlookup.New(r.api), logderivlookup.New(r.api), logderivlookup.New(r.api)
	days := 0
	for y := 1970; y < 2050; y++ {
		leap := y%4 == 0 && (y%100 != 0 || y%400 == 0)
		if y >= 2000 {
			r.yearStart.Insert(days)
			if leap {
				r.leapYear.Insert(1)
			} else {
				r.leapYear.Insert(0)
			}
		}
		days += 365
		if leap {
			days++
		}
	}
	cumulative := 0
	r.monthStart.Insert(0) // month 0 does not exist
	for _, d := range []int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31} {
		r.monthStart.Insert(cumulative)
		cumulative += d
	}
}

// utcTime converts the 12 digits YYMMDDHHMMSS at p to Unix seconds. Each digit
// and field is bounded on both sides; day-of-month is not checked against the
// month's length (the bytes are signed by the CA).
func (r *reader) utcTime(p frontend.Variable) frontend.Variable {
	api := r.api
	var d [12]frontend.Variable
	for i := range d {
		b := r.at(api.Add(p, i))
		r.small.AssertIsLessEq('0', b)
		r.small.AssertIsLessEq(b, '9')
		d[i] = api.Sub(b, '0')
	}
	two := func(i int) frontend.Variable { return api.Add(api.Mul(d[i], 10), d[i+1]) }
	year, month, day, hour, minute, second := two(0), two(2), two(4), two(6), two(8), two(10)
	r.small.AssertIsLess(year, 50)
	r.small.AssertIsLessEq(1, month)
	r.small.AssertIsLessEq(month, 12)
	r.small.AssertIsLessEq(1, day)
	r.small.AssertIsLessEq(day, 31)
	r.small.AssertIsLess(hour, 24)
	r.small.AssertIsLess(minute, 60)
	r.small.AssertIsLess(second, 60)
	afterFebruary := r.small.IsLess(2, month)
	days := api.Add(
		r.yearStart.Lookup(year)[0],
		r.monthStart.Lookup(month)[0],
		api.Mul(r.leapYear.Lookup(year)[0], afterFebruary),
		api.Sub(day, 1),
	)
	return api.Add(api.Mul(days, 86400), api.Mul(hour, 3600), api.Mul(minute, 60), second)
}
