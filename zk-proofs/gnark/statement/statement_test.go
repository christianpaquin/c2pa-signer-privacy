package statement

import (
	"crypto/sha512"
	"encoding/asn1"
	"math/big"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

// Smaller limits than the defaults keep the tests fast; the fixtures fit.
var testSizes = Sizes{MaxProtected: 1536, MaxClaim: 512, MaxTBS: 768, MaxExtensions: 8, MaxEKUs: 4}

// compiledCircuit is the statement compiled at test sizes for one curve, once.
type compiledCircuit struct {
	once sync.Once
	ccs  constraint.ConstraintSystem
	err  error
}

var compiled = map[ecc.ID]*compiledCircuit{ecc.BN254: {}, ecc.BLS12_381: {}}

func testCircuitOn(t *testing.T, curve ecc.ID) constraint.ConstraintSystem {
	t.Helper()
	c := compiled[curve]
	c.once.Do(func() {
		c.ccs, c.err = frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, NewCircuit(testSizes))
	})
	if c.err != nil {
		t.Fatal(c.err)
	}
	return c.ccs
}

func testCircuit(t *testing.T) constraint.ConstraintSystem { return testCircuitOn(t, ecc.BN254) }

// solvedOn reports whether the statement compiled for the curve accepts the assignment.
func solvedOn(t *testing.T, curve ecc.ID, c *Circuit) bool {
	t.Helper()
	w, err := frontend.NewWitness(c, curve.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return testCircuitOn(t, curve).IsSolved(w) == nil
}

// forEachCurve runs a statement test on BN254 and on BLS12-381 (roadmap E7):
// the circuit is the same, compiled for each curve's scalar field, so every
// rejection guarantee is checked on both.
func forEachCurve(t *testing.T, test func(t *testing.T, curve ecc.ID)) {
	for _, c := range []struct {
		name  string
		curve ecc.ID
	}{{"bn254", ecc.BN254}, {"bls12-381", ecc.BLS12_381}} {
		t.Run(c.name, func(t *testing.T) { test(t, c.curve) })
	}
}

func assign(t *testing.T, in Inputs) *Circuit {
	t.Helper()
	c, err := Assign(in, testSizes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestValidStatementIsAccepted(t *testing.T) {
	forEachCurve(t, func(t *testing.T, curve ecc.ID) {
		for _, claimLen := range []int{377, 200} { // both claim header forms (59 / 58)
			f := newFixture(t, fixtureOptions{claimLen: claimLen})
			if !solvedOn(t, curve, assign(t, f.in)) {
				t.Fatalf("valid statement rejected (claim %d bytes)", claimLen)
			}
		}
		t.Logf("%d constraints at test sizes", testCircuitOn(t, curve).GetNbConstraints())
	})
}

func TestTamperedPublicInputsAreRejected(t *testing.T) {
	forEachCurve(t, func(t *testing.T, curve ecc.ID) {
		f := newFixture(t, fixtureOptions{})
		cases := map[string]func(in *Inputs){
			"claim byte":            func(in *Inputs) { in.Claim[100] ^= 1 },
			"claim truncated":       func(in *Inputs) { in.Claim = in.Claim[:len(in.Claim)-1] },
			"imprint":               func(in *Inputs) { in.Imprint[31] ^= 1 },
			"time before notBefore": func(in *Inputs) { in.Time = f.notBefore.Unix() - 1 },
			"time after notAfter":   func(in *Inputs) { in.Time = f.notAfter.Unix() + 1 },
			"another CA": func(in *Inputs) {
				other := newFixture(t, fixtureOptions{})
				in.IssuerCert = other.in.IssuerCert
			},
		}
		for name, tamper := range cases {
			in := f.in
			in.Claim = append([]byte{}, f.in.Claim...)
			in.Imprint = append([]byte{}, f.in.Imprint...)
			tamper(&in)
			if solvedOn(t, curve, assign(t, in)) {
				t.Errorf("%s: accepted", name)
			}
		}
		// The boundaries of validity are inclusive.
		for _, at := range []time.Time{f.notBefore, f.notAfter} {
			in := f.in
			in.Time = at.Unix()
			if !solvedOn(t, curve, assign(t, in)) {
				t.Errorf("time %v at the validity boundary rejected", at)
			}
		}
	})
}

func TestTamperedPrivateInputsAreRejected(t *testing.T) {
	forEachCurve(t, func(t *testing.T, curve ecc.ID) {
		f := newFixture(t, fixtureOptions{})
		cases := map[string]func(c *Circuit){
			"claim signature": func(c *Circuit) { c.ClaimSig[40] = (c.ClaimSig[40].(byte) ^ 1) },
			"signer certificate": func(c *Circuit) {
				c.SigStructure[tbsContentOffset+60] = (c.SigStructure[tbsContentOffset+60].(byte) ^ 1)
			},
			"protected header": func(c *Circuit) {
				c.SigStructure[protectedOffset+700] = (c.SigStructure[protectedOffset+700].(byte) ^ 1)
			},
			"protected length": func(c *Circuit) { c.ProtectedLen = len(f.in.Protected) - 1 },
			"CA signature":     func(c *Circuit) { c.CASig = assign(t, newFixture(t, fixtureOptions{}).in).CASig },
		}
		for name, tamper := range cases {
			c := assign(t, f.in)
			tamper(c)
			if solvedOn(t, curve, c) {
				t.Errorf("%s: accepted", name)
			}
		}
	})
}

// Certificate purpose comes from the parsed extensions, not byte patterns
// (THIRD-PARTY-STATEMENT.md, Q5).
func TestCertificatePurposeIsEnforced(t *testing.T) {
	forEachCurve(t, func(t *testing.T, curve ecc.ID) {
		cases := map[string]fixtureOptions{
			"no claim-signing purpose":          {purposes: []asn1.ObjectIdentifier{oidEmailProtection}},
			"no extended key usage":             {noEKU: true},
			"EKU hidden in another extension":   {hiddenEKU: true},
			"two extended key usage extensions": {duplicateEKU: true},
			"a CA certificate":                  {isCA: true},
		}
		for name, opt := range cases {
			f := newFixture(t, opt)
			if solvedOn(t, curve, assign(t, f.in)) {
				t.Errorf("%s: accepted", name)
			}
		}
		// Claim signing alone, or among several purposes, is accepted.
		for _, purposes := range [][]asn1.ObjectIdentifier{{oidC2PAClaimSign}, {oidEmailProtection, oidPrivate, oidC2PAClaimSign}} {
			if !solvedOn(t, curve, assign(t, newFixture(t, fixtureOptions{purposes: purposes}).in)) {
				t.Errorf("purposes %v rejected", purposes)
			}
		}
	})
}

// Basic constraints is decoded structurally: a CA is rejected however its
// sequence is encoded, and unrecognized content is rejected, not ignored.
func TestBasicConstraintsIsDecodedStructurally(t *testing.T) {
	forEachCurve(t, func(t *testing.T, curve ecc.ID) {
		// The review's reproduction: cA TRUE in a sequence long enough to need a
		// long-form length (a 123-byte pathLenConstraint).
		longForm := append([]byte{0x30, 0x81, 0x80, 0x01, 0x01, 0xff, 0x02, 0x7b, 0x01}, make([]byte, 122)...)
		var parsed struct {
			IsCA    bool `asn1:"optional"`
			PathLen *big.Int
		}
		if rest, err := asn1.Unmarshal(longForm, &parsed); err != nil || len(rest) != 0 || !parsed.IsCA {
			t.Fatalf("the long-form value should be valid DER with cA TRUE: %v", err)
		}
		accepted := map[string]fixtureOptions{
			"absent":           {noBasicConstraints: true},
			"empty sequence":   {basicConstraints: []byte{0x30, 0x00}},
			"cA FALSE written": {basicConstraints: []byte{0x30, 0x03, 0x01, 0x01, 0x00}},
			"pathLen only":     {basicConstraints: []byte{0x30, 0x03, 0x02, 0x01, 0x05}},
		}
		rejected := map[string]fixtureOptions{
			"cA TRUE":                       {basicConstraints: []byte{0x30, 0x03, 0x01, 0x01, 0xff}},
			"cA TRUE, long-form length":     {basicConstraints: longForm},
			"cA TRUE with pathLen":          {basicConstraints: []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00}},
			"BOOLEAN of length 2":           {basicConstraints: []byte{0x30, 0x04, 0x01, 0x02, 0x00, 0xff}},
			"unexpected first element":      {basicConstraints: []byte{0x30, 0x03, 0x04, 0x01, 0x00}},
			"sequence shorter than value":   {basicConstraints: []byte{0x30, 0x00, 0x00}},
			"BOOLEAN past the sequence end": {basicConstraints: []byte{0x30, 0x02, 0x01, 0x01, 0xff}},
		}
		for name, opt := range accepted {
			if !solvedOn(t, curve, assign(t, newFixture(t, opt).in)) {
				t.Errorf("%s: rejected", name)
			}
		}
		for name, opt := range rejected {
			if solvedOn(t, curve, assign(t, newFixture(t, opt).in)) {
				t.Errorf("%s: accepted", name)
			}
		}
	})
}

// Assign refuses inputs the circuit cannot represent.
func TestAssignRefusesOutOfRangeInputs(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	for name, in := range map[string]Inputs{
		"claim too long":  {Public: Public{Claim: make([]byte, testSizes.MaxClaim+1), IssuerCert: f.in.IssuerCert, Imprint: f.in.Imprint}, Protected: f.in.Protected, Signature: f.in.Signature},
		"short signature": {Public: f.in.Public, Protected: f.in.Protected, Signature: f.in.Signature[:63]},
		"other layout":    {Public: f.in.Public, Protected: append([]byte{0xa1}, f.in.Protected[1:]...), Signature: f.in.Signature},
	} {
		if _, err := Assign(in, testSizes); err == nil {
			t.Errorf("%s: assigned", name)
		}
	}
}

// ---- Components ---------------------------------------------------------

type sha384Circuit struct {
	In     []uints.U8
	Len    frontend.Variable
	Digest []uints.U8 `gnark:",public"`
}

func (c *sha384Circuit) Define(api frontend.API) error {
	d, err := sum384(api, c.In, c.Len)
	if err != nil {
		return err
	}
	bapi, _ := uints.NewBytes(api)
	for i := range c.Digest {
		bapi.AssertIsEqual(d[i], c.Digest[i])
	}
	return nil
}

func TestVariableLengthSHA384MatchesStdlib(t *testing.T) {
	const max = 260
	msg := make([]byte, max)
	for i := range msg {
		msg[i] = byte(i*13 + 1)
	}
	circuit := &sha384Circuit{In: make([]uints.U8, max), Digest: make([]uints.U8, 48)}
	for _, n := range []int{0, 1, 111, 112, 127, 128, 239, 240, 255, 260} {
		want := sha512.Sum384(msg[:n])
		good := &sha384Circuit{In: uints.NewU8Array(msg), Len: n, Digest: uints.NewU8Array(want[:])}
		if err := test.IsSolved(circuit, good, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("length %d: %v", n, err)
		}
		want[0] ^= 1
		bad := &sha384Circuit{In: uints.NewU8Array(msg), Len: n, Digest: uints.NewU8Array(want[:])}
		if test.IsSolved(circuit, bad, ecc.BN254.ScalarField()) == nil {
			t.Fatalf("length %d: wrong digest accepted", n)
		}
	}
}

type utcCircuit struct {
	Digits []frontend.Variable
	Unix   frontend.Variable `gnark:",public"`
}

func (c *utcCircuit) Define(api frontend.API) error {
	r := &reader{api: api}
	r.table = newTable(api, c.Digits)
	r.small = newComparator(api, 1<<9)
	r.timeTables()
	api.AssertIsEqual(r.utcTime(0), c.Unix)
	return nil
}

func TestUTCTimeConversion(t *testing.T) {
	circuit := &utcCircuit{Digits: make([]frontend.Variable, 12)}
	digits := func(s string) []frontend.Variable {
		out := make([]frontend.Variable, 12)
		for i := range out {
			out[i] = s[i]
		}
		return out
	}
	for _, s := range []string{"000101000000", "240229235959", "240301000000", "250829011000", "491231235959", "000301000000"} {
		at, err := time.Parse("060102150405", s)
		if err != nil {
			t.Fatal(err)
		}
		if err := test.IsSolved(circuit, &utcCircuit{Digits: digits(s), Unix: at.Unix()}, ecc.BN254.ScalarField()); err != nil {
			t.Errorf("%s: %v", s, err)
		}
		if test.IsSolved(circuit, &utcCircuit{Digits: digits(s), Unix: at.Unix() + 1}, ecc.BN254.ScalarField()) == nil {
			t.Errorf("%s: wrong time accepted", s)
		}
	}
	for _, s := range []string{"500101000000", "241301000000", "240100000000", "241232000000", "240101240000", "2401010000/0"} {
		if test.IsSolved(circuit, &utcCircuit{Digits: digits(s), Unix: 0}, ecc.BN254.ScalarField()) == nil {
			t.Errorf("%s: accepted", s)
		}
	}
}

// A real Groth16 proof at test sizes (minutes): C2PA_ZK_GROTH16=1.
func TestGroth16ProofVerifies(t *testing.T) {
	if os.Getenv("C2PA_ZK_GROTH16") == "" {
		t.Skip("set C2PA_ZK_GROTH16=1 to run a real setup, proof, and verification")
	}
	ccs := testCircuit(t)
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, fixtureOptions{})
	w, _ := frontend.NewWitness(assign(t, f.in), ecc.BN254.ScalarField())
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := AssignPublic(f.in.Public, testSizes)
	if err != nil {
		t.Fatal(err)
	}
	pw, _ := frontend.NewWitness(pub, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err := groth16.Verify(proof, vk, pw); err != nil {
		t.Fatal(err)
	}
	f.in.Claim[0] ^= 1
	pub, _ = AssignPublic(f.in.Public, testSizes)
	pw, _ = frontend.NewWitness(pub, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if groth16.Verify(proof, vk, pw) == nil {
		t.Fatal("proof verified for another claim")
	}
}

func newTable(api frontend.API, values []frontend.Variable) logderivlookup.Table {
	t := logderivlookup.New(api)
	for _, v := range values {
		t.Insert(v)
	}
	return t
}

func newComparator(api frontend.API, bound int64) *cmp.BoundedComparator {
	return cmp.NewBoundedComparator(api, big.NewInt(bound), false)
}
