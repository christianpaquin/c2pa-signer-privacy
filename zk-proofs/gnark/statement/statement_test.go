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

var (
	compileOnce sync.Once
	compiled    constraint.ConstraintSystem
	compileErr  error
)

func testCircuit(t *testing.T) constraint.ConstraintSystem {
	t.Helper()
	compileOnce.Do(func() {
		compiled, compileErr = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, NewCircuit(testSizes))
	})
	if compileErr != nil {
		t.Fatal(compileErr)
	}
	return compiled
}

// solved reports whether the compiled constraint system accepts the assignment.
func solved(t *testing.T, c *Circuit) bool {
	t.Helper()
	w, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return testCircuit(t).IsSolved(w) == nil
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
	for _, claimLen := range []int{377, 200} { // both claim header forms (59 / 58)
		f := newFixture(t, fixtureOptions{claimLen: claimLen})
		if !solved(t, assign(t, f.in)) {
			t.Fatalf("valid statement rejected (claim %d bytes)", claimLen)
		}
	}
	t.Logf("%d constraints at test sizes", testCircuit(t).GetNbConstraints())
}

func TestTamperedPublicInputsAreRejected(t *testing.T) {
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
		if solved(t, assign(t, in)) {
			t.Errorf("%s: accepted", name)
		}
	}
	// The boundaries of validity are inclusive.
	for _, at := range []time.Time{f.notBefore, f.notAfter} {
		in := f.in
		in.Time = at.Unix()
		if !solved(t, assign(t, in)) {
			t.Errorf("time %v at the validity boundary rejected", at)
		}
	}
}

func TestTamperedPrivateInputsAreRejected(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	cases := map[string]func(c *Circuit){
		"claim signature":     func(c *Circuit) { c.ClaimSig[40] = (c.ClaimSig[40].(byte) ^ 1) },
		"signer certificate":  func(c *Circuit) { c.SigStructure[tbsContentOffset+60] = (c.SigStructure[tbsContentOffset+60].(byte) ^ 1) },
		"protected header":    func(c *Circuit) { c.SigStructure[protectedOffset+700] = (c.SigStructure[protectedOffset+700].(byte) ^ 1) },
		"protected length":    func(c *Circuit) { c.ProtectedLen = len(f.in.Protected) - 1 },
		"CA signature":        func(c *Circuit) { c.CASig = assign(t, newFixture(t, fixtureOptions{}).in).CASig },
	}
	for name, tamper := range cases {
		c := assign(t, f.in)
		tamper(c)
		if solved(t, c) {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Certificate purpose comes from the parsed extensions, not byte patterns
// (THIRD-PARTY-STATEMENT.md, Q5).
func TestCertificatePurposeIsEnforced(t *testing.T) {
	cases := map[string]fixtureOptions{
		"no claim-signing purpose":         {purposes: []asn1.ObjectIdentifier{oidEmailProtection}},
		"no extended key usage":            {noEKU: true},
		"EKU hidden in another extension":  {hiddenEKU: true},
		"two extended key usage extensions": {duplicateEKU: true},
		"a CA certificate":                 {isCA: true},
	}
	for name, opt := range cases {
		f := newFixture(t, opt)
		if solved(t, assign(t, f.in)) {
			t.Errorf("%s: accepted", name)
		}
	}
	// Claim signing alone, or among several purposes, is accepted.
	for _, purposes := range [][]asn1.ObjectIdentifier{{oidC2PAClaimSign}, {oidEmailProtection, oidPrivate, oidC2PAClaimSign}} {
		if !solved(t, assign(t, newFixture(t, fixtureOptions{purposes: purposes}).in)) {
			t.Errorf("purposes %v rejected", purposes)
		}
	}
}

// Assign refuses inputs the circuit cannot represent.
func TestAssignRefusesOutOfRangeInputs(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	for name, in := range map[string]Inputs{
		"claim too long":   {Public: Public{Claim: make([]byte, testSizes.MaxClaim+1), IssuerCert: f.in.IssuerCert, Imprint: f.in.Imprint}, Protected: f.in.Protected, Signature: f.in.Signature},
		"short signature":  {Public: f.in.Public, Protected: f.in.Protected, Signature: f.in.Signature[:63]},
		"other layout":     {Public: f.in.Public, Protected: append([]byte{0xa1}, f.in.Protected[1:]...), Signature: f.in.Signature},
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
