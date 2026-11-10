package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

// rsaCase is one input to an RSA circuit, with the verdict expected from the
// circuit and from Go's crypto/rsa. Every case is checked against the standard
// library: the circuit accepts exactly what a standard verifier accepts, except
// what it refuses by design (outsideScope: a modulus smaller than the circuit's
// key size, which a standard verifier accepts).
type rsaCase struct {
	name         string
	n, sig       []byte
	dgst         []byte
	accepted     bool
	outsideScope bool
}

// checkRsaCases runs every case through crypto/rsa, gnark's test engine, and
// the compiled R1CS (solved, without proving), so the verdicts hold for the
// constraints a proof is made against, not only for the circuit's definition.
func checkRsaCases(t *testing.T, cases []rsaCase, stdlib func(c rsaCase) error, build func(c rsaCase) fixture) {
	t.Helper()
	field := ecc.BN254.ScalarField()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, build(cases[0]).circuit)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := stdlib(c); (err == nil) != (c.accepted || c.outsideScope) {
				t.Fatalf("crypto/rsa verdict %v, want accepted=%v", err, c.accepted || c.outsideScope)
			}
			fx := build(c)
			if err := test.IsSolved(fx.circuit, fx.assignment, field); (err == nil) != c.accepted {
				t.Fatalf("test engine verdict %v, want accepted=%v", err, c.accepted)
			}
			w, err := frontend.NewWitness(fx.assignment, field)
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(w, fixedChallenge()); (err == nil) != c.accepted {
				t.Fatalf("compiled R1CS verdict %v, want accepted=%v", err, c.accepted)
			}
		})
	}
}

// plusModulus returns a signature s + n that still fits the key size, and the
// digest it verifies (as s) under: s + n is the same signature modulo n, which
// RSAVP1 refuses.
func plusModulus(t *testing.T, key *rsa.PrivateKey, sign func(i int) (sig, dgst []byte)) ([]byte, []byte) {
	t.Helper()
	limit := new(big.Int).Lsh(big.NewInt(1), uint(8*key.Size()))
	for i := range 256 {
		sig, dgst := sign(i)
		if s := new(big.Int).Add(bigBytes(sig), key.N); s.Cmp(limit) < 0 {
			return s.FillBytes(make([]byte, key.Size())), dgst
		}
	}
	t.Fatal("no signature s with s + n below the key size")
	return nil, nil
}

// shortKey is a 2047-bit key: standard verifiers accept its signatures, and a
// 2048-bit circuit must refuse its modulus (PS256's encoding size depends on
// the modulus size).
func shortKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2047)
	if err != nil {
		t.Fatal(err)
	}
	if key.N.BitLen() != 2047 || key.Size() != 256 {
		t.Fatalf("got a %d-bit key", key.N.BitLen())
	}
	return key
}

// pkcs1Encoding returns EMSA-PKCS1-v1_5 for a key of k bytes, built by hand
// so that single fields can be altered.
func pkcs1Encoding(k int, prefix, dgst []byte) []byte {
	em := make([]byte, k)
	em[1] = 0x01
	tLen := len(prefix) + len(dgst)
	for i := 2; i < k-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-tLen:], prefix)
	copy(em[k-len(dgst):], dgst)
	return em
}

func TestRsaPkcs1AcceptsExactlyTheStandardEncoding(t *testing.T) {
	key, err := rsaKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dgst := digest("sha256", message(smallTbs))
	n := key.N.Bytes()
	k := key.Size()
	prefix := digestInfoPrefix["sha256"]
	alter := func(f func(em []byte)) []byte {
		em := pkcs1Encoding(k, prefix, dgst)
		f(em)
		return rawSign(key, em)
	}
	signed, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, dgst)
	if err != nil {
		t.Fatal(err)
	}
	tamperedSig := append([]byte(nil), signed...)
	tamperedSig[k/2] ^= 1
	tamperedDigest := append([]byte(nil), dgst...)
	tamperedDigest[31] ^= 1
	tLen := len(prefix) + len(dgst)
	bigSig, bigDigest := plusModulus(t, key, func(i int) ([]byte, []byte) {
		d := digest("sha256", message(i))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d)
		if err != nil {
			t.Fatal(err)
		}
		return sig, d
	})
	short := shortKey(t)
	shortSig, err := rsa.SignPKCS1v15(rand.Reader, short, crypto.SHA256, dgst)
	if err != nil {
		t.Fatal(err)
	}

	cases := []rsaCase{
		{"signed by crypto/rsa", n, signed, dgst, true, false},
		{"hand-built encoding", n, alter(func([]byte) {}), dgst, true, false},
		{"tampered signature", n, tamperedSig, dgst, false, false},
		{"tampered digest", n, signed, tamperedDigest, false, false},
		{"another key's modulus", other.N.Bytes(), signed, dgst, false, false},
		{"block type 2", n, alter(func(em []byte) { em[1] = 0x02 }), dgst, false, false},
		{"padding byte not 0xff", n, alter(func(em []byte) { em[10] = 0xfe }), dgst, false, false},
		{"no zero separator", n, alter(func(em []byte) { em[k-tLen-1] = 0xff }), dgst, false, false},
		{"SHA-384 algorithm identifier", n, alter(func(em []byte) { em[k-tLen+14] = 0x02 }), dgst, false, false},
		{"signature plus modulus", n, bigSig, bigDigest, false, false},
		{"2047-bit modulus", short.N.Bytes(), shortSig, dgst, false, true},
	}
	checkRsaCases(t, cases,
		func(c rsaCase) error {
			return rsa.VerifyPKCS1v15(&rsa.PublicKey{N: bigBytes(c.n), E: 65537}, crypto.SHA256, c.dgst, c.sig)
		},
		func(c rsaCase) fixture { return pkcs1Circuit[rsa2048]("sha256", c.n, c.sig, c.dgst) })
}

// pssEncoding returns EMSA-PSS-ENCODE (RFC 8017, 9.1.1) for SHA-256 and a key
// of k bytes whose size is a multiple of 8 bits, built by hand so that single
// fields can be altered: edit changes DB before masking, and emEdit the final EM.
func pssEncoding(k int, mHash, salt []byte, edit func(db []byte), emEdit func(em []byte)) []byte {
	mPrime := append(append(make([]byte, 8), mHash...), salt...)
	h := sha256.Sum256(mPrime)
	dbLen := k - len(h) - 1
	db := make([]byte, dbLen)
	db[dbLen-len(salt)-1] = 0x01
	copy(db[dbLen-len(salt):], salt)
	if edit != nil {
		edit(db)
	}
	var mask []byte
	for counter := 0; len(mask) < dbLen; counter++ {
		block := sha256.Sum256(append(append([]byte(nil), h[:]...), byte(counter>>24), byte(counter>>16), byte(counter>>8), byte(counter)))
		mask = append(mask, block[:]...)
	}
	em := make([]byte, k)
	for i := range db {
		em[i] = db[i] ^ mask[i]
	}
	em[0] &= 0x7f
	copy(em[dbLen:], h[:])
	em[k-1] = 0xbc
	if emEdit != nil {
		emEdit(em)
	}
	return em
}

func TestRsaPssAcceptsExactlyPS256(t *testing.T) {
	key, err := rsaKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dgst := digest("sha256", message(smallTbs))
	n := key.N.Bytes()
	k := key.Size()
	salt := make([]byte, pssSaltLen)
	rand.Read(salt)
	built := func(salt []byte, edit func([]byte), emEdit func([]byte)) []byte {
		return rawSign(key, pssEncoding(k, dgst, salt, edit, emEdit))
	}
	signed, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, dgst, pssOptions)
	if err != nil {
		t.Fatal(err)
	}
	shortSalt, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, dgst, &rsa.PSSOptions{SaltLength: 20})
	if err != nil {
		t.Fatal(err)
	}
	tamperedDigest := append([]byte(nil), dgst...)
	tamperedDigest[0] ^= 1
	bigSig, _ := plusModulus(t, key, func(int) ([]byte, []byte) {
		sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, dgst, pssOptions)
		if err != nil {
			t.Fatal(err)
		}
		return sig, dgst
	})
	short := shortKey(t)
	shortSig, err := rsa.SignPSS(rand.Reader, short, crypto.SHA256, dgst, pssOptions)
	if err != nil {
		t.Fatal(err)
	}

	cases := []rsaCase{
		{"signed by crypto/rsa", n, signed, dgst, true, false},
		{"hand-built encoding", n, built(salt, nil, nil), dgst, true, false},
		{"tampered digest", n, signed, tamperedDigest, false, false},
		{"another key's modulus", other.N.Bytes(), signed, dgst, false, false},
		{"20-byte salt", n, shortSalt, dgst, false, false},
		{"empty salt", n, built(nil, nil, nil), dgst, false, false},
		{"trailer not 0xbc", n, built(salt, nil, func(em []byte) { em[k-1] = 0xbd }), dgst, false, false},
		{"leftmost bit set", n, leftmostBitSet(t, key, dgst), dgst, false, false},
		{"nonzero padding", n, built(salt, func(db []byte) { db[5] = 0x01 }, nil), dgst, false, false},
		{"separator not 0x01", n, built(salt, func(db []byte) { db[len(db)-pssSaltLen-1] = 0x02 }, nil), dgst, false, false},
		{"signature plus modulus", n, bigSig, dgst, false, false},
		{"2047-bit modulus", short.N.Bytes(), shortSig, dgst, false, true},
	}
	checkRsaCases(t, cases,
		func(c rsaCase) error {
			return rsa.VerifyPSS(&rsa.PublicKey{N: bigBytes(c.n), E: 65537}, crypto.SHA256, c.dgst, c.sig, &rsa.PSSOptions{SaltLength: pssSaltLen})
		},
		func(c rsaCase) fixture { return pssCircuit[rsa2048](c.n, c.sig, c.dgst) })
}

func bigBytes(b []byte) *big.Int { return new(big.Int).SetBytes(b) }

// leftmostBitSet signs a PSS encoding whose leftmost bit is set, with a salt
// for which that encoding stays below the modulus, so it is rejected for the
// bit and not because it wraps around n.
func leftmostBitSet(t *testing.T, key *rsa.PrivateKey, dgst []byte) []byte {
	t.Helper()
	salt := make([]byte, pssSaltLen)
	for range 64 {
		rand.Read(salt)
		em := pssEncoding(key.Size(), dgst, salt, nil, func(em []byte) { em[0] |= 0x80 })
		if bigBytes(em).Cmp(key.N) < 0 {
			return rawSign(key, em)
		}
	}
	t.Fatal("no salt gives an encoding below the modulus")
	return nil
}
