package main

// The E1 RSA circuits: RSA signature verification with the public exponent
// 65537, as real C2PA deployments use it:
//
//   - rsa*-pkcs1-*: RSASSA-PKCS1-v1_5 verification of a given digest (the
//     encoding CAs use for SHA256-RSA and SHA384-RSA certificate signatures).
//   - rsa*-pss-sha256: RSASSA-PSS verification of a given digest with SHA-256,
//     MGF1-SHA-256, and a 32-byte salt (PS256, as COSE and C2PA signers use it;
//     RFC 8230 sets the salt length to the hash length).
//   - ca-rsa*-*: "a CA signature over a TBS" with PKCS#1 v1.5: hash the private
//     TBS bytes and verify the CA's signature over the digest under the public
//     CA key, like the ca-p256/p384 circuits.
//
// The modulus is an emulated element of exactly the key's size (variable
// modulus arithmetic, gnark's ModMul), so one circuit serves every key of that
// size. The signature s is private; s^65537 mod n is computed with 16
// squarings and one multiplication, its canonical value (asserted below n) is
// decomposed into bits, and the encoded message is checked bit by bit.

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// Emulation parameters with exactly as many 64-bit limbs as the key size: the
// cost of the variable-modulus operations depends on these, not on the key.
type rsa2048 struct{}
type rsa3072 struct{}
type rsa4096 struct{}

func (rsa2048) NbLimbs() uint     { return 32 }
func (rsa3072) NbLimbs() uint     { return 48 }
func (rsa4096) NbLimbs() uint     { return 64 }
func (rsa2048) BitsPerLimb() uint { return 64 }
func (rsa3072) BitsPerLimb() uint { return 64 }
func (rsa4096) BitsPerLimb() uint { return 64 }
func (rsa2048) IsPrime() bool     { return false }
func (rsa3072) IsPrime() bool     { return false }
func (rsa4096) IsPrime() bool     { return false }
func (rsa2048) Modulus() *big.Int { return allOnes(2048) }
func (rsa3072) Modulus() *big.Int { return allOnes(3072) }
func (rsa4096) Modulus() *big.Int { return allOnes(4096) }

// allOnes returns 2^bits - 1, the parametrization modulus: every RSA modulus of
// that size is strictly below it, as the variable-modulus operations require.
func allOnes(bits int) *big.Int {
	one := big.NewInt(1)
	return new(big.Int).Sub(new(big.Int).Lsh(one, uint(bits)), one)
}

// DigestInfo prefixes for EMSA-PKCS1-v1_5 (RFC 8017, section 9.2, note 1).
var digestInfoPrefix = map[string][]byte{
	"sha256": {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	"sha384": {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
}

var digestLen = map[string]int{"sha256": 32, "sha384": 48}

// PSS parameters (PS256).
const (
	pssHashLen = 32
	pssSaltLen = 32
)

// RsaPkcs1Circuit verifies an RSASSA-PKCS1-v1_5 signature over a given digest.
type RsaPkcs1Circuit[T emulated.FieldParams] struct {
	Hash   string              `gnark:"-"`
	N      emulated.Element[T] `gnark:",public"`
	S      emulated.Element[T]
	Digest []uints.U8
}

func (c *RsaPkcs1Circuit[T]) Define(api frontend.API) error {
	em, err := rsaEncodedMessage(api, &c.S, &c.N)
	if err != nil {
		return err
	}
	return assertPkcs1(api, em, c.Hash, c.Digest)
}

// CaRsaCircuit verifies the CA's RSASSA-PKCS1-v1_5 signature over the TBS bytes.
type CaRsaCircuit[T emulated.FieldParams] struct {
	Hash string              `gnark:"-"`
	N    emulated.Element[T] `gnark:",public"`
	S    emulated.Element[T]
	Tbs  []uints.U8
}

func (c *CaRsaCircuit[T]) Define(api frontend.API) error {
	digest, err := hashBytes(api, c.Hash, c.Tbs)
	if err != nil {
		return err
	}
	em, err := rsaEncodedMessage(api, &c.S, &c.N)
	if err != nil {
		return err
	}
	return assertPkcs1(api, em, c.Hash, digest)
}

// RsaPssCircuit verifies a PS256 signature over a given digest. The signer's
// key is private, as it is in the anonymization statement.
type RsaPssCircuit[T emulated.FieldParams] struct {
	N      emulated.Element[T]
	S      emulated.Element[T]
	Digest []uints.U8
}

func (c *RsaPssCircuit[T]) Define(api frontend.API) error {
	em, err := rsaEncodedMessage(api, &c.S, &c.N)
	if err != nil {
		return err
	}
	return assertPss(api, em, c.Digest)
}

// rsaEncodedMessage computes s^65537 mod n and returns it as big-endian bytes,
// each byte as eight bits, least significant first. The result is asserted to
// be below n, so its bits are unique.
func rsaEncodedMessage[T emulated.FieldParams](api frontend.API, s, n *emulated.Element[T]) ([][]frontend.Variable, error) {
	f, err := emulated.NewField[T](api)
	if err != nil {
		return nil, err
	}
	m := s
	for i := 0; i < 16; i++ {
		m = f.ModMul(m, m, n)
	}
	m = f.ModMulCanonical(m, s, n)
	bits := f.ToBits(m) // least significant first; exactly 8k bits, as T has the key's size
	k := len(bits) / 8
	em := make([][]frontend.Variable, k)
	for i := range em {
		em[i] = bits[(k-1-i)*8 : (k-i)*8]
	}
	return em, nil
}

func assertByte(api frontend.API, bits []frontend.Variable, want byte) {
	for b := 0; b < 8; b++ {
		api.AssertIsEqual(bits[b], (want>>b)&1)
	}
}

// assertPkcs1 checks EM = 0x00 0x01 0xff...0xff 0x00 || DigestInfo || digest.
func assertPkcs1(api frontend.API, em [][]frontend.Variable, hash string, digest []uints.U8) error {
	prefix, ok := digestInfoPrefix[hash]
	if !ok || len(digest) != digestLen[hash] {
		return fmt.Errorf("unsupported PKCS#1 v1.5 hash %q with a %d-byte digest", hash, len(digest))
	}
	k := len(em)
	tLen := len(prefix) + len(digest)
	if k < tLen+11 {
		return fmt.Errorf("modulus too short for %s", hash)
	}
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	assertByte(api, em[0], 0x00)
	assertByte(api, em[1], 0x01)
	for i := 2; i < k-tLen-1; i++ {
		assertByte(api, em[i], 0xff)
	}
	assertByte(api, em[k-tLen-1], 0x00)
	for i, p := range prefix {
		assertByte(api, em[k-tLen+i], p)
	}
	for i, d := range digest {
		dbits := bapi.ToBits(d)
		for b := 0; b < 8; b++ {
			api.AssertIsEqual(em[k-len(digest)+i][b], dbits[b])
		}
	}
	return nil
}

// assertPss runs EMSA-PSS-VERIFY (RFC 8017, section 9.1.2) for SHA-256,
// MGF1-SHA-256, a 32-byte salt, and a modulus whose size is a multiple of
// eight bits (emBits = 8k - 1, emLen = k).
func assertPss(api frontend.API, em [][]frontend.Variable, digest []uints.U8) error {
	if len(digest) != pssHashLen {
		return fmt.Errorf("PS256 needs a %d-byte digest, got %d", pssHashLen, len(digest))
	}
	k := len(em)
	dbLen := k - pssHashLen - 1
	psLen := dbLen - pssSaltLen - 1
	if psLen < 0 {
		return fmt.Errorf("modulus too short for PS256")
	}
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	// Steps 4 and 6: the trailer field and the leftmost bit (8·emLen − emBits = 1).
	assertByte(api, em[k-1], 0xbc)
	api.AssertIsEqual(em[0][7], 0)

	// Step 5: maskedDB and H.
	masked := em[:dbLen]
	h := make([]uints.U8, pssHashLen)
	for i := range h {
		h[i] = bapi.FromBits(em[dbLen+i]...)
	}

	// Steps 7–9: DB = maskedDB XOR MGF1(H, dbLen), leftmost bit cleared.
	mask, err := mgf1Sha256(api, h, dbLen)
	if err != nil {
		return err
	}
	db := make([][]frontend.Variable, dbLen)
	for i := range db {
		mbits := bapi.ToBits(mask[i])
		db[i] = make([]frontend.Variable, 8)
		for b := 0; b < 8; b++ {
			db[i][b] = api.Xor(masked[i][b], mbits[b])
		}
	}
	db[0][7] = 0

	// Step 10: DB = PS (zeros) || 0x01 || salt.
	for i := 0; i < psLen; i++ {
		assertByte(api, db[i], 0x00)
	}
	assertByte(api, db[psLen], 0x01)

	// Steps 11–14: H' = SHA-256(0x00 × 8 || mHash || salt) equals H.
	mPrime := make([]uints.U8, 0, 8+pssHashLen+pssSaltLen)
	for i := 0; i < 8; i++ {
		mPrime = append(mPrime, uints.NewU8(0))
	}
	mPrime = append(mPrime, digest...)
	for i := dbLen - pssSaltLen; i < dbLen; i++ {
		mPrime = append(mPrime, bapi.FromBits(db[i]...))
	}
	sha, err := sha2.New(api)
	if err != nil {
		return err
	}
	sha.Write(mPrime)
	for i, b := range sha.Sum() {
		bapi.AssertIsEqual(b, h[i])
	}
	return nil
}

// mgf1Sha256 returns the first n bytes of MGF1-SHA-256(seed) (RFC 8017, B.2.1).
func mgf1Sha256(api frontend.API, seed []uints.U8, n int) ([]uints.U8, error) {
	var out []uints.U8
	for counter := 0; len(out) < n; counter++ {
		sha, err := sha2.New(api)
		if err != nil {
			return nil, err
		}
		sha.Write(seed)
		sha.Write(uints.NewU8Array([]byte{byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter)}))
		out = append(out, sha.Sum()...)
	}
	return out[:n], nil
}
