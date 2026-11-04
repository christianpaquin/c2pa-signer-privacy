package main

// SHA-384 in-circuit, built on gnark's 64-bit word API (uints.U64). gnark's
// standard library only provides SHA-256 (and SHA-3), so this follows its
// SHA-256 permutation (std/permutation/sha2) with SHA-512's word size,
// constants, rotations, and 80 rounds (FIPS 180-4, section 6.4); SHA-384 is
// SHA-512 with a different initial value, truncated to 48 bytes.

import (
	"encoding/binary"
	"math/big"

	"github.com/consensys/gnark/std/math/uints"
)

// Constants derived as FIPS 180-4 defines them, so no table needs checking by
// eye: K[i] is the first 64 bits of the fractional part of the cube root of
// the i-th prime; SHA-384's initial value is the same for the square roots of
// the 9th through 16th primes. Tests compare the result with crypto/sha512.
var (
	sha512K   = deriveK()
	sha384IV  = deriveIV([]int64{23, 29, 31, 37, 41, 43, 47, 53})
	two64Mask = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
)

func firstPrimes(n int) []int64 {
	var ps []int64
	for c := int64(2); len(ps) < n; c++ {
		if big.NewInt(c).ProbablyPrime(20) {
			ps = append(ps, c)
		}
	}
	return ps
}

// icbrt returns floor(cbrt(n)) by Newton's method on integers.
func icbrt(n *big.Int) *big.Int {
	x := new(big.Int).Lsh(big.NewInt(1), uint(n.BitLen()/3+1))
	for {
		// y = (2x + n / x^2) / 3
		y := new(big.Int).Div(n, new(big.Int).Mul(x, x))
		y.Add(y, new(big.Int).Lsh(x, 1))
		y.Div(y, big.NewInt(3))
		if y.Cmp(x) >= 0 {
			return x
		}
		x = y
	}
}

func deriveK() [80]uint64 {
	var k [80]uint64
	for i, p := range firstPrimes(80) {
		root := icbrt(new(big.Int).Lsh(big.NewInt(p), 192)) // cbrt(p) * 2^64
		k[i] = new(big.Int).And(root, two64Mask).Uint64()
	}
	return k
}

func deriveIV(primes []int64) [8]uint64 {
	var iv [8]uint64
	for i, p := range primes {
		root := new(big.Int).Sqrt(new(big.Int).Lsh(big.NewInt(p), 128)) // sqrt(p) * 2^64
		iv[i] = new(big.Int).And(root, two64Mask).Uint64()
	}
	return iv
}

// permute512 is one SHA-512 compression of a 128-byte block.
func permute512(u *uints.BinaryField[uints.U64], h [8]uints.U64, p [128]uints.U8) [8]uints.U64 {
	var w [80]uints.U64
	for i := 0; i < 16; i++ {
		w[i] = u.PackMSB(p[8*i : 8*i+8]...)
	}
	for i := 16; i < 80; i++ {
		s0 := u.Xor(u.Lrot(w[i-15], -1), u.Lrot(w[i-15], -8), u.Rshift(w[i-15], 7))
		s1 := u.Xor(u.Lrot(w[i-2], -19), u.Lrot(w[i-2], -61), u.Rshift(w[i-2], 6))
		w[i] = u.Add(s1, w[i-7], s0, w[i-16])
	}
	a, b, c, d, e, f, g, hh := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
	for i := 0; i < 80; i++ {
		t1 := u.Add(
			hh,
			u.Xor(u.Lrot(e, -14), u.Lrot(e, -18), u.Lrot(e, -41)),
			u.Xor(u.And(e, f), u.And(u.Not(e), g)),
			uints.NewU64(sha512K[i]),
			w[i],
		)
		t2 := u.Add(
			u.Xor(u.Lrot(a, -28), u.Lrot(a, -34), u.Lrot(a, -39)),
			u.Xor(u.And(a, b), u.And(a, c), u.And(b, c)),
		)
		hh, g, f, e, d, c, b, a = g, f, e, u.Add(d, t1), c, b, a, u.Add(t1, t2)
	}
	return [8]uints.U64{
		u.Add(h[0], a), u.Add(h[1], b), u.Add(h[2], c), u.Add(h[3], d),
		u.Add(h[4], e), u.Add(h[5], f), u.Add(h[6], g), u.Add(h[7], hh),
	}
}

// sum384 hashes a message whose length is fixed when the circuit is compiled.
func sum384(u *uints.BinaryField[uints.U64], in []uints.U8) []uints.U8 {
	// Padding: 0x80, zeros, then the 128-bit big-endian bit length.
	zeros := (112 - (len(in)+1)%128 + 128) % 128
	msg := append(append([]uints.U8{}, in...), uints.NewU8(0x80))
	msg = append(msg, uints.NewU8Array(make([]uint8, zeros+8))...)
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(8*len(in)))
	msg = append(msg, uints.NewU8Array(length[:])...)

	var state [8]uints.U64
	for i := range state {
		state[i] = uints.NewU64(sha384IV[i])
	}
	var block [128]uints.U8
	for i := 0; i < len(msg)/128; i++ {
		copy(block[:], msg[i*128:(i+1)*128])
		state = permute512(u, state, block)
	}
	var out []uints.U8
	for i := 0; i < 6; i++ {
		out = append(out, u.UnpackMSB(state[i])...)
	}
	return out
}
