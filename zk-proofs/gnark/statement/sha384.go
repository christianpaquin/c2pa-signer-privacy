package statement

// SHA-384 in-circuit over a variable-length input, built on gnark's 64-bit
// word API (uints.U64). The compression function is E1's (experiments/e1-p384,
// tested against crypto/sha512): SHA-512's word size, constants, rotations,
// and 80 rounds (FIPS 180-4, section 6.4), with SHA-384's initial value and a
// 48-byte output. Variable-length padding follows gnark's SHA-256
// FixedLengthSum: hash up to the maximum, place the padding by the actual
// length, and keep the digest after the last block in use.

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/cmp"
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

// sum384 hashes in[:length], where length <= len(in) is only known at proving time.
func sum384(api frontend.API, in []uints.U8, length frontend.Variable) ([]uints.U8, error) {
	u, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, err
	}
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return nil, err
	}
	maxLen := len(in)
	// Room for the 0x80 byte and the 16-byte length, rounded up to a block.
	maxTotal := (maxLen + 1 + 16 + 127) / 128 * 128
	comparator := cmp.NewBoundedComparator(api, big.NewInt(int64(maxTotal+128)), false)
	comparator.AssertIsLessEq(length, maxLen)

	data := make([]uints.U8, maxTotal)
	copy(data, in)
	for i := maxLen; i < maxTotal; i++ {
		data[i] = uints.NewU8(0)
	}

	// Total padded length: the smallest multiple of 128 holding length + 17.
	lenMod128, _ := bitsPartition(api, length, 7)
	fits := comparator.IsLess(lenMod128, 112) // 0x80 and the length fit in this block
	padding := api.Sub(128, lenMod128)
	padding = api.Select(fits, padding, api.Add(padding, 128))
	totalLen := api.Add(length, padding)
	lengthPos := api.Sub(totalLen, 8) // the bit length's low 64 bits; the high 64 are zero

	bitLen := bits.ToBinary(api, api.Mul(length, 8), bits.WithNbDigits(64))
	var lengthBytes [8]uints.U8
	for i := 0; i < 8; i++ {
		lengthBytes[i] = bapi.ValueOf(bits.FromBinary(api, bitLen[(7-i)*8:(8-i)*8]))
	}
	for i := 0; i <= maxLen; i++ {
		data[i] = bapi.Select(cmp.IsEqual(api, i, length), uints.NewU8(0x80), data[i])
	}
	for i := 1; i < maxTotal; i++ {
		if i < maxLen {
			data[i] = bapi.Select(comparator.IsLess(length, i), uints.NewU8(0), data[i])
		}
	}
	for i := 0; i+8 <= maxTotal; i++ {
		at := cmp.IsEqual(api, i, lengthPos)
		for j := 0; j < 8; j++ {
			data[i+j] = bapi.Select(at, lengthBytes[j], data[i+j])
		}
	}

	var state, result [8]uints.U64
	for i := range state {
		state[i] = uints.NewU64(sha384IV[i])
	}
	var block [128]uints.U8
	for b := 0; b < maxTotal/128; b++ {
		copy(block[:], data[b*128:(b+1)*128])
		state = permute512(u, state, block)
		if b == 0 {
			result = state
			continue
		}
		inUse := comparator.IsLess(b*128, totalLen)
		for j := range result {
			for k := range result[j] {
				result[j][k] = bapi.Select(inUse, state[j][k], result[j][k])
			}
		}
	}
	var out []uints.U8
	for i := 0; i < 6; i++ {
		out = append(out, u.UnpackMSB(result[i])...)
	}
	return out, nil
}

// bitsPartition splits v into its low n bits (as a number) and the rest.
func bitsPartition(api frontend.API, v frontend.Variable, n int) (frontend.Variable, frontend.Variable) {
	b := bits.ToBinary(api, v, bits.WithNbDigits(32))
	return bits.FromBinary(api, b[:n]), bits.FromBinary(api, b[n:])
}
