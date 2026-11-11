// Package issuertree builds the Merkle tree of issuing CAs that the
// hidden-issuer statement proves membership in (roadmap H4,
// HIDING-THE-ISSUER.md, "Tree format, version 1").
//
// A leaf commits to a CA's P-384 key and validity period:
//
//	H(1, version, keyType, x2, x1, x0, y2, y1, y0, notBefore, notAfter)
//
// where x2 x1 x0 (and y2 y1 y0) are the canonical coordinate as three 128-bit
// limbs, most significant first, and notBefore and notAfter are Unix seconds.
// Internal nodes are H(2, left, right) and empty leaves H(3). H is Poseidon2
// with gnark-crypto's default parameters for the proof's scalar field, in the
// Merkle-Damgard mode of gnark's std/hash/poseidon2. Leaves are sorted by
// their hash as an integer; identical leaves are kept once; the tree is
// padded with empty leaves to 2^Depth, and larger sets are refused.
//
// Which certificates are eligible (CA checks, no name or policy constraints)
// is the caller's decision (HIDING-THE-ISSUER.md, I1): Build takes the
// certificates it is given and keeps those with P-384 keys.
package issuertree

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"hash"
	"math/big"
	"sort"

	"github.com/consensys/gnark-crypto/ecc"
	gchash "github.com/consensys/gnark-crypto/hash"

	_ "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2" // registers POSEIDON2_BLS12_381
	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"     // registers POSEIDON2_BN254
)

const (
	// FormatVersion is the tree format specified in HIDING-THE-ISSUER.md.
	FormatVersion = 1
	// KeyTypeP384 identifies P-384 CA keys in leaves.
	KeyTypeP384 = 1
	// Depth is the tree's fixed depth; Capacity its number of leaves.
	Depth    = 8
	Capacity = 1 << Depth

	tagLeaf  = 1
	tagNode  = 2
	tagEmpty = 3
)

// Hasher computes H over field elements for a curve's scalar field.
type Hasher struct {
	curve ecc.ID
	size  int
	mod   *big.Int
}

// NewHasher returns the Poseidon2 hasher for the curve's scalar field.
func NewHasher(curve ecc.ID) (*Hasher, error) {
	switch curve {
	case ecc.BN254, ecc.BLS12_381:
	default:
		return nil, fmt.Errorf("no Poseidon2 tree for curve %s", curve)
	}
	mod := curve.ScalarField()
	return &Hasher{curve: curve, size: (mod.BitLen() + 7) / 8, mod: mod}, nil
}

func (h *Hasher) newHash() hash.Hash {
	if h.curve == ecc.BN254 {
		return gchash.POSEIDON2_BN254.New()
	}
	return gchash.POSEIDON2_BLS12_381.New()
}

// Hash is H(elements...), each element below the field modulus.
func (h *Hasher) Hash(elements ...*big.Int) (*big.Int, error) {
	hh := h.newHash()
	buf := make([]byte, h.size)
	for _, e := range elements {
		if e.Sign() < 0 || e.Cmp(h.mod) >= 0 {
			return nil, fmt.Errorf("element %s is not in the scalar field", e)
		}
		e.FillBytes(buf)
		hh.Write(buf)
	}
	return new(big.Int).SetBytes(hh.Sum(nil)), nil
}

// Limbs128 splits a value below 2^384 into three 128-bit limbs, most
// significant first.
func Limbs128(v *big.Int) [3]*big.Int {
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	var out [3]*big.Int
	for i := 0; i < 3; i++ {
		out[2-i] = new(big.Int).And(new(big.Int).Rsh(v, uint(128*i)), mask)
	}
	return out
}

// CA is a tree entry: a CA's P-384 key and validity period.
type CA struct {
	X, Y                *big.Int
	NotBefore, NotAfter int64
	// The certificate's SHA-256, to identify it (not part of the leaf).
	CertSHA256 string
}

// LeafInputs are the leaf's hash inputs, in order.
func LeafInputs(ca CA) []*big.Int {
	x, y := Limbs128(ca.X), Limbs128(ca.Y)
	return []*big.Int{
		big.NewInt(tagLeaf), big.NewInt(FormatVersion), big.NewInt(KeyTypeP384),
		x[0], x[1], x[2], y[0], y[1], y[2],
		big.NewInt(ca.NotBefore), big.NewInt(ca.NotAfter),
	}
}

// FromCertificate reads a CA entry from a DER certificate with a P-384 key.
func FromCertificate(der []byte) (CA, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return CA{}, err
	}
	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P384() {
		return CA{}, fmt.Errorf("%s: not a P-384 key", cert.Subject)
	}
	nb, na := cert.NotBefore.Unix(), cert.NotAfter.Unix()
	if nb < 0 || na < 0 {
		return CA{}, fmt.Errorf("%s: validity before 1970", cert.Subject)
	}
	sum := sha256.Sum256(der)
	return CA{X: key.X, Y: key.Y, NotBefore: nb, NotAfter: na, CertSHA256: hex.EncodeToString(sum[:])}, nil
}

// Tree is a built tree: its levels, leaves first.
type Tree struct {
	hasher *Hasher
	// Entries in leaf order (sorted by leaf hash), without the padding.
	Entries []CA
	levels  [][]*big.Int
}

// Build builds the tree over the given certificates' CA entries. Certificates
// without a P-384 key are skipped and returned, with the reason.
func Build(curve ecc.ID, certificates [][]byte) (*Tree, []string, error) {
	h, err := NewHasher(curve)
	if err != nil {
		return nil, nil, err
	}
	type leaf struct {
		ca   CA
		hash *big.Int
	}
	var leaves []leaf
	var skipped []string
	seen := map[string]bool{}
	for _, der := range certificates {
		ca, err := FromCertificate(der)
		if err != nil {
			skipped = append(skipped, err.Error())
			continue
		}
		v, err := h.Hash(LeafInputs(ca)...)
		if err != nil {
			return nil, nil, err
		}
		if seen[v.String()] {
			continue // the same key and validity, listed twice
		}
		seen[v.String()] = true
		leaves = append(leaves, leaf{ca, v})
	}
	if len(leaves) > Capacity {
		return nil, nil, fmt.Errorf("%d eligible certificates; tree format %d holds at most %d", len(leaves), FormatVersion, Capacity)
	}
	sort.Slice(leaves, func(i, j int) bool { return leaves[i].hash.Cmp(leaves[j].hash) < 0 })

	empty, err := h.Hash(big.NewInt(tagEmpty))
	if err != nil {
		return nil, nil, err
	}
	t := &Tree{hasher: h}
	level := make([]*big.Int, Capacity)
	for i := range level {
		if i < len(leaves) {
			level[i] = leaves[i].hash
			t.Entries = append(t.Entries, leaves[i].ca)
		} else {
			level[i] = empty
		}
	}
	t.levels = append(t.levels, level)
	for len(level) > 1 {
		next := make([]*big.Int, len(level)/2)
		for i := range next {
			if next[i], err = h.Hash(big.NewInt(tagNode), level[2*i], level[2*i+1]); err != nil {
				return nil, nil, err
			}
		}
		t.levels = append(t.levels, next)
		level = next
	}
	return t, skipped, nil
}

// Root is the tree's root.
func (t *Tree) Root() *big.Int { return t.levels[Depth][0] }

// Proof is a membership proof: the entry, its leaf index, and the sibling
// hashes from the leaf up.
type Proof struct {
	CA       CA
	Index    int
	Siblings [Depth]*big.Int
}

// Prove returns the membership proof of the certificate with the given
// SHA-256 (hex), or an error if it is not in the tree.
func (t *Tree) Prove(certSHA256 string) (Proof, error) {
	for i, ca := range t.Entries {
		if ca.CertSHA256 != certSHA256 {
			continue
		}
		p := Proof{CA: ca, Index: i}
		idx := i
		for d := 0; d < Depth; d++ {
			p.Siblings[d] = t.levels[d][idx^1]
			idx >>= 1
		}
		return p, nil
	}
	return Proof{}, fmt.Errorf("certificate %s is not in the tree", certSHA256)
}

// Verify recomputes the root from a proof (the circuit's computation, natively).
func (t *Tree) Verify(p Proof) (*big.Int, error) { return VerifyWith(t.hasher, p) }

// VerifyWith recomputes the root from a proof with a given hasher.
func VerifyWith(h *Hasher, p Proof) (*big.Int, error) {
	cur, err := h.Hash(LeafInputs(p.CA)...)
	if err != nil {
		return nil, err
	}
	idx := p.Index
	for d := 0; d < Depth; d++ {
		left, right := cur, p.Siblings[d]
		if idx&1 == 1 {
			left, right = p.Siblings[d], cur
		}
		if cur, err = h.Hash(big.NewInt(tagNode), left, right); err != nil {
			return nil, err
		}
		idx >>= 1
	}
	return cur, nil
}
