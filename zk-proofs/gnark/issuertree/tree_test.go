package issuertree

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
)

// caCert is a self-signed CA certificate with a key on the given curve.
func caCert(t *testing.T, curve elliptic.Curve, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Tree Test CA"},
		NotBefore: notBefore, NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func cas(t *testing.T, n int) [][]byte {
	now := time.Now()
	var out [][]byte
	for i := 0; i < n; i++ {
		out = append(out, caCert(t, elliptic.P384(), now.Add(-time.Hour), now.Add(time.Duration(i+1)*24*time.Hour)))
	}
	return out
}

func TestLimbs128(t *testing.T) {
	v, _ := new(big.Int).SetString("fedcba9876543210fedcba9876543210"+"0123456789abcdef0123456789abcdef"+"00112233445566778899aabbccddeeff", 16)
	l := Limbs128(v)
	want := []string{"fedcba9876543210fedcba9876543210", "123456789abcdef0123456789abcdef", "112233445566778899aabbccddeeff"}
	for i := range l {
		if l[i].Text(16) != want[i] {
			t.Errorf("limb %d = %s, want %s", i, l[i].Text(16), want[i])
		}
	}
}

func TestRootIsIndependentOfInputOrderAndDuplicates(t *testing.T) {
	for _, curve := range []ecc.ID{ecc.BN254, ecc.BLS12_381} {
		certs := cas(t, 5)
		a, _, err := Build(curve, certs)
		if err != nil {
			t.Fatal(err)
		}
		reversed := [][]byte{certs[4], certs[3], certs[2], certs[1], certs[0], certs[2]} // and a duplicate
		b, _, err := Build(curve, reversed)
		if err != nil {
			t.Fatal(err)
		}
		if a.Root().Cmp(b.Root()) != 0 || len(b.Entries) != 5 {
			t.Fatalf("%s: roots differ or duplicate kept (%d entries)", curve, len(b.Entries))
		}
		// Every entry's proof recomputes the root.
		for _, e := range a.Entries {
			p, err := a.Prove(e.CertSHA256)
			if err != nil {
				t.Fatal(err)
			}
			root, err := a.Verify(p)
			if err != nil || root.Cmp(a.Root()) != 0 {
				t.Fatalf("%s: proof of entry %d does not recompute the root", curve, p.Index)
			}
		}
	}
}

func TestRootDependsOnEveryEntryAndTheCurve(t *testing.T) {
	certs := cas(t, 3)
	full, _, _ := Build(ecc.BN254, certs)
	fewer, _, _ := Build(ecc.BN254, certs[:2])
	other, _, _ := Build(ecc.BLS12_381, certs)
	if full.Root().Cmp(fewer.Root()) == 0 {
		t.Fatal("removing an entry kept the root")
	}
	if full.Root().Cmp(other.Root()) == 0 {
		t.Fatal("BN254 and BLS12-381 roots are equal")
	}
	// The same key with another validity period (a renewal) is another leaf.
	ca, _ := FromCertificate(certs[0])
	renewed := ca
	renewed.NotAfter++
	h, _ := NewHasher(ecc.BN254)
	a, _ := h.Hash(LeafInputs(ca)...)
	b, _ := h.Hash(LeafInputs(renewed)...)
	if a.Cmp(b) == 0 {
		t.Fatal("validity is not part of the leaf")
	}
}

func TestNonP384KeysAreSkippedAndCapacityIsEnforced(t *testing.T) {
	now := time.Now()
	certs := append(cas(t, 2), caCert(t, elliptic.P256(), now, now.Add(time.Hour)))
	tree, skipped, err := Build(ecc.BN254, certs)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Entries) != 2 || len(skipped) != 1 {
		t.Fatalf("%d entries, %d skipped; want 2 and 1", len(tree.Entries), len(skipped))
	}
	if _, err := tree.Prove("00"); err == nil {
		t.Fatal("proof for a certificate not in the tree")
	}
	if testing.Short() {
		return
	}
	if _, _, err := Build(ecc.BN254, cas(t, Capacity+1)); err == nil {
		t.Fatalf("%d entries accepted; capacity is %d", Capacity+1, Capacity)
	}
}

func TestHashRejectsOutOfFieldElements(t *testing.T) {
	h, _ := NewHasher(ecc.BN254)
	if _, err := h.Hash(ecc.BN254.ScalarField()); err == nil {
		t.Fatal("the field modulus was accepted as an element")
	}
	if _, err := h.Hash(big.NewInt(-1)); err == nil {
		t.Fatal("a negative element was accepted")
	}
}
