package statement

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
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
	"github.com/consensys/gnark/std/math/emulated"

	"c2pa-zk-gnark/issuertree"
)

var compiledHidden = map[ecc.ID]*compiledCircuit{ecc.BN254: {}, ecc.BLS12_381: {}}

func hiddenCircuitOn(t *testing.T, curve ecc.ID) constraint.ConstraintSystem {
	t.Helper()
	c := compiledHidden[curve]
	c.once.Do(func() {
		c.ccs, c.err = frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, NewHiddenIssuerCircuit(testSizes))
	})
	if c.err != nil {
		t.Fatal(c.err)
	}
	return c.ccs
}

func hiddenSolvedOn(t *testing.T, curve ecc.ID, c *HiddenIssuerCircuit) bool {
	t.Helper()
	w, err := frontend.NewWitness(c, curve.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return hiddenCircuitOn(t, curve).IsSolved(w) == nil
}

// otherCAs are P-384 CA certificates that did not issue the fixture's signer.
var otherCAs = sync.OnceValue(func() [][]byte {
	var out [][]byte
	for i := 0; i < 6; i++ {
		key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: "Other CA"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour * 365),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			panic(err)
		}
		out = append(out, der)
	}
	return out
})

// treeWith builds the issuer tree over the given CA certificates and the others.
func treeWith(t *testing.T, curve ecc.ID, certs ...[]byte) *issuertree.Tree {
	t.Helper()
	tree, _, err := issuertree.Build(curve, append(append([][]byte{}, otherCAs()...), certs...))
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func assignHidden(t *testing.T, in Inputs, tree *issuertree.Tree) *HiddenIssuerCircuit {
	t.Helper()
	c, err := AssignHidden(in, tree, testSizes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func certSHA256(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func TestHiddenIssuerStatementIsAccepted(t *testing.T) {
	forEachCurve(t, func(t *testing.T, curve ecc.ID) {
		f := newFixture(t, fixtureOptions{})
		if !hiddenSolvedOn(t, curve, assignHidden(t, f.in, treeWith(t, curve, f.in.IssuerCert))) {
			t.Fatal("valid hidden-issuer statement rejected")
		}
		t.Logf("%d constraints at test sizes (disclosed CA: %d)", hiddenCircuitOn(t, curve).GetNbConstraints(), testCircuitOn(t, curve).GetNbConstraints())
	})
}

// The in-circuit leaf and path hashing agree with the tree builder: a valid
// assignment's root is the builder's, and any other root is rejected.
func TestHiddenIssuerMembershipIsEnforced(t *testing.T) {
	forEachCurve(t, func(t *testing.T, curve ecc.ID) {
		f := newFixture(t, fixtureOptions{})
		tree := treeWith(t, curve, f.in.IssuerCert)
		valid := assignHidden(t, f.in, tree)

		withoutCA := treeWith(t, curve) // the same list without the issuing CA
		cases := map[string]func(c *HiddenIssuerCircuit){
			"root of a list without the CA": func(c *HiddenIssuerCircuit) { c.Root = withoutCA.Root() },
			"a sibling changed": func(c *HiddenIssuerCircuit) {
				c.Siblings[3] = new(big.Int).Add(c.Siblings[3].(*big.Int), big.NewInt(1))
			},
			"an index bit flipped":     func(c *HiddenIssuerCircuit) { c.IndexBits[0] = 1 - c.IndexBits[0].(int) },
			"an index bit not boolean": func(c *HiddenIssuerCircuit) { c.IndexBits[0] = 2 },
			"CA validity changed":      func(c *HiddenIssuerCircuit) { c.CANotAfter = c.CANotAfter.(int64) + 1 },
		}
		for name, tamper := range cases {
			c := *valid
			tamper(&c)
			if hiddenSolvedOn(t, curve, &c) {
				t.Errorf("%s: accepted", name)
			}
		}

		// A listed CA that did not issue the signer's certificate: its own
		// valid membership proof, but its key does not verify the TBS.
		other := otherCAs()[0]
		proof, err := tree.Prove(certSHA256(other))
		if err != nil {
			t.Fatal(err)
		}
		c := *valid
		setMembership(&c, proof)
		if hiddenSolvedOn(t, curve, &c) {
			t.Error("a listed CA that did not issue the certificate: accepted")
		}
	})
}

// The CA's validity, from its leaf, must contain t: a tree listing the same
// CA key with a validity period that ended before t is rejected, with an
// otherwise valid membership proof.
func TestHiddenIssuerCAValidityIsEnforced(t *testing.T) {
	forEachCurve(t, func(t *testing.T, curve ecc.ID) {
		f := newFixture(t, fixtureOptions{})
		valid := assignHidden(t, f.in, treeWith(t, curve, f.in.IssuerCert))
		ca, err := issuertree.FromCertificate(f.in.IssuerCert)
		if err != nil {
			t.Fatal(err)
		}
		for name, change := range map[string]func(ca *issuertree.CA){
			"CA expired before t":   func(ca *issuertree.CA) { ca.NotAfter = f.in.Time - 1 },
			"CA not yet valid at t": func(ca *issuertree.CA) { ca.NotBefore = f.in.Time + 1 },
		} {
			changed := ca
			change(&changed)
			root, proof := singleEntryTree(t, curve, changed)
			c := *valid
			setMembership(&c, proof)
			c.Root = root
			if hiddenSolvedOn(t, curve, &c) {
				t.Errorf("%s: accepted", name)
			}
		}
		// The boundaries are inclusive.
		for name, change := range map[string]func(ca *issuertree.CA){
			"t at the CA's notAfter":  func(ca *issuertree.CA) { ca.NotAfter = f.in.Time },
			"t at the CA's notBefore": func(ca *issuertree.CA) { ca.NotBefore = f.in.Time },
		} {
			changed := ca
			change(&changed)
			root, proof := singleEntryTree(t, curve, changed)
			c := *valid
			setMembership(&c, proof)
			c.Root = root
			if !hiddenSolvedOn(t, curve, &c) {
				t.Errorf("%s: rejected", name)
			}
		}
	})
}

// The disclosed statement's checks still hold with the issuer hidden.
func TestHiddenIssuerKeepsTheStatementsChecks(t *testing.T) {
	forEachCurve(t, func(t *testing.T, curve ecc.ID) {
		f := newFixture(t, fixtureOptions{})
		tree := treeWith(t, curve, f.in.IssuerCert)
		for name, tamper := range map[string]func(in *Inputs){
			"claim byte":            func(in *Inputs) { in.Claim[100] ^= 1 },
			"imprint":               func(in *Inputs) { in.Imprint[31] ^= 1 },
			"time after notAfter":   func(in *Inputs) { in.Time = f.notAfter.Unix() + 1 },
			"time before notBefore": func(in *Inputs) { in.Time = f.notBefore.Unix() - 1 },
		} {
			in := f.in
			in.Claim = append([]byte{}, f.in.Claim...)
			in.Imprint = append([]byte{}, f.in.Imprint...)
			tamper(&in)
			if hiddenSolvedOn(t, curve, assignHidden(t, in, tree)) {
				t.Errorf("%s: accepted", name)
			}
		}
		c := assignHidden(t, f.in, tree)
		c.ClaimSig[40] = c.ClaimSig[40].(byte) ^ 1
		if hiddenSolvedOn(t, curve, c) {
			t.Error("claim signature changed: accepted")
		}
	})
}

func TestAssignHiddenRefusesACANotInTheTree(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	if _, err := AssignHidden(f.in, treeWith(t, ecc.BN254), testSizes); err == nil {
		t.Fatal("assigned with an issuing CA missing from the tree")
	}
	if _, err := AssignHiddenPublic(HiddenPublic{Claim: f.in.Claim, Root: "not hex", Time: f.in.Time, Imprint: f.in.Imprint}, testSizes); err == nil {
		t.Fatal("accepted a root that is not hex")
	}
}

// A real Groth16 proof of the hidden-issuer statement at test sizes
// (minutes): C2PA_ZK_GROTH16=1. The verifier's public inputs hold only the
// root; a proof does not verify against another list's root.
func TestHiddenIssuerGroth16ProofVerifies(t *testing.T) {
	if os.Getenv("C2PA_ZK_GROTH16") == "" {
		t.Skip("set C2PA_ZK_GROTH16=1 to run a real setup, proof, and verification")
	}
	ccs := hiddenCircuitOn(t, ecc.BN254)
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, fixtureOptions{})
	tree := treeWith(t, ecc.BN254, f.in.IssuerCert)
	w, _ := frontend.NewWitness(assignHidden(t, f.in, tree), ecc.BN254.ScalarField())
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(root string) error {
		pub, err := AssignHiddenPublic(HiddenPublic{Claim: f.in.Claim, Root: root, Time: f.in.Time, Imprint: f.in.Imprint}, testSizes)
		if err != nil {
			t.Fatal(err)
		}
		pw, _ := frontend.NewWitness(pub, ecc.BN254.ScalarField(), frontend.PublicOnly())
		return groth16.Verify(proof, vk, pw)
	}
	if err := verify(tree.Root().Text(16)); err != nil {
		t.Fatal(err)
	}
	if verify(treeWith(t, ecc.BN254).Root().Text(16)) == nil {
		t.Fatal("proof verified against another list's root")
	}
}

// setMembership replaces an assignment's CA, validity, and path with a proof's.
func setMembership(c *HiddenIssuerCircuit, p issuertree.Proof) {
	c.CAKey.X = emulated.ValueOf[emulated.P384Fp](p.CA.X)
	c.CAKey.Y = emulated.ValueOf[emulated.P384Fp](p.CA.Y)
	c.CANotBefore, c.CANotAfter = p.CA.NotBefore, p.CA.NotAfter
	for d := 0; d < issuertree.Depth; d++ {
		c.Siblings[d] = p.Siblings[d]
		c.IndexBits[d] = (p.Index >> d) & 1
	}
}

// singleEntryTree is the root and membership proof of a tree with one CA
// entry and empty leaves, computed with the tree format's hash.
func singleEntryTree(t *testing.T, curve ecc.ID, ca issuertree.CA) (*big.Int, issuertree.Proof) {
	t.Helper()
	h, err := issuertree.NewHasher(curve)
	if err != nil {
		t.Fatal(err)
	}
	empty, _ := h.Hash(big.NewInt(3))
	p := issuertree.Proof{CA: ca, Index: 0}
	sibling := empty
	for d := 0; d < issuertree.Depth; d++ {
		p.Siblings[d] = sibling
		sibling, _ = h.Hash(big.NewInt(2), sibling, sibling)
	}
	root, err := issuertree.VerifyWith(h, p)
	if err != nil {
		t.Fatal(err)
	}
	return root, p
}
