package statement

import (
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"c2pa-zk-gnark/issuertree"
)

var compiledHiddenAll = map[ecc.ID]*compiledCircuit{ecc.BN254: {}, ecc.BLS12_381: {}}

func hiddenAllOn(t *testing.T, curve ecc.ID) *compiledCircuit {
	t.Helper()
	c := compiledHiddenAll[curve]
	c.once.Do(func() {
		c.ccs, c.err = frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, NewHiddenAllCircuit(testSizes, DefaultTokenSizes))
	})
	if c.err != nil {
		t.Fatal(c.err)
	}
	return c
}

func hiddenAllSolved(t *testing.T, curve ecc.ID, c *HiddenAllCircuit) bool {
	t.Helper()
	w, err := frontend.NewWitness(c, curve.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return hiddenAllOn(t, curve).ccs.IsSolved(w) == nil
}

// cmsToken wraps a token's parts as an RFC 3161 TimeStampToken (CMS
// SignedData), as a TSA returns it, for ParseToken.
func cmsToken(t *testing.T, f *tokenFixture) []byte {
	t.Helper()
	oid := func(o asn1.ObjectIdentifier) []byte { return mustMarshal(t, o) }
	r, s := new(big.Int).SetBytes(f.parts.TSASig[:32]), new(big.Int).SetBytes(f.parts.TSASig[32:])
	sigDER := mustMarshal(t, struct{ R, S *big.Int }{r, s})
	attrs := append([]byte{0xa0}, f.parts.SignedAttrs[1:]...) // [0] IMPLICIT in the SignerInfo
	signerInfo := tlv(0x30,
		[]byte{0x02, 0x01, 0x01},
		tlv(0x30, tlv(0x30), []byte{0x02, 0x01, 0x01}), // issuerAndSerialNumber (not used)
		tlv(0x30, oid(oidSHA256)),
		attrs,
		tlv(0x30, oid(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2})),
		tlv(0x04, sigDER),
	)
	signedData := tlv(0x30,
		[]byte{0x02, 0x01, 0x03},
		tlv(0x31, tlv(0x30, oid(oidSHA256))),
		tlv(0x30, oid(oidCTTSTInfo), tlv(0xa0, tlv(0x04, f.parts.TSTInfo))),
		tlv(0xa0, f.parts.TSACert),
		tlv(0x31, signerInfo),
	)
	return tlv(0x30, oid(oidSignedData), tlv(0xa0, signedData))
}

type hiddenAllFixture struct {
	in            Inputs
	issuers, tsas *issuertree.Tree
	token         *tokenFixture
	t1, t2        int64
}

// newHiddenAllFixture: the statement fixture with a time-stamp token over its
// imprint at its time, from a TSA whose CA is in a TSA tree of seven.
func newHiddenAllFixture(t *testing.T, curve ecc.ID) *hiddenAllFixture {
	t.Helper()
	f := newFixture(t, fixtureOptions{})
	tok := newToken(t, tokenOptions{genTime: time.Unix(f.in.Time, 0), imprint: f.in.Imprint})
	in := f.in
	in.TimeStampToken = cmsToken(t, tok)
	issuers := treeWith(t, curve, f.in.IssuerCert)
	tsas, _, err := issuertree.Build(curve, issuertree.RoleTSA, append(append([][]byte{}, otherCAs()...), tok.caDER))
	if err != nil {
		t.Fatal(err)
	}
	t1, t2 := Window(f.in.Time, 86400)
	return &hiddenAllFixture{in: in, issuers: issuers, tsas: tsas, token: tok, t1: t1, t2: t2}
}

func (h *hiddenAllFixture) assign(t *testing.T) *HiddenAllCircuit {
	t.Helper()
	c, err := AssignHiddenAll(h.in, h.issuers, h.tsas, h.t1, h.t2, testSizes, DefaultTokenSizes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestHiddenAllStatementIsAccepted(t *testing.T) {
	forEachCurve(t, func(t *testing.T, curve ecc.ID) {
		h := newHiddenAllFixture(t, curve)
		if !hiddenAllSolved(t, curve, h.assign(t)) {
			t.Fatal("valid statement rejected")
		}
		t.Logf("%d constraints at test sizes (hidden issuer: %d)", hiddenAllOn(t, curve).ccs.GetNbConstraints(), hiddenCircuitOn(t, curve).GetNbConstraints())
	})
}

// The trees' roles are fixed by the statement (option B,
// HIDING-THE-TIME-STAMP.md, T4): the same CAs built as the other role's tree,
// or the roots swapped, are rejected, though each path is valid in its own tree.
func TestHiddenAllRolesAreNotInterchangeable(t *testing.T) {
	forEachCurve(t, func(t *testing.T, curve ecc.ID) {
		h := newHiddenAllFixture(t, curve)
		valid := h.assign(t)
		sameCAs := append(append([][]byte{}, otherCAs()...), h.token.caDER)

		// The TSA CAs as an issuer-role tree, with a valid path in it.
		asIssuer, _, err := issuertree.Build(curve, issuertree.RoleIssuer, sameCAs)
		if err != nil {
			t.Fatal(err)
		}
		c := *valid
		setTSAMembership(t, &c, asIssuer, h.token.caDER)
		if hiddenAllSolved(t, curve, &c) {
			t.Error("a TSA CA proven in an issuer-role tree: accepted")
		}

		// The issuing CA as a TSA-role tree, with a valid path in it.
		issuerAsTSA, _, err := issuertree.Build(curve, issuertree.RoleTSA, append(append([][]byte{}, otherCAs()...), h.in.IssuerCert))
		if err != nil {
			t.Fatal(err)
		}
		c = *valid
		p, err := issuerAsTSA.Prove(certSHA256(h.in.IssuerCert))
		if err != nil {
			t.Fatal(err)
		}
		c.Root = issuerAsTSA.Root()
		for d := 0; d < issuertree.Depth; d++ {
			c.Siblings[d], c.IndexBits[d] = p.Siblings[d], (p.Index>>d)&1
		}
		if hiddenAllSolved(t, curve, &c) {
			t.Error("an issuing CA proven in a TSA-role tree: accepted")
		}

		// Swapped roots.
		c = *valid
		c.Root, c.TSARoot = valid.TSARoot, valid.Root
		if hiddenAllSolved(t, curve, &c) {
			t.Error("swapped roots: accepted")
		}
	})
}

// The token is bound to the statement: its imprint is the original
// signature's, its genTime is the statement's time, inside the window, and
// within the TSA CA's validity; its TSA CA is in the TSA tree.
func TestHiddenAllBindsTheToken(t *testing.T) {
	forEachCurve(t, func(t *testing.T, curve ecc.ID) {
		h := newHiddenAllFixture(t, curve)
		valid := h.assign(t)

		// A token over another imprint (another signature's), from the same TSA.
		other := sha256.Sum256([]byte("another signature"))
		otherToken := newToken(t, tokenOptions{genTime: time.Unix(h.in.Time, 0), imprint: other[:]})
		otherInputs, err := AssignToken(otherToken.parts, DefaultTokenSizes)
		if err != nil {
			t.Fatal(err)
		}
		c := *valid
		c.Token = otherInputs
		if hiddenAllSolved(t, curve, &c) {
			t.Error("a token over another imprint: accepted")
		}
		c.Imprint = [2]frontend.Variable{new(big.Int).SetBytes(other[:16]), new(big.Int).SetBytes(other[16:])}
		if hiddenAllSolved(t, curve, &c) {
			t.Error("a token over another imprint, with that imprint: accepted")
		}

		// A token at another time (one second later), same imprint.
		later := newToken(t, tokenOptions{genTime: time.Unix(h.in.Time+1, 0), imprint: h.in.Imprint})
		laterInputs, err := AssignToken(later.parts, DefaultTokenSizes)
		if err != nil {
			t.Fatal(err)
		}
		c = *valid
		c.Token = laterInputs
		if hiddenAllSolved(t, curve, &c) {
			t.Error("a token at another time than the statement's: accepted")
		}

		// genTime outside the window.
		c = *valid
		c.T1, c.T2 = h.in.Time-86400, h.in.Time
		if hiddenAllSolved(t, curve, &c) {
			t.Error("genTime = t2: accepted")
		}

		// A TSA tree without the token's CA.
		without, _, err := issuertree.Build(curve, issuertree.RoleTSA, otherCAs())
		if err != nil {
			t.Fatal(err)
		}
		c = *valid
		c.TSARoot = without.Root()
		if hiddenAllSolved(t, curve, &c) {
			t.Error("a TSA tree without the TSA CA: accepted")
		}

		// The TSA CA's validity in its leaf must contain genTime.
		ca, err := issuertree.FromCertificate(h.token.caDER)
		if err != nil {
			t.Fatal(err)
		}
		for name, change := range map[string]func(*issuertree.CA){
			"TSA CA expired before genTime":   func(ca *issuertree.CA) { ca.NotAfter = h.in.Time - 1 },
			"TSA CA not yet valid at genTime": func(ca *issuertree.CA) { ca.NotBefore = h.in.Time + 1 },
		} {
			changed := ca
			change(&changed)
			root, p := singleEntryTreeAs(t, curve, issuertree.RoleTSA, changed)
			c = *valid
			c.TSARoot = root
			c.TSACANotBefore, c.TSACANotAfter = changed.NotBefore, changed.NotAfter
			for d := 0; d < issuertree.Depth; d++ {
				c.TSASiblings[d], c.TSAIndexBits[d] = p.Siblings[d], (p.Index>>d)&1
			}
			if hiddenAllSolved(t, curve, &c) {
				t.Errorf("%s: accepted", name)
			}
		}

		// The statement's own checks still hold.
		in := h.in
		in.Claim = append([]byte{}, h.in.Claim...)
		in.Claim[100] ^= 1
		changed := *h
		changed.in = in
		cc, err := AssignHiddenAll(changed.in, h.issuers, h.tsas, h.t1, h.t2, testSizes, DefaultTokenSizes)
		if err != nil {
			t.Fatal(err)
		}
		if hiddenAllSolved(t, curve, cc) {
			t.Error("a changed claim byte: accepted")
		}
	})
}

func TestAssignHiddenAllRefusals(t *testing.T) {
	h := newHiddenAllFixture(t, ecc.BN254)
	if _, err := AssignHiddenAll(h.in, h.tsas, h.issuers, h.t1, h.t2, testSizes, DefaultTokenSizes); err == nil {
		t.Error("trees given in the wrong roles: assigned")
	}
	if _, err := AssignHiddenAll(h.in, h.issuers, h.tsas, h.t2, h.t2+86400, testSizes, DefaultTokenSizes); err == nil {
		t.Error("genTime outside the window: assigned")
	}
	in := h.in
	in.Time++
	if _, err := AssignHiddenAll(in, h.issuers, h.tsas, h.t1, h.t2, testSizes, DefaultTokenSizes); err == nil {
		t.Error("a token whose genTime is not the inputs' time: assigned")
	}
	pub := HiddenAllPublic{Claim: h.in.Claim, IssuerRoot: h.issuers.Root().Text(16), TSARoot: h.tsas.Root().Text(16), T1: h.t1, T2: h.t2}
	if _, err := AssignHiddenAllPublic(pub, testSizes, DefaultTokenSizes, ecc.BN254); err != nil {
		t.Errorf("valid public inputs refused: %v", err)
	}
	for name, change := range map[string]func(p *HiddenAllPublic){
		"an empty window":          func(p *HiddenAllPublic) { p.T2 = p.T1 },
		"a negative start":         func(p *HiddenAllPublic) { p.T1 = -1 },
		"an end beyond 2^34":       func(p *HiddenAllPublic) { p.T2 = 1 << timeBits },
		"a non-canonical TSA root": func(p *HiddenAllPublic) { p.TSARoot = "0" + p.TSARoot },
	} {
		p := pub
		change(&p)
		if _, err := AssignHiddenAllPublic(p, testSizes, DefaultTokenSizes, ecc.BN254); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// setTSAMembership sets the TSA CA's membership from a tree containing caDER.
func setTSAMembership(t *testing.T, c *HiddenAllCircuit, tree *issuertree.Tree, caDER []byte) {
	t.Helper()
	p, err := tree.Prove(certSHA256(caDER))
	if err != nil {
		t.Fatal(err)
	}
	c.TSARoot = tree.Root()
	for d := 0; d < issuertree.Depth; d++ {
		c.TSASiblings[d], c.TSAIndexBits[d] = p.Siblings[d], (p.Index>>d)&1
	}
}

// singleEntryTreeAs is the root and proof of a role's tree with one entry.
func singleEntryTreeAs(t *testing.T, curve ecc.ID, role issuertree.Role, ca issuertree.CA) (*big.Int, issuertree.Proof) {
	t.Helper()
	h, err := issuertree.NewHasher(curve)
	if err != nil {
		t.Fatal(err)
	}
	empty, _ := h.Hash(big.NewInt(3))
	p := issuertree.Proof{CA: ca}
	sibling := empty
	for d := 0; d < issuertree.Depth; d++ {
		p.Siblings[d] = sibling
		sibling, _ = h.Hash(big.NewInt(2), sibling, sibling)
	}
	root, err := issuertree.VerifyWith(h, role, p)
	if err != nil {
		t.Fatal(err)
	}
	return root, p
}
