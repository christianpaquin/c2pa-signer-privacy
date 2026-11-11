package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"c2pa-zk-gnark/issuertree"
	"c2pa-zk-gnark/statement"
)

// A proof must be exactly the input: truncated or extended inputs (a signer
// certificate appended, say) are rejected.
func TestReadProofRejectsTrailingAndTruncatedData(t *testing.T) {
	var buf bytes.Buffer
	if _, err := groth16.NewProof(ecc.BN254).WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	proof := buf.Bytes()
	if _, err := readProof(proof, ecc.BN254); err != nil {
		t.Fatalf("a well-formed proof was rejected: %v", err)
	}
	for name, data := range map[string][]byte{
		"appended certificate": append(append([]byte{}, proof...), 0x30, 0x82, 0x02, 0x00),
		"one extra byte":       append(append([]byte{}, proof...), 0),
		"truncated":            proof[:len(proof)-1],
		"empty":                nil,
	} {
		if _, err := readProof(data, ecc.BN254); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type squareCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *squareCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X), c.Y)
	return nil
}

// Every proving-key format and checking mode loads the same key, a dump
// cannot be "validated", and a file that does not match keys.json is
// refused before it is parsed.
func TestProvingKeyFormatsLoadTheSameKey(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &squareCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	pk, _, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	m := manifest{SHA256: map[string]string{}}
	sum, err := writeFile(filepath.Join(dir, pkFile), pk)
	if err != nil {
		t.Fatal(err)
	}
	m.SHA256[pkFile] = sum
	data, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, manifestFile), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := convertPK(dir); err != nil {
		t.Fatal(err)
	}
	m, err = readManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	if _, err := pk.WriteTo(&want); err != nil {
		t.Fatal(err)
	}
	for _, mode := range [][2]string{{"compressed", "full"}, {"compressed", "none"}, {"raw", "full"}, {"raw", "none"}, {"dump", "none"}} {
		loaded, err := loadProvingKey(dir, m, mode[0], mode[1])
		if err != nil {
			t.Fatalf("%v: %v", mode, err)
		}
		var got bytes.Buffer
		if _, err := loaded.WriteTo(&got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Bytes(), want.Bytes()) {
			t.Errorf("%v: a different key was loaded", mode)
		}
	}
	if _, err := loadProvingKey(dir, m, "dump", "full"); err == nil {
		t.Error("a dump was loaded with --pk-check full")
	}
	raw := filepath.Join(dir, pkFiles["raw"])
	contents, _ := os.ReadFile(raw)
	contents[len(contents)/2] ^= 1
	if err := os.WriteFile(raw, contents, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProvingKey(dir, m, "raw", "none"); err == nil || !strings.Contains(err.Error(), "does not match keys.json") {
		t.Errorf("a modified key file was not refused by its hash: %v", err)
	}
}

// convertedKeys sets up a small circuit's keys directory with converted keys (BN254).
func convertedKeys(t *testing.T) (string, manifest) { t.Helper(); return convertedKeysOn(t, "bn254") }

// convertedKeysOn sets up a small circuit's keys directory on a curve, with converted keys.
func convertedKeysOn(t *testing.T, curveName string) (string, manifest) {
	t.Helper()
	curve, err := curveID(curveName)
	if err != nil {
		t.Fatal(err)
	}
	ccs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, &squareCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	pk, _, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	m := manifest{Curve: curveName, SHA256: map[string]string{}}
	if m.SHA256[pkFile], err = writeFile(filepath.Join(dir, pkFile), pk); err != nil {
		t.Fatal(err)
	}
	writeManifest(t, dir, m)
	if err := convertPK(dir); err != nil {
		t.Fatal(err)
	}
	m, err = readManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, m
}

func writeManifest(t *testing.T, dir string, m manifest) {
	t.Helper()
	data, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, manifestFile), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Unchecked loading needs a provenance record that matches the file and this
// gnark version; it is refused otherwise, with no fallback. Full checks need
// no record.
func TestUncheckedLoadingNeedsProvenance(t *testing.T) {
	dir, m := convertedKeys(t)
	if m.ProvingKeys["raw"].Source != "converted" || m.ProvingKeys["raw"].SourceSHA256 != m.SHA256[pkFile] || m.ProvingKeys["compressed"].Source != "setup" {
		t.Fatalf("unexpected provenance records: %+v", m.ProvingKeys)
	}
	if _, err := loadProvingKey(dir, m, "raw", "none"); err != nil {
		t.Fatalf("a key with matching provenance was refused: %v", err)
	}
	refused := func(name string, edit func(m *manifest)) {
		mm := m
		mm.ProvingKeys = map[string]keyFile{}
		for k, v := range m.ProvingKeys {
			mm.ProvingKeys[k] = v
		}
		edit(&mm)
		if _, err := loadProvingKey(dir, mm, "raw", "none"); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Errorf("%s: not refused (%v)", name, err)
		}
		if _, err := loadProvingKey(dir, mm, "raw", "full"); err != nil {
			t.Errorf("%s: full checks were refused too: %v", name, err)
		}
	}
	refused("no record", func(m *manifest) { delete(m.ProvingKeys, "raw") })
	refused("other gnark version", func(m *manifest) { r := m.ProvingKeys["raw"]; r.GnarkVersion = "v0.0.1"; m.ProvingKeys["raw"] = r })
	refused("record for another file", func(m *manifest) {
		r := m.ProvingKeys["raw"]
		r.SHA256 = strings.Repeat("0", 64)
		m.ProvingKeys["raw"] = r
	})
	refused("unknown source", func(m *manifest) { r := m.ProvingKeys["raw"]; r.Source = "downloaded"; m.ProvingKeys["raw"] = r })
	// Valid records, but for another key: the record must describe the file loaded.
	refused("the compressed key's record", func(m *manifest) { m.ProvingKeys["raw"] = m.ProvingKeys["compressed"] })
	refused("the dump's record", func(m *manifest) { m.ProvingKeys["raw"] = m.ProvingKeys["dump"] })
	refused("only the format label changed", func(m *manifest) { r := m.ProvingKeys["raw"]; r.Format = "dump"; m.ProvingKeys["raw"] = r })
	refused("only the file name changed", func(m *manifest) { r := m.ProvingKeys["raw"]; r.File = pkFile; m.ProvingKeys["raw"] = r })
}

// A file that changes between the hashing and parsing passes is rejected,
// as is one with bytes after its contents (even if keys.json covers them).
func TestStreamedLoadingRejectsChangesAndTrailingBytes(t *testing.T) {
	dir, m := convertedKeys(t)
	raw := filepath.Join(dir, pkFiles["raw"])
	original, _ := os.ReadFile(raw)

	betweenPasses = func(path string) {
		data, _ := os.ReadFile(path)
		data[len(data)/2] ^= 1 // inside point data, which an unchecked parser accepts
		_ = os.WriteFile(path, data, 0o644)
	}
	_, err := loadProvingKey(dir, m, "raw", "none")
	betweenPasses = func(string) {}
	if err == nil || !strings.Contains(err.Error(), "changed while it was being loaded") {
		t.Errorf("a change between the passes was not detected: %v", err)
	}

	extended := append(append([]byte{}, original...), 0x30, 0x82, 0x01, 0x00)
	if err := os.WriteFile(raw, extended, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(extended)
	m.SHA256[pkFiles["raw"]] = hex.EncodeToString(sum[:])
	r := m.ProvingKeys["raw"]
	r.SHA256 = m.SHA256[pkFiles["raw"]]
	m.ProvingKeys["raw"] = r
	if _, err := loadProvingKey(dir, m, "raw", "none"); err == nil || !strings.Contains(err.Error(), "bytes after its contents") {
		t.Errorf("trailing bytes were not rejected: %v", err)
	}
}

// A BLS12-381 key set (roadmap E7): every format loads, a proof made with it
// verifies, and keys or proofs of the other curve are refused.
func TestBLS12381KeySets(t *testing.T) {
	dir, m := convertedKeysOn(t, "bls12-381")
	if m.curve() != ecc.BLS12_381 {
		t.Fatalf("curve %v", m.curve())
	}
	for _, mode := range [][2]string{{"compressed", "full"}, {"raw", "none"}, {"dump", "none"}} {
		if _, err := loadProvingKey(dir, m, mode[0], mode[1]); err != nil {
			t.Errorf("%v: %v", mode, err)
		}
	}
	// The same file read as the other curve's key is refused.
	bn := m
	bn.Curve = "bn254"
	if _, err := loadProvingKey(dir, bn, "compressed", "full"); err == nil {
		t.Error("a BLS12-381 proving key was loaded as a BN254 key")
	}
	// A proof on one curve is not a proof on the other.
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &squareCircuit{})
	pk, _, _ := groth16.Setup(ccs)
	w, _ := frontend.NewWitness(&squareCircuit{X: 3, Y: 9}, ecc.BN254.ScalarField())
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	if _, err := readProof(buf.Bytes(), ecc.BLS12_381); err == nil {
		t.Error("a BN254 proof was read as a BLS12-381 proof")
	}
	if _, err := readProof(buf.Bytes(), ecc.BN254); err != nil {
		t.Errorf("the BN254 proof itself was rejected: %v", err)
	}
	// An unknown curve in keys.json is refused when the keys are read.
	m.Curve = "secp256k1"
	writeManifest(t, dir, m)
	if _, err := readManifest(dir); err == nil {
		t.Error("an unknown curve was accepted")
	}
}

// The statement belongs to the key set: key sets from before H4 are the
// disclosed statement, and an unknown statement is refused.
func TestStatementIsPartOfTheKeySet(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, manifest{Statement: "old", Curve: "bn254"})
	m, err := readManifest(dir)
	if err != nil || m.variant() != variantDisclosed {
		t.Fatalf("a key set without a variant: %v, %q", err, m.variant())
	}
	writeManifest(t, dir, manifest{Statement: "x", Curve: "bn254", Variant: "hidden-everything"})
	if _, err := readManifest(dir); err == nil {
		t.Fatal("an unknown statement was accepted")
	}
	if err := setup(t.TempDir(), "bn254", "hidden-everything"); err == nil {
		t.Fatal("setup accepted an unknown statement")
	}
}

// --issuers is required by the hidden-issuer statement and refused by the
// disclosed one, so a mistaken invocation never silently proves the other.
func TestIssuersFlagMatchesTheStatement(t *testing.T) {
	var in statementInputs
	if _, err := assignment(in.Inputs, smallSizes, statement.DefaultTokenSizes, ecc.BN254, variantDisclosed, proverOptions{issuers: "issuers.pem"}); err == nil || !strings.Contains(err.Error(), "only to the hidden-issuer and hidden-all") {
		t.Fatalf("disclosed statement with --issuers: %v", err)
	}
	if _, err := assignment(in.Inputs, smallSizes, statement.DefaultTokenSizes, ecc.BN254, variantHidden, proverOptions{}); err == nil || !strings.Contains(err.Error(), "needs --issuers") {
		t.Fatalf("hidden issuer without --issuers: %v", err)
	}
}

func TestIssuerTreeReadsPEMCertificates(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.pem")
	os.WriteFile(empty, []byte("no certificates here\n"), 0o644)
	if _, _, err := issuerTree(empty, ecc.BN254, issuertree.RoleIssuer); err == nil {
		t.Fatal("a file without certificates was accepted")
	}
	pemFile := filepath.Join(dir, "issuers.pem")
	var buf bytes.Buffer
	for _, der := range testCAs(t, 3) {
		pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	os.WriteFile(pemFile, buf.Bytes(), 0o644)
	tree, _, err := issuerTree(pemFile, ecc.BN254, issuertree.RoleIssuer)
	if err != nil || len(tree.Entries) != 3 {
		t.Fatalf("tree from 3 certificates: %v", err)
	}
}

type statementInputs struct{ Inputs statement.Inputs }

var smallSizes = statement.Sizes{MaxProtected: 1536, MaxClaim: 512, MaxTBS: 768, MaxExtensions: 8, MaxEKUs: 4}

func testCAs(t *testing.T, n int) [][]byte {
	t.Helper()
	var out [][]byte
	for i := 0; i < n; i++ {
		key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: "CLI Test CA"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, der)
	}
	return out
}

// --tsa-issuers applies only to hidden-all, which needs both lists.
func TestTSAIssuersFlagMatchesTheStatement(t *testing.T) {
	var in statementInputs
	for _, v := range []string{variantDisclosed, variantHidden} {
		if _, err := assignment(in.Inputs, smallSizes, statement.DefaultTokenSizes, ecc.BN254, v, proverOptions{issuers: "i.pem", tsaIssuers: "t.pem"}); err == nil || !strings.Contains(err.Error(), "only to the hidden-all") {
			t.Fatalf("%s with --tsa-issuers: %v", v, err)
		}
	}
	for _, o := range []proverOptions{{issuers: "i.pem"}, {tsaIssuers: "t.pem"}} {
		if _, err := assignment(in.Inputs, smallSizes, statement.DefaultTokenSizes, ecc.BN254, variantHiddenAll, o); err == nil || !strings.Contains(err.Error(), "needs --issuers and --tsa-issuers") {
			t.Fatalf("hidden-all with %+v: %v", o, err)
		}
	}
	if err := checkVariant(variantHiddenAll); err != nil {
		t.Fatal(err)
	}
}
