package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// A proof must be exactly the input: truncated or extended inputs (a signer
// certificate appended, say) are rejected.
func TestReadProofRejectsTrailingAndTruncatedData(t *testing.T) {
	var buf bytes.Buffer
	if _, err := groth16.NewProof(ecc.BN254).WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	proof := buf.Bytes()
	if _, err := readProof(proof); err != nil {
		t.Fatalf("a well-formed proof was rejected: %v", err)
	}
	for name, data := range map[string][]byte{
		"appended certificate": append(append([]byte{}, proof...), 0x30, 0x82, 0x02, 0x00),
		"one extra byte":       append(append([]byte{}, proof...), 0),
		"truncated":            proof[:len(proof)-1],
		"empty":                nil,
	} {
		if _, err := readProof(data); err == nil {
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

// convertedKeys sets up a small circuit's keys directory with converted keys.
func convertedKeys(t *testing.T) (string, manifest) {
	t.Helper()
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
