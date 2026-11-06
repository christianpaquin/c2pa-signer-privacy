package main

import (
	"bytes"
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
