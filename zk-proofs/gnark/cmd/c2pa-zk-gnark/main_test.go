package main

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
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
