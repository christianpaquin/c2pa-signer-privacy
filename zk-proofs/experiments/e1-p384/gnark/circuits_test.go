package main

import (
	"crypto/sha512"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

func TestDerivedConstantsMatchFips180(t *testing.T) {
	// Spot checks against FIPS 180-4, sections 4.2.3 and 5.3.4.
	if sha512K[0] != 0x428a2f98d728ae22 || sha512K[79] != 0x6c44198c4a475817 {
		t.Fatalf("K: %x ... %x", sha512K[0], sha512K[79])
	}
	if sha384IV[0] != 0xcbbb9d5dc1059ed8 || sha384IV[7] != 0x47b5481dbefa4fa4 {
		t.Fatalf("IV: %x ... %x", sha384IV[0], sha384IV[7])
	}
}

// The in-circuit SHA-384 agrees with crypto/sha512 around the padding boundaries.
func TestSha384MatchesStdlib(t *testing.T) {
	for _, n := range []int{0, 1, 111, 112, 127, 128, 239, 240, 414} {
		msg := message(n)
		want := sha512.Sum384(msg)
		circuit := &HashCircuit{Alg: "sha384", In: make([]uints.U8, n), Digest: make([]uints.U8, 48)}
		good := &HashCircuit{Alg: "sha384", In: uints.NewU8Array(msg), Digest: uints.NewU8Array(want[:])}
		if err := test.IsSolved(circuit, good, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("length %d: %v", n, err)
		}
		want[47] ^= 1
		bad := &HashCircuit{Alg: "sha384", In: uints.NewU8Array(msg), Digest: uints.NewU8Array(want[:])}
		if test.IsSolved(circuit, bad, ecc.BN254.ScalarField()) == nil {
			t.Fatalf("length %d: wrong digest accepted", n)
		}
	}
}

// Every benchmarked circuit accepts its fixture and rejects a tampered one.
func TestFixturesAcceptAndReject(t *testing.T) {
	for _, name := range specNames() {
		if testing.Short() && name != "ca-p384-sha384-414" && name != "ca-p256-sha256-414" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			s, _ := lookup(name)
			good, err := s.build(false)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.IsSolved(good.circuit, good.assignment, ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("valid input rejected: %v", err)
			}
			bad, err := s.build(true)
			if err != nil {
				t.Fatal(err)
			}
			if test.IsSolved(bad.circuit, bad.assignment, ecc.BN254.ScalarField()) == nil {
				t.Fatal("tampered input accepted")
			}
		})
	}
}
