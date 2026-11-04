package main

import (
	cryptoecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/big"
	mrand "math/rand"
	"sort"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

// TBS sizes measured: the test PKI's signer certificate has a 414-byte TBS;
// 1,500 bytes stands for a larger real certificate (the current circom circuit
// accepts certificates up to 1,500 bytes).
const (
	smallTbs = 414
	largeTbs = 1500
)

// fixture is a circuit definition and a satisfying assignment (or, with
// tamper, an assignment the circuit must reject).
type fixture struct {
	circuit, assignment frontend.Circuit
}

type spec struct {
	description string
	build       func(tamper bool) (fixture, error)
}

var specs = map[string]spec{
	"ecdsa-p256":          {"ECDSA P-256 verify, digest given", ecdsaSpec[emulated.P256Fp, emulated.P256Fr](elliptic.P256(), "sha256")},
	"ecdsa-p384":          {"ECDSA P-384 verify, digest given", ecdsaSpec[emulated.P384Fp, emulated.P384Fr](elliptic.P384(), "sha384")},
	"sha256-414":          {"SHA-256 over 414 bytes", hashSpec("sha256", smallTbs)},
	"sha256-1500":         {"SHA-256 over 1,500 bytes", hashSpec("sha256", largeTbs)},
	"sha384-414":          {"SHA-384 over 414 bytes", hashSpec("sha384", smallTbs)},
	"sha384-1500":         {"SHA-384 over 1,500 bytes", hashSpec("sha384", largeTbs)},
	"ca-p256-sha256-414":  {"CA signature (ECDSA P-256, SHA-256) over a 414-byte TBS", caSpec[emulated.P256Fp, emulated.P256Fr](elliptic.P256(), "sha256", smallTbs)},
	"ca-p256-sha256-1500": {"CA signature (ECDSA P-256, SHA-256) over a 1,500-byte TBS", caSpec[emulated.P256Fp, emulated.P256Fr](elliptic.P256(), "sha256", largeTbs)},
	"ca-p384-sha384-414":  {"CA signature (ECDSA P-384, SHA-384) over a 414-byte TBS", caSpec[emulated.P384Fp, emulated.P384Fr](elliptic.P384(), "sha384", smallTbs)},
	"ca-p384-sha384-1500": {"CA signature (ECDSA P-384, SHA-384) over a 1,500-byte TBS", caSpec[emulated.P384Fp, emulated.P384Fr](elliptic.P384(), "sha384", largeTbs)},
}

func specNames() []string {
	var names []string
	for n := range specs {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// message returns deterministic stand-in TBS bytes (contents do not affect cost).
func message(n int) []byte {
	b := make([]byte, n)
	mrand.New(mrand.NewSource(int64(n))).Read(b)
	return b
}

func digest(alg string, msg []byte) []byte {
	if alg == "sha256" {
		d := sha256.Sum256(msg)
		return d[:]
	}
	d := sha512.Sum384(msg)
	return d[:]
}

// sign signs a digest with a fresh key and returns the key and signature as circuit values.
func sign[Fp, Fr emulated.FieldParams](curve elliptic.Curve, dgst []byte) (ecdsa.PublicKey[Fp, Fr], ecdsa.Signature[Fr], error) {
	priv, err := cryptoecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return ecdsa.PublicKey[Fp, Fr]{}, ecdsa.Signature[Fr]{}, err
	}
	r, s, err := cryptoecdsa.Sign(rand.Reader, priv, dgst)
	if err != nil {
		return ecdsa.PublicKey[Fp, Fr]{}, ecdsa.Signature[Fr]{}, err
	}
	point, err := priv.PublicKey.Bytes() // 0x04 || X || Y
	if err != nil {
		return ecdsa.PublicKey[Fp, Fr]{}, ecdsa.Signature[Fr]{}, err
	}
	size := (len(point) - 1) / 2
	pub := ecdsa.PublicKey[Fp, Fr]{
		X: emulated.ValueOf[Fp](new(big.Int).SetBytes(point[1 : 1+size])),
		Y: emulated.ValueOf[Fp](new(big.Int).SetBytes(point[1+size:])),
	}
	sig := ecdsa.Signature[Fr]{R: emulated.ValueOf[Fr](r), S: emulated.ValueOf[Fr](s)}
	return pub, sig, nil
}

func ecdsaSpec[Fp, Fr emulated.FieldParams](curve elliptic.Curve, alg string) func(bool) (fixture, error) {
	return func(tamper bool) (fixture, error) {
		dgst := digest(alg, message(smallTbs))
		pub, sig, err := sign[Fp, Fr](curve, dgst)
		if err != nil {
			return fixture{}, err
		}
		if tamper {
			dgst[0] ^= 1
		}
		msg := emulated.ValueOf[Fr](new(big.Int).SetBytes(dgst))
		return fixture{&EcdsaCircuit[Fp, Fr]{}, &EcdsaCircuit[Fp, Fr]{Pub: pub, Sig: sig, Msg: msg}}, nil
	}
}

func hashSpec(alg string, n int) func(bool) (fixture, error) {
	return func(tamper bool) (fixture, error) {
		msg := message(n)
		dgst := digest(alg, msg)
		if tamper {
			msg[n/2] ^= 1
		}
		circuit := &HashCircuit{Alg: alg, In: make([]uints.U8, n), Digest: make([]uints.U8, len(dgst))}
		assignment := &HashCircuit{Alg: alg, In: uints.NewU8Array(msg), Digest: uints.NewU8Array(dgst)}
		return fixture{circuit, assignment}, nil
	}
}

func caSpec[Fp, Fr emulated.FieldParams](curve elliptic.Curve, alg string, n int) func(bool) (fixture, error) {
	return func(tamper bool) (fixture, error) {
		tbs := message(n)
		pub, sig, err := sign[Fp, Fr](curve, digest(alg, tbs))
		if err != nil {
			return fixture{}, err
		}
		if tamper {
			tbs[n/2] ^= 1
		}
		circuit := &CaSignatureCircuit[Fp, Fr]{Alg: alg, Tbs: make([]uints.U8, n)}
		assignment := &CaSignatureCircuit[Fp, Fr]{Alg: alg, Pub: pub, Sig: sig, Tbs: uints.NewU8Array(tbs)}
		return fixture{circuit, assignment}, nil
	}
}

func lookup(name string) (spec, error) {
	s, ok := specs[name]
	if !ok {
		return spec{}, fmt.Errorf("unknown circuit %q (known: %v)", name, specNames())
	}
	return s, nil
}
