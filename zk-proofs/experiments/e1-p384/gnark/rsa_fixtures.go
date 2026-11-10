package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"sync"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

func init() {
	add := func(name, description string, build func(bool) (fixture, error)) {
		specs[name] = spec{description, build}
	}
	add("rsa2048-pkcs1-sha256", "RSA-2048 PKCS#1 v1.5 verify (SHA-256 DigestInfo), digest given", pkcs1Spec[rsa2048](2048, "sha256"))
	add("rsa3072-pkcs1-sha256", "RSA-3072 PKCS#1 v1.5 verify (SHA-256 DigestInfo), digest given", pkcs1Spec[rsa3072](3072, "sha256"))
	add("rsa4096-pkcs1-sha384", "RSA-4096 PKCS#1 v1.5 verify (SHA-384 DigestInfo), digest given", pkcs1Spec[rsa4096](4096, "sha384"))
	add("rsa2048-pss-sha256", "RSA-2048 PSS verify (PS256: SHA-256, MGF1-SHA-256, 32-byte salt), digest given, private key", pssSpec[rsa2048](2048))
	add("rsa3072-pss-sha256", "RSA-3072 PSS verify (PS256), digest given, private key", pssSpec[rsa3072](3072))
	add("rsa4096-pss-sha256", "RSA-4096 PSS verify (PS256), digest given, private key", pssSpec[rsa4096](4096))
	add("ca-rsa2048-sha384-1500", "CA signature (RSA-2048 PKCS#1 v1.5, SHA-384) over a 1,500-byte TBS", caRsaSpec[rsa2048](2048, "sha384", largeTbs))
	add("ca-rsa4096-sha256-1500", "CA signature (RSA-4096 PKCS#1 v1.5, SHA-256) over a 1,500-byte TBS", caRsaSpec[rsa4096](4096, "sha256", largeTbs))
	add("ca-rsa4096-sha384-414", "CA signature (RSA-4096 PKCS#1 v1.5, SHA-384) over a 414-byte TBS", caRsaSpec[rsa4096](4096, "sha384", smallTbs))
	add("ca-rsa4096-sha384-1500", "CA signature (RSA-4096 PKCS#1 v1.5, SHA-384) over a 1,500-byte TBS", caRsaSpec[rsa4096](4096, "sha384", largeTbs))
}

// rsaKey returns a fresh key of the given size, generated once per process
// (generating RSA-4096 keys takes seconds; the key does not affect cost).
var rsaKeys sync.Map

func rsaKey(bits int) (*rsa.PrivateKey, error) {
	if k, ok := rsaKeys.Load(bits); ok {
		return k.(*rsa.PrivateKey), nil
	}
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	actual, _ := rsaKeys.LoadOrStore(bits, k)
	return actual.(*rsa.PrivateKey), nil
}

var cryptoHash = map[string]crypto.Hash{"sha256": crypto.SHA256, "sha384": crypto.SHA384}

// pssOptions are PS256's: the salt is as long as the hash (RFC 8230).
var pssOptions = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}

// rawSign returns em^d mod n: a signature over an arbitrary encoded message,
// for the rejection tests' malformed encodings.
func rawSign(key *rsa.PrivateKey, em []byte) []byte {
	s := new(big.Int).Exp(new(big.Int).SetBytes(em), key.D, key.N)
	return s.FillBytes(make([]byte, key.Size()))
}

func element[T emulated.FieldParams](b []byte) emulated.Element[T] {
	return emulated.ValueOf[T](new(big.Int).SetBytes(b))
}

func pkcs1Circuit[T emulated.FieldParams](hash string, n, sig, dgst []byte) fixture {
	return fixture{
		&RsaPkcs1Circuit[T]{Hash: hash, Digest: make([]uints.U8, len(dgst))},
		&RsaPkcs1Circuit[T]{Hash: hash, N: element[T](n), S: element[T](sig), Digest: uints.NewU8Array(dgst)},
	}
}

func pssCircuit[T emulated.FieldParams](n, sig, dgst []byte) fixture {
	return fixture{
		&RsaPssCircuit[T]{Digest: make([]uints.U8, len(dgst))},
		&RsaPssCircuit[T]{N: element[T](n), S: element[T](sig), Digest: uints.NewU8Array(dgst)},
	}
}

func pkcs1Spec[T emulated.FieldParams](bits int, hash string) func(bool) (fixture, error) {
	return func(tamper bool) (fixture, error) {
		key, err := rsaKey(bits)
		if err != nil {
			return fixture{}, err
		}
		dgst := digest(hash, message(smallTbs))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, cryptoHash[hash], dgst)
		if err != nil {
			return fixture{}, err
		}
		if tamper {
			dgst[0] ^= 1
		}
		return pkcs1Circuit[T](hash, key.N.Bytes(), sig, dgst), nil
	}
}

func pssSpec[T emulated.FieldParams](bits int) func(bool) (fixture, error) {
	return func(tamper bool) (fixture, error) {
		key, err := rsaKey(bits)
		if err != nil {
			return fixture{}, err
		}
		dgst := digest("sha256", message(smallTbs))
		sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, dgst, pssOptions)
		if err != nil {
			return fixture{}, err
		}
		if tamper {
			dgst[0] ^= 1
		}
		return pssCircuit[T](key.N.Bytes(), sig, dgst), nil
	}
}

func caRsaSpec[T emulated.FieldParams](bits int, hash string, n int) func(bool) (fixture, error) {
	return func(tamper bool) (fixture, error) {
		key, err := rsaKey(bits)
		if err != nil {
			return fixture{}, err
		}
		tbs := message(n)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, cryptoHash[hash], digest(hash, tbs))
		if err != nil {
			return fixture{}, err
		}
		if tamper {
			tbs[n/2] ^= 1
		}
		circuit := &CaRsaCircuit[T]{Hash: hash, Tbs: make([]uints.U8, n)}
		assignment := &CaRsaCircuit[T]{Hash: hash, N: element[T](key.N.Bytes()), S: element[T](sig), Tbs: uints.NewU8Array(tbs)}
		return fixture{circuit, assignment}, nil
	}
}

// Compile-time check that the circuits implement frontend.Circuit.
var (
	_ frontend.Circuit = (*RsaPkcs1Circuit[rsa2048])(nil)
	_ frontend.Circuit = (*RsaPssCircuit[rsa2048])(nil)
	_ frontend.Circuit = (*CaRsaCircuit[rsa2048])(nil)
)
