// c2pa-zk-gnark proves and verifies the third-party anonymization statement
// (package statement) with Groth16 on BN254.
//
//	c2pa-zk-gnark setup  --keys DIR
//	c2pa-zk-gnark check  --input inputs.json
//	c2pa-zk-gnark prove  --keys DIR --input inputs.json --proof proof.bin [--pk-format F --pk-check C]
//	c2pa-zk-gnark convert-pk --keys DIR
//	c2pa-zk-gnark verify --keys DIR --public public.json --proof proof.bin
//
// inputs.json holds statement.Inputs (byte fields in base64); public.json
// holds statement.Public. Both are produced from a signed asset by the Rust
// tools (c2pa-x509-zk-statement-inputs). setup writes the constraint system,
// both keys, and keys.json (the sizes and each file's SHA-256) into DIR.
//
// Proving-key formats (roadmap E6): setup writes the key compressed;
// convert-pk adds it raw (uncompressed points) and as a binary dump, with
// their hashes. prove --pk-format compressed|raw|dump picks the file, and
// --pk-check full|none whether points are validated on load (subgroup
// checks; a dump is never validated). Every file's SHA-256 is checked
// against keys.json before it is parsed.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnarkio "github.com/consensys/gnark/io"

	"c2pa-zk-gnark/statement"
)

const (
	ccsFile      = "statement.ccs"
	pkFile       = "statement.pk"
	vkFile       = "statement.vk"
	manifestFile = "keys.json"
)

// manifest identifies the keys: the circuit's sizes and the files' hashes.
type manifest struct {
	Statement   string            `json:"statement"`
	Sizes       statement.Sizes   `json:"sizes"`
	Constraints int               `json:"constraints"`
	SHA256      map[string]string `json:"sha256"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	keys := fs.String("keys", "", "key directory")
	input := fs.String("input", "", "prover inputs (JSON)")
	public := fs.String("public", "", "public inputs (JSON)")
	proofPath := fs.String("proof", "", "proof file")
	pkFormat := fs.String("pk-format", "compressed", "proving-key file: compressed, raw, or dump")
	pkCheck := fs.String("pk-check", "full", "validate proving-key points on load: full or none")
	_ = fs.Parse(os.Args[2:])

	var err error
	switch os.Args[1] {
	case "setup":
		err = setup(require(*keys, "--keys"))
	case "check":
		err = check(require(*input, "--input"))
	case "prove":
		err = prove(require(*keys, "--keys"), require(*input, "--input"), require(*proofPath, "--proof"), *pkFormat, *pkCheck)
	case "convert-pk":
		err = convertPK(require(*keys, "--keys"))
	case "verify":
		err = verify(require(*keys, "--keys"), require(*public, "--public"), require(*proofPath, "--proof"))
		if errors.Is(err, errInvalid) {
			fmt.Fprintln(os.Stderr, "proof is INVALID")
			os.Exit(1)
		}
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}

var errInvalid = errors.New("invalid proof")

func usage() {
	fmt.Fprintln(os.Stderr, "usage: c2pa-zk-gnark setup|check|prove|verify|convert-pk (see the source header)")
	os.Exit(2)
}

func require(v, name string) string {
	if v == "" {
		fmt.Fprintf(os.Stderr, "%s is required\n", name)
		os.Exit(2)
	}
	return v
}

// timed runs f and reports how long it took on stderr.
func timed(what string, f func() error) error {
	start := time.Now()
	err := f()
	fmt.Fprintf(os.Stderr, "%s: %.2f s\n", what, time.Since(start).Seconds())
	return err
}

func compile(s statement.Sizes) (constraint.ConstraintSystem, error) {
	var ccs constraint.ConstraintSystem
	err := timed("compile", func() (err error) {
		ccs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, statement.NewCircuit(s))
		return
	})
	return ccs, err
}

func setup(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	s := statement.DefaultSizes
	ccs, err := compile(s)
	if err != nil {
		return err
	}
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	if err := timed("setup", func() (err error) { pk, vk, err = groth16.Setup(ccs); return }); err != nil {
		return err
	}
	m := manifest{Statement: "c2pa-x509-zk third-party (E2b)", Sizes: s, Constraints: ccs.GetNbConstraints(), SHA256: map[string]string{}}
	for name, w := range map[string]io.WriterTo{ccsFile: ccs, pkFile: pk, vkFile: vk} {
		sum, err := writeFile(filepath.Join(dir, name), w)
		if err != nil {
			return err
		}
		m.SHA256[name] = sum
	}
	data, _ := json.MarshalIndent(m, "", "  ")
	fmt.Fprintf(os.Stderr, "%d constraints\n", m.Constraints)
	return os.WriteFile(filepath.Join(dir, manifestFile), append(data, '\n'), 0o644)
}

func check(inputPath string) error {
	var in statement.Inputs
	if err := readJSON(inputPath, &in); err != nil {
		return err
	}
	ccs, err := compile(statement.DefaultSizes)
	if err != nil {
		return err
	}
	assignment, err := statement.Assign(in, statement.DefaultSizes)
	if err != nil {
		return err
	}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	// Lookups use a commitment (BSB22) as their random challenge, which the
	// Groth16 prover computes; solving alone draws it at random instead, as
	// gnark does in tests.
	randomChallenge := solver.OverrideHint(solver.GetHintID(cs.Bsb22CommitmentComputePlaceholder),
		func(mod *big.Int, _ []*big.Int, out []*big.Int) (err error) {
			out[0], err = rand.Int(rand.Reader, mod)
			return
		})
	if err := timed("solve", func() error { return ccs.IsSolved(w, randomChallenge) }); err != nil {
		return fmt.Errorf("the inputs do not satisfy the statement: %w", err)
	}
	fmt.Println("inputs satisfy the statement")
	return nil
}

// pkFiles maps a proving-key format to its file in the key directory.
var pkFiles = map[string]string{"compressed": pkFile, "raw": pkFile + ".raw", "dump": pkFile + ".dump"}

// loadProvingKey reads the proving key in the given format and checking
// mode, reporting reading, hashing, and parsing separately.
func loadProvingKey(dir string, m manifest, format, check string) (groth16.ProvingKey, error) {
	name, ok := pkFiles[format]
	if !ok {
		return nil, fmt.Errorf("unknown --pk-format %q", format)
	}
	if check != "full" && check != "none" {
		return nil, fmt.Errorf("unknown --pk-check %q", check)
	}
	if format == "dump" && check == "full" {
		return nil, fmt.Errorf("a dumped proving key cannot be validated on load: use --pk-check none")
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	err := timed("load proving key", func() error {
		data, err := readChecked(dir, name, m, "proving key")
		if err != nil {
			return err
		}
		return timed("parse proving key", func() error {
			switch {
			case format == "dump":
				return pk.(gnarkio.BinaryDumper).ReadDump(bytes.NewReader(data))
			case check == "none":
				_, err := pk.(gnarkio.UnsafeReaderFrom).UnsafeReadFrom(bytes.NewReader(data))
				return err
			default:
				_, err := pk.ReadFrom(bytes.NewReader(data))
				return err
			}
		})
	})
	return pk, err
}

// convertPK writes the proving key raw and as a binary dump, next to the
// compressed key setup wrote, and records their hashes in keys.json.
func convertPK(dir string) error {
	m, err := readManifest(dir)
	if err != nil {
		return err
	}
	pk, err := loadProvingKey(dir, m, "compressed", "full")
	if err != nil {
		return err
	}
	writers := map[string]io.WriterTo{
		pkFiles["raw"]:  writerFunc(func(w io.Writer) (int64, error) { return pk.WriteRawTo(w) }),
		pkFiles["dump"]: writerFunc(func(w io.Writer) (int64, error) { return 0, pk.(gnarkio.BinaryDumper).WriteDump(w) }),
	}
	for name, w := range writers {
		if err := timed("write "+name, func() error {
			sum, err := writeFile(filepath.Join(dir, name), w)
			m.SHA256[name] = sum
			return err
		}); err != nil {
			return err
		}
	}
	data, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(filepath.Join(dir, manifestFile), append(data, '\n'), 0o644)
}

type writerFunc func(io.Writer) (int64, error)

func (f writerFunc) WriteTo(w io.Writer) (int64, error) { return f(w) }

func prove(dir, inputPath, proofPath, pkFormat, pkCheck string) error {
	m, err := readManifest(dir)
	if err != nil {
		return err
	}
	var in statement.Inputs
	if err := readJSON(inputPath, &in); err != nil {
		return err
	}
	assignment, err := statement.Assign(in, m.Sizes)
	if err != nil {
		return err
	}
	ccs := groth16.NewCS(ecc.BN254)
	if err := timed("load constraint system", func() error { return readFile(dir, ccsFile, m, ccs) }); err != nil {
		return err
	}
	pk, err := loadProvingKey(dir, m, pkFormat, pkCheck)
	if err != nil {
		return err
	}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	var proof groth16.Proof
	if err := timed("prove", func() (err error) { proof, err = groth16.Prove(ccs, pk, w); return }); err != nil {
		return err
	}
	_, err = writeFile(proofPath, proof)
	return err
}

func verify(dir, publicPath, proofPath string) error {
	m, err := readManifest(dir)
	if err != nil {
		return err
	}
	var pub statement.Public
	if err := readJSON(publicPath, &pub); err != nil {
		return err
	}
	assignment, err := statement.AssignPublic(pub, m.Sizes)
	if err != nil {
		return err
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := readFile(dir, vkFile, m, vk); err != nil {
		return err
	}
	data, err := os.ReadFile(proofPath)
	if err != nil {
		return err
	}
	proof, err := readProof(data)
	if err != nil {
		return err
	}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	if err := timed("verify", func() error { return groth16.Verify(proof, vk, w) }); err != nil {
		return errInvalid
	}
	fmt.Println("proof is valid")
	return nil
}

func readManifest(dir string) (manifest, error) {
	var m manifest
	if err := readJSON(filepath.Join(dir, manifestFile), &m); err != nil {
		return m, fmt.Errorf("no keys in %s (run setup): %w", dir, err)
	}
	return m, nil
}

// readFile loads a key-directory file after checking its hash against keys.json.
func readFile(dir, name string, m manifest, into io.ReaderFrom) error {
	data, err := readChecked(dir, name, m, "")
	if err != nil {
		return err
	}
	_, err = into.ReadFrom(bytes.NewReader(data))
	return err
}

// readChecked reads a key-directory file and checks its SHA-256 against
// keys.json; with a label, it reports reading and hashing times.
func readChecked(dir, name string, m manifest, label string) ([]byte, error) {
	expected, ok := m.SHA256[name]
	if !ok {
		return nil, fmt.Errorf("keys.json has no hash for %s (run convert-pk?)", name)
	}
	var data []byte
	read := func() (err error) { data, err = os.ReadFile(filepath.Join(dir, name)); return }
	hash := func() error {
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != expected {
			return fmt.Errorf("%s does not match keys.json", name)
		}
		return nil
	}
	if label == "" {
		if err := read(); err != nil {
			return nil, err
		}
		return data, hash()
	}
	if err := timed("read "+label, read); err != nil {
		return nil, err
	}
	return data, timed("hash "+label, hash)
}

func writeFile(path string, w io.WriterTo) (string, error) {
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := w.WriteTo(io.MultiWriter(f, h)); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// readProof decodes a proof that must be exactly the input: trailing bytes
// (data appended to a valid proof) are rejected.
func readProof(data []byte) (groth16.Proof, error) {
	proof := groth16.NewProof(ecc.BN254)
	n, err := proof.ReadFrom(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("malformed proof: %w", err)
	}
	if n != int64(len(data)) {
		return nil, fmt.Errorf("malformed proof: %d bytes follow it", int64(len(data))-n)
	}
	return proof, nil
}
