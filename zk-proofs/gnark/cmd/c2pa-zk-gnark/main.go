// c2pa-zk-gnark proves and verifies the third-party anonymization statement
// (package statement) with Groth16, on BN254 (the default) or BLS12-381.
//
//	c2pa-zk-gnark setup  --keys DIR [--curve bn254|bls12-381] [--statement disclosed|hidden-issuer]
//	c2pa-zk-gnark check  --input inputs.json [--curve C] [--statement S --issuers issuers.pem]
//	c2pa-zk-gnark prove  --keys DIR --input inputs.json --proof proof.bin [--issuers issuers.pem] [--pk-format F --pk-check C]
//	c2pa-zk-gnark convert-pk --keys DIR
//	c2pa-zk-gnark verify --keys DIR --public public.json --proof proof.bin
//	c2pa-zk-gnark tree   --issuers issuers.pem [--curve C] [--role issuer|tsa]
//
// A third statement, "hidden-all" (roadmap I6, HIDING-THE-TIME-STAMP.md),
// also hides the time-stamp token: prove and check take --issuers (signer
// issuers) and --tsa-issuers (TSA issuers, eligible for time stamping), and
// --window (the window's granularity in seconds, default a day); inputs.json
// must hold the token (time_stamp_token); public.json holds
// statement.HiddenAllPublic. Each tree's role is fixed by the statement: tree
// --role tsa prints a TSA tree's root (leaf tag 4), --role issuer (the
// default) an issuer tree's (leaf tag 1).
//
// Two statements (roadmap H4, HIDING-THE-ISSUER.md): "disclosed" (the
// default: the issuing CA's key is a public input) and "hidden-issuer" (the
// CA's key is private and proven a member of the issuer tree whose root is
// public). The statement belongs to the key set, like the curve. For the
// hidden issuer, prove and check build the tree from --issuers (a PEM file of
// eligible CA certificates; eligibility is the caller's, I1), and public.json
// holds statement.HiddenPublic, with the root of a tree the verifier
// approves. tree prints a tree's root and entries (JSON).
//
// inputs.json holds statement.Inputs (byte fields in base64); public.json
// holds statement.Public. Both are produced from a signed asset by the Rust
// tools (c2pa-x509-zk-statement-inputs). setup writes the constraint system,
// both keys, and keys.json (the curve, the sizes, and each file's SHA-256)
// into DIR. The curve belongs to the key set (roadmap E7): prove, verify,
// and convert-pk take it from keys.json.
//
// Proving-key formats (roadmap E6): setup writes the key compressed;
// convert-pk adds it raw (uncompressed points) and as a binary dump, with
// their hashes. prove --pk-format compressed|raw|dump picks the file, and
// --pk-check full|none whether points are validated on load (subgroup
// checks; a dump is never validated). Every file's SHA-256 is checked
// against keys.json before it is parsed, and again as it is parsed (files
// are streamed, never held whole in memory). Loading without point checks
// needs the key's provenance record in keys.json (written by setup and
// convert-pk), matching its hash and this gnark version; otherwise it is
// refused, never silently downgraded.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnarkio "github.com/consensys/gnark/io"

	"c2pa-zk-gnark/issuertree"
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
	Statement string `json:"statement"`
	// "hidden-issuer" for the H4 statement; absent for the disclosed one.
	Variant string `json:"variant,omitempty"`
	// The proof system's curve: "bn254" (also when absent, for key sets
	// from before E7) or "bls12-381".
	Curve string          `json:"curve,omitempty"`
	Sizes statement.Sizes `json:"sizes"`
	// The token's sizes, for the hidden-all statement.
	TokenSizes  *statement.TokenSizes `json:"token_sizes,omitempty"`
	Constraints int                   `json:"constraints"`
	SHA256      map[string]string     `json:"sha256"`
	// How each proving-key file was produced, by format (roadmap E6).
	// Loading a key without point checks requires its record.
	ProvingKeys map[string]keyFile `json:"proving_keys,omitempty"`
}

// keyFile records a proving-key file's provenance: its format, hash, the
// gnark version that wrote it (gnark does not guarantee its serialized
// formats across versions), and its source.
type keyFile struct {
	File         string `json:"file"`
	Format       string `json:"format"`
	SHA256       string `json:"sha256"`
	GnarkVersion string `json:"gnark_version"`
	// "setup" (written by local setup), or "converted" from SourceSHA256,
	// a key loaded with full point checks.
	Source       string `json:"source"`
	SourceSHA256 string `json:"source_sha256,omitempty"`
}

// curves are the supported curves, by the names used in keys.json and --curve.
var curves = map[string]ecc.ID{"bn254": ecc.BN254, "bls12-381": ecc.BLS12_381}

func curveID(name string) (ecc.ID, error) {
	if name == "" {
		name = "bn254"
	}
	id, ok := curves[name]
	if !ok {
		return ecc.UNKNOWN, fmt.Errorf("unknown curve %q (bn254 or bls12-381)", name)
	}
	return id, nil
}

// gnarkVersion is the version of gnark this binary was built with.
func gnarkVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/consensys/gnark" {
				if dep.Replace != nil {
					return dep.Replace.Version
				}
				return dep.Version
			}
		}
	}
	return "unknown"
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
	curve := fs.String("curve", "bn254", "setup, check, and tree: the curve, bn254 or bls12-381")
	variant := fs.String("statement", variantDisclosed, "setup and check: the statement, disclosed, hidden-issuer, or hidden-all")
	issuers := fs.String("issuers", "", "hidden issuer: the eligible CA certificates (PEM) the tree is built from")
	tsaIssuers := fs.String("tsa-issuers", "", "hidden-all: the CA certificates eligible for time stamping (PEM) the TSA tree is built from")
	window := fs.Int64("window", 86400, "hidden-all: the time window's granularity, in seconds (aligned to the Unix epoch; a day by default)")
	role := fs.String("role", "issuer", "tree: the tree's role, issuer or tsa")
	_ = fs.Parse(os.Args[2:])
	opts := proverOptions{issuers: *issuers, tsaIssuers: *tsaIssuers, window: *window}

	var err error
	switch os.Args[1] {
	case "setup":
		err = setup(require(*keys, "--keys"), *curve, *variant)
	case "check":
		err = check(require(*input, "--input"), *curve, *variant, opts)
	case "prove":
		err = prove(require(*keys, "--keys"), require(*input, "--input"), require(*proofPath, "--proof"), *pkFormat, *pkCheck, opts)
	case "convert-pk":
		err = convertPK(require(*keys, "--keys"))
	case "verify":
		err = verify(require(*keys, "--keys"), require(*public, "--public"), require(*proofPath, "--proof"))
		if errors.Is(err, errInvalid) {
			fmt.Fprintln(os.Stderr, "proof is INVALID")
			os.Exit(1)
		}
	case "tree":
		err = printTree(require(*issuers, "--issuers"), *curve, *role)
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
	fmt.Fprintln(os.Stderr, "usage: c2pa-zk-gnark setup|check|prove|verify|convert-pk|tree (see the source header)")
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

const (
	variantDisclosed = "disclosed"
	variantHidden    = "hidden-issuer"
	variantHiddenAll = "hidden-all"
)

func checkVariant(v string) error {
	if v != variantDisclosed && v != variantHidden && v != variantHiddenAll {
		return fmt.Errorf("unknown statement %q (disclosed, hidden-issuer, or hidden-all)", v)
	}
	return nil
}

// proverOptions are the prover's options for the hidden statements.
type proverOptions struct {
	issuers, tsaIssuers string
	window              int64
}

func compile(s statement.Sizes, ts statement.TokenSizes, curve ecc.ID, variant string) (constraint.ConstraintSystem, error) {
	var circuit frontend.Circuit = statement.NewCircuit(s)
	switch variant {
	case variantHidden:
		circuit = statement.NewHiddenIssuerCircuit(s)
	case variantHiddenAll:
		circuit = statement.NewHiddenAllCircuit(s, ts)
	}
	var ccs constraint.ConstraintSystem
	err := timed("compile", func() (err error) {
		ccs, err = frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, circuit)
		return
	})
	return ccs, err
}

// issuerTree builds the role's tree from a PEM file of CA certificates
// (already filtered for the role's purpose by the caller).
func issuerTree(path string, curve ecc.ID, role issuertree.Role) (*issuertree.Tree, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var certs [][]byte
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, block.Bytes)
		}
	}
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no certificates in %s", path)
	}
	return issuertree.Build(curve, role, certs)
}

// assignment builds the prover's assignment for the key set's statement.
func assignment(in statement.Inputs, s statement.Sizes, ts statement.TokenSizes, curve ecc.ID, variant string, o proverOptions) (frontend.Circuit, error) {
	if variant != variantHiddenAll && o.tsaIssuers != "" {
		return nil, fmt.Errorf("--tsa-issuers applies only to the hidden-all statement")
	}
	switch variant {
	case variantDisclosed:
		if o.issuers != "" {
			return nil, fmt.Errorf("--issuers applies only to the hidden-issuer and hidden-all statements")
		}
		return statement.Assign(in, s)
	case variantHidden:
		if o.issuers == "" {
			return nil, fmt.Errorf("the hidden-issuer statement needs --issuers")
		}
		tree, _, err := issuerTree(o.issuers, curve, issuertree.RoleIssuer)
		if err != nil {
			return nil, err
		}
		return statement.AssignHidden(in, tree, s)
	}
	if o.issuers == "" || o.tsaIssuers == "" {
		return nil, fmt.Errorf("the hidden-all statement needs --issuers and --tsa-issuers")
	}
	if o.window <= 0 {
		return nil, fmt.Errorf("--window must be positive")
	}
	issuers, _, err := issuerTree(o.issuers, curve, issuertree.RoleIssuer)
	if err != nil {
		return nil, err
	}
	tsas, _, err := issuerTree(o.tsaIssuers, curve, issuertree.RoleTSA)
	if err != nil {
		return nil, fmt.Errorf("--tsa-issuers: %w", err)
	}
	t1, t2 := statement.Window(in.Time, o.window)
	return statement.AssignHiddenAll(in, issuers, tsas, t1, t2, s, ts)
}

func printTree(issuers, curveName, roleName string) error {
	curve, err := curveID(curveName)
	if err != nil {
		return err
	}
	role, err := issuertree.ParseRole(roleName)
	if err != nil {
		return err
	}
	tree, skipped, err := issuerTree(issuers, curve, role)
	if err != nil {
		return err
	}
	type entry struct {
		CertSHA256s []string `json:"cert_sha256s"` // every certificate with this leaf
		NotBefore   int64    `json:"not_before"`
		NotAfter    int64    `json:"not_after"`
	}
	out := struct {
		FormatVersion int      `json:"format_version"`
		Role          string   `json:"role"`
		Curve         string   `json:"curve"`
		KeyType       string   `json:"key_type"`
		Root          string   `json:"root"`
		Entries       []entry  `json:"entries"`
		Skipped       []string `json:"skipped"`
	}{FormatVersion: issuertree.FormatVersion, Role: role.String(), Curve: curveName, KeyType: "P-384", Root: tree.Root().Text(16), Entries: []entry{}, Skipped: append([]string{}, skipped...)}
	for _, e := range tree.Entries {
		out.Entries = append(out.Entries, entry{e.CertSHA256s, e.NotBefore, e.NotAfter})
	}
	data, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(data))
	return nil
}

func setup(dir, curveName, variant string) error {
	curve, err := curveID(curveName)
	if err != nil {
		return err
	}
	if err := checkVariant(variant); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	s := statement.DefaultSizes
	ccs, err := compile(s, statement.DefaultTokenSizes, curve, variant)
	if err != nil {
		return err
	}
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	if err := timed("setup", func() (err error) { pk, vk, err = groth16.Setup(ccs); return }); err != nil {
		return err
	}
	m := manifest{Statement: "c2pa-x509-zk third-party (E2b)", Curve: curveName, Sizes: s, Constraints: ccs.GetNbConstraints(), SHA256: map[string]string{}}
	switch variant {
	case variantHidden:
		m.Statement, m.Variant = "c2pa-x509-zk third-party, hidden issuer (H4)", variantHidden
	case variantHiddenAll:
		ts := statement.DefaultTokenSizes
		m.Statement, m.Variant, m.TokenSizes = "c2pa-x509-zk third-party, hidden issuer and time stamp (I6)", variantHiddenAll, &ts
	}
	for name, w := range map[string]io.WriterTo{ccsFile: ccs, pkFile: pk, vkFile: vk} {
		sum, err := writeFile(filepath.Join(dir, name), w)
		if err != nil {
			return err
		}
		m.SHA256[name] = sum
	}
	m.ProvingKeys = map[string]keyFile{"compressed": {File: pkFile, Format: "compressed", SHA256: m.SHA256[pkFile], GnarkVersion: gnarkVersion(), Source: "setup"}}
	data, _ := json.MarshalIndent(m, "", "  ")
	fmt.Fprintf(os.Stderr, "%d constraints\n", m.Constraints)
	return os.WriteFile(filepath.Join(dir, manifestFile), append(data, '\n'), 0o644)
}

func check(inputPath, curveName, variant string, opts proverOptions) error {
	curve, err := curveID(curveName)
	if err != nil {
		return err
	}
	if err := checkVariant(variant); err != nil {
		return err
	}
	var in statement.Inputs
	if err := readJSON(inputPath, &in); err != nil {
		return err
	}
	assigned, err := assignment(in, statement.DefaultSizes, statement.DefaultTokenSizes, curve, variant, opts)
	if err != nil {
		return err
	}
	ccs, err := compile(statement.DefaultSizes, statement.DefaultTokenSizes, curve, variant)
	if err != nil {
		return err
	}
	w, err := frontend.NewWitness(assigned, curve.ScalarField())
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

// uncheckedAllowed reports why loading the key in this format without point
// checks is refused, or nil: it needs a provenance record in keys.json that
// matches the file's hash, comes from local setup or a fully checked
// conversion, and was written by this gnark version. There is no fallback.
func uncheckedAllowed(m manifest, format string) error {
	rec, ok := m.ProvingKeys[format]
	if !ok {
		return fmt.Errorf("keys.json has no provenance record for the %s proving key (run convert-pk, or load with --pk-check full)", format)
	}
	// The record must describe the file that will be loaded: its name,
	// format, and hash, not those of another key.
	file := pkFiles[format]
	if rec.File != file || rec.Format != format {
		return fmt.Errorf("the %s proving key's provenance record describes %s (%s), not %s", format, rec.File, rec.Format, file)
	}
	if rec.SHA256 == "" || rec.SHA256 != m.SHA256[file] {
		return fmt.Errorf("the %s proving key's provenance record does not match its recorded hash", format)
	}
	if v := gnarkVersion(); rec.GnarkVersion != v || v == "unknown" {
		return fmt.Errorf("the %s proving key was written by gnark %s, this is gnark %s: convert it again, or load with --pk-check full", format, rec.GnarkVersion, v)
	}
	if rec.Source != "setup" && (rec.Source != "converted" || rec.SourceSHA256 == "") {
		return fmt.Errorf("the %s proving key's source (%q) is neither local setup nor a fully checked conversion", format, rec.Source)
	}
	return nil
}

// loadProvingKey reads the proving key in the given format and checking
// mode. Unchecked loading needs the key's provenance record (uncheckedAllowed).
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
	if check == "none" {
		if err := uncheckedAllowed(m, format); err != nil {
			return nil, fmt.Errorf("refusing to load the proving key without point checks: %w", err)
		}
	}
	pk := groth16.NewProvingKey(m.curve())
	err := timed("load proving key", func() error {
		return loadChecked(dir, name, m, "proving key", func(r io.Reader) error {
			switch {
			case format == "dump":
				return pk.(gnarkio.BinaryDumper).ReadDump(r)
			case check == "none":
				_, err := pk.(gnarkio.UnsafeReaderFrom).UnsafeReadFrom(r)
				return err
			default:
				_, err := pk.ReadFrom(r)
				return err
			}
		})
	})
	return pk, err
}

// convertPK writes the proving key raw and as a binary dump, next to the
// compressed key setup wrote, after loading that key with full point
// checks, and records each file's provenance in keys.json.
func convertPK(dir string) error {
	m, err := readManifest(dir)
	if err != nil {
		return err
	}
	source, ok := m.SHA256[pkFile]
	if !ok {
		return fmt.Errorf("keys.json has no hash for %s", pkFile)
	}
	pk, err := loadProvingKey(dir, m, "compressed", "full")
	if err != nil {
		return err
	}
	if m.ProvingKeys == nil {
		m.ProvingKeys = map[string]keyFile{}
	}
	if _, ok := m.ProvingKeys["compressed"]; !ok {
		// Keys from a setup that predates provenance records: setup recorded the hash.
		m.ProvingKeys["compressed"] = keyFile{File: pkFile, Format: "compressed", SHA256: source, GnarkVersion: gnarkVersion(), Source: "setup"}
	}
	writers := map[string]io.WriterTo{
		"raw":  writerFunc(func(w io.Writer) (int64, error) { return pk.WriteRawTo(w) }),
		"dump": writerFunc(func(w io.Writer) (int64, error) { return 0, pk.(gnarkio.BinaryDumper).WriteDump(w) }),
	}
	for format, w := range writers {
		name := pkFiles[format]
		if err := timed("write "+name, func() error {
			sum, err := writeFile(filepath.Join(dir, name), w)
			m.SHA256[name] = sum
			m.ProvingKeys[format] = keyFile{File: name, Format: format, SHA256: sum, GnarkVersion: gnarkVersion(), Source: "converted", SourceSHA256: source}
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

func prove(dir, inputPath, proofPath, pkFormat, pkCheck string, opts proverOptions) error {
	m, err := readManifest(dir)
	if err != nil {
		return err
	}
	var in statement.Inputs
	if err := readJSON(inputPath, &in); err != nil {
		return err
	}
	assigned, err := assignment(in, m.Sizes, m.tokenSizes(), m.curve(), m.variant(), opts)
	if err != nil {
		return err
	}
	ccs := groth16.NewCS(m.curve())
	if err := timed("load constraint system", func() error { return readFile(dir, ccsFile, m, ccs) }); err != nil {
		return err
	}
	pk, err := loadProvingKey(dir, m, pkFormat, pkCheck)
	if err != nil {
		return err
	}
	w, err := frontend.NewWitness(assigned, m.curve().ScalarField())
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
	var assigned frontend.Circuit
	if m.variant() == variantHiddenAll {
		var pub statement.HiddenAllPublic
		if err := readJSON(publicPath, &pub); err != nil {
			return err
		}
		if assigned, err = statement.AssignHiddenAllPublic(pub, m.Sizes, m.tokenSizes(), m.curve()); err != nil {
			return err
		}
	} else if m.variant() == variantHidden {
		var pub statement.HiddenPublic
		if err := readJSON(publicPath, &pub); err != nil {
			return err
		}
		if assigned, err = statement.AssignHiddenPublic(pub, m.Sizes, m.curve()); err != nil {
			return err
		}
	} else {
		var pub statement.Public
		if err := readJSON(publicPath, &pub); err != nil {
			return err
		}
		if assigned, err = statement.AssignPublic(pub, m.Sizes); err != nil {
			return err
		}
	}
	vk := groth16.NewVerifyingKey(m.curve())
	if err := readFile(dir, vkFile, m, vk); err != nil {
		return err
	}
	data, err := os.ReadFile(proofPath)
	if err != nil {
		return err
	}
	proof, err := readProof(data, m.curve())
	if err != nil {
		return err
	}
	w, err := frontend.NewWitness(assigned, m.curve().ScalarField(), frontend.PublicOnly())
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
	if _, err := curveID(m.Curve); err != nil {
		return m, fmt.Errorf("%s: %w", manifestFile, err)
	}
	if err := checkVariant(m.variant()); err != nil {
		return m, fmt.Errorf("%s: %w", manifestFile, err)
	}
	return m, nil
}

// tokenSizes are the key set's token sizes (hidden-all key sets record them).
func (m manifest) tokenSizes() statement.TokenSizes {
	if m.TokenSizes != nil {
		return *m.TokenSizes
	}
	return statement.DefaultTokenSizes
}

// variant is the key set's statement: disclosed when absent (key sets from
// before H4).
func (m manifest) variant() string {
	if m.Variant == "" {
		return variantDisclosed
	}
	return m.Variant
}

// curve is the key set's curve (validated by readManifest).
func (m manifest) curve() ecc.ID {
	id, _ := curveID(m.Curve)
	return id
}

// readFile loads a key-directory file after checking its hash against keys.json.
func readFile(dir, name string, m manifest, into io.ReaderFrom) error {
	return loadChecked(dir, name, m, "", func(r io.Reader) error {
		_, err := into.ReadFrom(r)
		return err
	})
}

// streamBuffer bounds the memory used to read key-directory files.
const streamBuffer = 4 << 20

// betweenPasses is called between the hashing and parsing passes (tests).
var betweenPasses = func(path string) {}

// loadChecked streams a key-directory file twice, so it is never held whole
// in memory: first through SHA-256, checked against keys.json before any
// parsing; then through the parser, buffered, while the same bytes are hashed
// again. The result is used only if that second hash matches too and the
// parser consumed the whole file, so a file that changed between the passes,
// or carries bytes the parser did not read, is rejected. With a label, the
// two passes are timed as "hash <label>" and "parse <label>".
func loadChecked(dir, name string, m manifest, label string, parse func(io.Reader) error) error {
	expected, ok := m.SHA256[name]
	if !ok {
		return fmt.Errorf("keys.json has no hash for %s (run convert-pk?)", name)
	}
	path := filepath.Join(dir, name)
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	step := func(what string, fn func() error) error {
		if label == "" {
			return fn()
		}
		return timed(what+" "+label, fn)
	}
	if err := step("hash", func() error {
		h := sha256.New()
		if _, err := io.Copy(h, bufio.NewReaderSize(f, streamBuffer)); err != nil {
			return err
		}
		if hex.EncodeToString(h.Sum(nil)) != expected {
			return fmt.Errorf("%s does not match keys.json", name)
		}
		return nil
	}); err != nil {
		return err
	}
	betweenPasses(path)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return step("parse", func() error {
		h := sha256.New()
		r := io.TeeReader(bufio.NewReaderSize(f, streamBuffer), h)
		if err := parse(r); err != nil {
			return err
		}
		trailing, err := io.Copy(io.Discard, r)
		if err != nil {
			return err
		}
		if hex.EncodeToString(h.Sum(nil)) != expected {
			return fmt.Errorf("%s changed while it was being loaded", name)
		}
		if trailing != 0 {
			return fmt.Errorf("%s has %d bytes after its contents", name, trailing)
		}
		return nil
	})
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
func readProof(data []byte, curve ecc.ID) (groth16.Proof, error) {
	proof := groth16.NewProof(curve)
	n, err := proof.ReadFrom(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("malformed proof: %w", err)
	}
	if n != int64(len(data)) {
		return nil, fmt.Errorf("malformed proof: %d bytes follow it", int64(len(data))-n)
	}
	return proof, nil
}
