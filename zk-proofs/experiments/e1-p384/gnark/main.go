// Command e1bench measures the E1 primitive circuits with gnark (Groth16 on BN254).
//
//	e1bench list                     list the circuits
//	e1bench one NAME                 measure one circuit in this process; print one JSON line
//	e1bench all -out FILE [NAME...]  measure each circuit in its own subprocess; write a JSON record
//
// Each circuit runs in its own process, so its peak RSS (wait4's ru_maxrss) is its own.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	fcs "github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/logger"
)

const resultPrefix = "E1-RESULT "

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: e1bench list | one NAME | all -out FILE [NAME...]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "list":
		for _, n := range specNames() {
			fmt.Printf("%-22s %s\n", n, specs[n].description)
		}
	case "one":
		if len(os.Args) != 3 {
			err = fmt.Errorf("usage: e1bench one NAME")
			break
		}
		err = one(os.Args[2])
	case "all":
		err = all(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type countingWriter struct{ n int64 }

func (w *countingWriter) Write(p []byte) (int, error) { w.n += int64(len(p)); return len(p), nil }

func size(write func(io.Writer) (int64, error)) int64 {
	var w countingWriter
	if _, err := write(&w); err != nil {
		panic(err)
	}
	return w.n
}

// one measures a single circuit: compile, setup, witness, solve, prove, verify.
func one(name string) error {
	logger.Disable()
	s, err := lookup(name)
	if err != nil {
		return err
	}
	fx, err := s.build(false)
	if err != nil {
		return err
	}
	steps := map[string]float64{}
	data := map[string]any{"description": s.description}
	timed := func(step string, f func() error) error {
		start := time.Now()
		err := f()
		steps[step+"_s"] = time.Since(start).Seconds()
		return err
	}
	field := ecc.BN254.ScalarField()

	var ccs constraint.ConstraintSystem
	if err := timed("compile", func() (err error) { ccs, err = frontend.Compile(field, r1cs.NewBuilder, fx.circuit); return }); err != nil {
		return err
	}
	data["r1cs_constraints"] = ccs.GetNbConstraints()
	data["public_variables"] = ccs.GetNbPublicVariables()
	data["secret_variables"] = ccs.GetNbSecretVariables()
	data["internal_variables"] = ccs.GetNbInternalVariables()

	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	if err := timed("setup", func() (err error) { pk, vk, err = groth16.Setup(ccs); return }); err != nil {
		return err
	}
	data["proving_key_bytes_compressed"] = size(pk.WriteTo)
	data["proving_key_bytes_raw"] = size(pk.WriteRawTo)
	data["verifying_key_bytes"] = size(vk.WriteTo)

	var full, public witness.Witness
	if err := timed("witness", func() (err error) {
		if full, err = frontend.NewWitness(fx.assignment, field); err != nil {
			return err
		}
		public, err = full.Public()
		return err
	}); err != nil {
		return err
	}
	// Solving on its own needs the commitment hint the prover normally
	// supplies; a fixed challenge stands in for it (the lookup identities hold
	// for any challenge), so solve excludes computing the commitment itself.
	fixedChallenge := solver.OverrideHint(solver.GetHintID(fcs.Bsb22CommitmentComputePlaceholder), func(_ *big.Int, _ []*big.Int, out []*big.Int) error {
		out[0].Lsh(big.NewInt(1), 200).Add(out[0], big.NewInt(12345))
		return nil
	})
	if err := timed("solve", func() error { _, err := ccs.Solve(full, fixedChallenge); return err }); err != nil {
		return err
	}
	var proof groth16.Proof
	if err := timed("prove", func() (err error) { proof, err = groth16.Prove(ccs, pk, full); return }); err != nil {
		return err
	}
	if err := timed("verify", func() error { return groth16.Verify(proof, vk, public) }); err != nil {
		return err
	}
	data["proof_bytes"] = size(proof.WriteTo)
	if p, ok := proof.(*groth16bn254.Proof); ok {
		data["proof_commitments"] = len(p.Commitments)
	}
	data["public_inputs"] = ccs.GetNbPublicVariables() - 1 // excluding the constant one

	// PLONKish (sparse R1CS) size of the same circuit, for E6; compile only.
	if err := timed("compile_scs", func() error {
		scsCcs, err := frontend.Compile(field, scs.NewBuilder, fx.circuit)
		if err == nil {
			data["scs_constraints"] = scsCcs.GetNbConstraints()
		}
		return err
	}); err != nil {
		return err
	}

	out, err := json.Marshal(map[string]any{"name": name, "steps": steps, "data": data})
	if err != nil {
		return err
	}
	fmt.Println(resultPrefix + string(out))
	return nil
}

// all measures each circuit in its own subprocess and writes one record.
func all(args []string) error {
	fs := flag.NewFlagSet("all", flag.ExitOnError)
	outPath := fs.String("out", "", "write the JSON record here (default: stdout)")
	fs.Parse(args)
	names := fs.Args()
	if len(names) == 0 {
		names = specNames()
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	env := environment() // before any measurement
	var results []map[string]any
	for _, name := range names {
		fmt.Fprintf(os.Stderr, "Measuring %s...\n", name)
		cmd := exec.Command(exe, "one", name)
		cmd.Stderr = os.Stderr
		var stdout bytes.Buffer
		cmd.Stdout = &stdout
		start := time.Now()
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		wall := time.Since(start).Seconds()
		var result map[string]any
		sc := bufio.NewScanner(&stdout)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			if line, ok := strings.CutPrefix(sc.Text(), resultPrefix); ok {
				if err := json.Unmarshal([]byte(line), &result); err != nil {
					return err
				}
			}
		}
		if result == nil {
			return fmt.Errorf("%s: no result", name)
		}
		result["wall_s"] = wall
		result["peak_rss_mib"] = float64(cmd.ProcessState.SysUsage().(*syscall.Rusage).Maxrss) / 1024
		results = append(results, result)
		d := result["data"].(map[string]any)
		st := result["steps"].(map[string]any)
		fmt.Fprintf(os.Stderr, "  %v R1CS constraints; setup %.1f s; prove %.2f s; peak %.0f MiB\n",
			d["r1cs_constraints"], st["setup_s"], st["prove_s"], result["peak_rss_mib"])
	}
	record := map[string]any{
		"schema":       "c2pa-x509-zk-e1/1",
		"experiment":   "E1: in-circuit cost of P-384/SHA-384 next to P-256/SHA-256 (standalone primitives)",
		"stack":        "gnark " + moduleVersion("github.com/consensys/gnark") + ", Groth16 on BN254 (R1CS); emulated (non-native) P-256 and P-384 arithmetic",
		"environment":  env,
		"shortcuts":    shortcuts,
		"step_notes":   stepNotes,
		"measurements": results,
	}
	text, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if *outPath == "" {
		fmt.Println(string(text))
		return nil
	}
	return os.WriteFile(*outPath, append(text, '\n'), 0o644)
}

const shortcuts = "Primitive benchmarks: no certificate parsing, no field extraction, no chain or validity checks. " +
	"Hashes run over a message whose length is fixed at compile time (a real circuit hashes a variable-length " +
	"TBS up to a maximum, at about the cost of the maximum). ECDSA verifies under a public key given as a public " +
	"input, as the anonymization circuit does for the issuing CA; keys and signatures are fresh per run and the " +
	"messages are deterministic stand-ins, neither of which affects cost."

const stepNotes = "compile = R1CS compilation; setup = Groth16 setup (single party, not a ceremony); witness = " +
	"assigning inputs; solve = computing the full witness (gnark's equivalent of witness generation), with a fixed lookup challenge in place of the commitment the prover computes; prove = " +
	"groth16.Prove, which solves again internally, so prove includes solve; verify = groth16.Verify; compile_scs = " +
	"compiling the same circuit for a PLONKish backend, for its constraint count only. Proving keys are reported " +
	"compressed (WriteTo) and raw (WriteRawTo, uncompressed). gnark's hash and range-check gadgets use lookup " +
	"arguments, which its Groth16 backend implements with a commitment (proof_commitments), adding a commitment " +
	"and a proof of knowledge to the proof."

func moduleVersion(path string) string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == path {
				return dep.Version
			}
		}
	}
	return "unknown"
}

func commandOutput(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func procField(path, key string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, key) {
			if _, v, ok := strings.Cut(line, ":"); ok {
				return strings.TrimSpace(v)
			}
		}
	}
	return "unknown"
}

func environment() map[string]any {
	kernelBytes, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	kernel := strings.TrimSpace(string(kernelBytes))
	osName := "unknown"
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
				osName = strings.Trim(v, `"`)
			}
		}
	}
	// Tracked files in the repository that differ from the commit.
	changed := []string{}
	for _, line := range strings.Split(commandOutput("git", "status", "--porcelain", "--untracked-files=no"), "\n") {
		if line = strings.TrimSpace(line); line != "" && line != "unknown" {
			changed = append(changed, line)
		}
	}
	return map[string]any{
		"cpu":               procField("/proc/cpuinfo", "model name"),
		"logical_cpus":      runtime.NumCPU(),
		"memory":            procField("/proc/meminfo", "MemTotal"),
		"os":                osName,
		"kernel":            kernel,
		"wsl":               strings.Contains(strings.ToLower(kernel), "microsoft"),
		"go":                runtime.Version(),
		"gnark":             moduleVersion("github.com/consensys/gnark"),
		"gnark_crypto":      moduleVersion("github.com/consensys/gnark-crypto"),
		"git_commit":        commandOutput("git", "rev-parse", "HEAD"),
		"git_changed_files": changed,
	}
}
