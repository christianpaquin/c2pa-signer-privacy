//! Native Rust ZK proof generation using ark-circom + ark-groth16
//!
//! This module replaces snarkjs subprocess calls with native Rust proving,
//! providing 10-100x faster setup and 5-10x faster proving.

use anyhow::{anyhow, bail, Result};
use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig};
use ark_snark::SNARK;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::thread_rng;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use std::path::Path;

// Re-export types from the main circuit module that we still need
pub use crate::circuit::{
    CircuitInputs, ProofInputs, ProofOutputs, PublicKeyComponents, SignatureComponents,
    proof_inputs_to_circuit, prepare_inputs, CircuitPaths,
};

use base64::Engine;

/// Type alias for our Groth16 over BN254
type GrothBn = Groth16<Bn254>;

/// A native Groth16 proof with public inputs
#[derive(Debug, Clone)]
pub struct NativeProof {
    /// The Groth16 proof
    pub proof: Proof<Bn254>,
    /// Public inputs as field elements (as decimal strings for compatibility)
    pub public_inputs: Vec<String>,
}

impl NativeProof {
    /// Serialize to base64 for embedding in manifests
    pub fn to_base64(&self) -> Result<String> {
        let mut proof_bytes = Vec::new();
        self.proof.serialize_compressed(&mut proof_bytes)
            .map_err(|e| anyhow!("failed to serialize proof: {e}"))?;
        
        let data = NativeProofSerialized {
            proof: base64::engine::general_purpose::STANDARD.encode(&proof_bytes),
            public_inputs: self.public_inputs.clone(),
        };
        
        let json = serde_json::to_vec(&data)?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&json))
    }
    
    /// Deserialize from base64
    pub fn from_base64(encoded: &str) -> Result<Self> {
        let json_bytes = base64::engine::general_purpose::STANDARD.decode(encoded)?;
        let data: NativeProofSerialized = serde_json::from_slice(&json_bytes)?;
        
        let proof_bytes = base64::engine::general_purpose::STANDARD.decode(&data.proof)?;
        let proof = Proof::deserialize_compressed(&proof_bytes[..])
            .map_err(|e| anyhow!("failed to deserialize proof: {e}"))?;
        
        Ok(Self {
            proof,
            public_inputs: data.public_inputs,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct NativeProofSerialized {
    proof: String,
    public_inputs: Vec<String>,
}

/// Paths to circuit artifacts for native proving
pub struct NativeCircuitPaths {
    /// Path to the .r1cs file
    pub r1cs: std::path::PathBuf,
    /// Path to the WASM file for witness generation
    pub wasm: std::path::PathBuf,
    /// Path to store/load the proving key
    pub proving_key: std::path::PathBuf,
    /// Path to store/load the verifying key
    pub verifying_key: std::path::PathBuf,
    /// Build manifest written by setup: which circuit and keys these are
    pub build_manifest: std::path::PathBuf,
    /// Circuit name (the file stem used for the paths above)
    pub circuit_name: String,
}

/// Identifies a circuit and the keys generated for it. Written by setup next
/// to the keys; the anonymizer copies the identifiers into the assertion, and
/// the verifier compares them with its own keys as a diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildManifest {
    pub circuit: String,
    /// Hex SHA-256 of the .r1cs the keys were generated from
    pub r1cs_sha256: String,
    /// Hex SHA-256 of the serialized verifying key
    pub verifying_key_sha256: String,
}

impl NativeCircuitPaths {
    /// Default paths relative to the circuits directory
    pub fn default_for_circuit(circuits_dir: &Path, circuit_name: &str) -> Self {
        let build_dir = circuits_dir.join("build");
        Self {
            r1cs: build_dir.join(format!("{circuit_name}.r1cs")),
            wasm: build_dir.join(format!("{circuit_name}_js/{circuit_name}.wasm")),
            proving_key: build_dir.join(format!("{circuit_name}_native.pk")),
            verifying_key: build_dir.join(format!("{circuit_name}_native.vk")),
            build_manifest: build_dir.join(format!("{circuit_name}_native.build.json")),
            circuit_name: circuit_name.to_string(),
        }
    }
    
    /// Check if setup has been completed (proving and verifying keys exist)
    pub fn setup_complete(&self) -> bool {
        self.proving_key.exists() && self.verifying_key.exists()
    }

    /// Whether a verifying key is available. Verification needs only this,
    /// not the proving key or the .r1cs.
    pub fn can_verify(&self) -> bool {
        self.verifying_key.exists()
    }

    /// The build manifest written by setup, if any.
    pub fn read_build_manifest(&self) -> Result<Option<BuildManifest>> {
        match std::fs::read_to_string(&self.build_manifest) {
            Ok(json) => Ok(Some(serde_json::from_str(&json)
                .map_err(|e| anyhow!("invalid build manifest {:?}: {e}", self.build_manifest))?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow!("failed to read {:?}: {e}", self.build_manifest)),
        }
    }

    /// Check that the keys were generated from the current .r1cs.
    ///
    /// Keys from an older circuit produce proofs that never verify, so callers
    /// should refuse to use them. Keys without a build manifest (from before
    /// it existed) count as stale.
    pub fn keys_match_circuit(&self) -> Result<bool> {
        let Some(manifest) = self.read_build_manifest()? else {
            return Ok(false);
        };
        Ok(manifest.r1cs_sha256 == file_sha256(&self.r1cs)?
            && manifest.verifying_key_sha256 == file_sha256(&self.verifying_key)?)
    }
}

/// Hex SHA-256 of a (possibly multi-GB) file, streamed.
pub fn file_sha256(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path)
        .map_err(|e| anyhow!("failed to open {path:?}: {e}"))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)
        .map_err(|e| anyhow!("failed to read {path:?}: {e}"))?;
    Ok(hex::encode(hasher.finalize()))
}

/// Run the Groth16 trusted setup using native Rust (much faster than snarkjs)
///
/// This generates proving and verifying keys and saves them to disk.
pub fn native_setup(paths: &NativeCircuitPaths) -> Result<()> {
    use std::fs::File;
    use std::io::BufWriter;
    
    println!("Starting native Groth16 setup...");
    println!("  R1CS: {:?}", paths.r1cs);
    println!("  WASM: {:?}", paths.wasm);
    
    if !paths.r1cs.exists() {
        bail!("R1CS file not found: {:?}", paths.r1cs);
    }
    if !paths.wasm.exists() {
        bail!("WASM file not found: {:?}", paths.wasm);
    }
    
    // Load the circuit
    println!("Loading circuit...");
    let cfg = CircomConfig::<Fr>::new(&paths.wasm, &paths.r1cs)
        .map_err(|e| anyhow!("failed to load circuit: {e}"))?;
    let builder = CircomBuilder::new(cfg);
    
    // Build the circuit (with empty inputs for setup)
    let circom = builder.setup();
    
    // Generate proving and verifying keys
    println!("Generating proving and verifying keys (this may take a while)...");
    let mut rng = thread_rng();
    let params = GrothBn::generate_random_parameters_with_reduction(circom, &mut rng)
        .map_err(|e| anyhow!("failed to generate parameters: {e}"))?;
    
    // Save proving key
    println!("Saving proving key to {:?}", paths.proving_key);
    let pk_file = File::create(&paths.proving_key)?;
    let mut pk_writer = BufWriter::new(pk_file);
    params.serialize_compressed(&mut pk_writer)
        .map_err(|e| anyhow!("failed to serialize proving key: {e}"))?;
    
    // Save verifying key
    println!("Saving verifying key to {:?}", paths.verifying_key);
    let vk_file = File::create(&paths.verifying_key)?;
    let mut vk_writer = BufWriter::new(vk_file);
    params.vk.serialize_compressed(&mut vk_writer)
        .map_err(|e| anyhow!("failed to serialize verifying key: {e}"))?;

    // Flush both keys to disk before hashing them for the build manifest.
    use std::io::Write;
    pk_writer.flush()?;
    vk_writer.flush()?;

    // Record which circuit these keys belong to
    let manifest = BuildManifest {
        circuit: paths.circuit_name.clone(),
        r1cs_sha256: file_sha256(&paths.r1cs)?,
        verifying_key_sha256: file_sha256(&paths.verifying_key)?,
    };
    std::fs::write(&paths.build_manifest, serde_json::to_string_pretty(&manifest)?)?;
    
    println!("✅ Native setup complete!");
    Ok(())
}

/// Load the proving key from disk
pub fn load_proving_key(path: &Path) -> Result<ProvingKey<Bn254>> {
    use std::fs::File;
    use std::io::BufReader;
    
    let file = File::open(path)
        .map_err(|e| anyhow!("failed to open proving key: {e}"))?;
    let reader = BufReader::new(file);
    
    ProvingKey::deserialize_compressed(reader)
        .map_err(|e| anyhow!("failed to deserialize proving key: {e}"))
}

/// Load the verifying key from disk
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey<Bn254>> {
    use std::fs::File;
    use std::io::BufReader;
    
    let file = File::open(path)
        .map_err(|e| anyhow!("failed to open verifying key: {e}"))?;
    let reader = BufReader::new(file);
    
    VerifyingKey::deserialize_compressed(reader)
        .map_err(|e| anyhow!("failed to deserialize verifying key: {e}"))
}

/// Generate a ZK proof using native Rust (ark-groth16)
pub fn generate_proof_native(
    circuit_inputs: &CircuitInputs,
    paths: &NativeCircuitPaths,
) -> Result<NativeProof> {
    generate_proof_native_with(circuit_inputs, paths, ProveOptions::default())
}

/// Options for `generate_proof_native_with`.
#[derive(Debug, Clone, Copy)]
pub struct ProveOptions {
    /// Check that the witness satisfies every R1CS constraint before
    /// proving (on by default). ark-circom's witness generator does not stop
    /// on a failing `===` (its exception handler is a no-op, whatever
    /// `sanity_check` says), so without this check an input the circuit
    /// rejects still yields a proof, which only fails verification. Turn it
    /// off only to test that the proof system itself rejects such inputs.
    pub check_witness: bool,
}

impl Default for ProveOptions {
    fn default() -> Self {
        Self { check_witness: true }
    }
}

/// The circuit rejected the inputs: the witness violates an R1CS constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessRejected {
    /// Index of the first unsatisfied constraint.
    pub constraint: usize,
    /// Total number of constraints.
    pub total: usize,
}

impl std::fmt::Display for WitnessRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "circuit rejected the inputs: constraint {} of {} is not satisfied", self.constraint, self.total)
    }
}

impl std::error::Error for WitnessRejected {}

/// Check that `circuit`'s witness satisfies every R1CS constraint
/// (`<A,w> * <B,w> = <C,w>`), with the same wire mapping the prover uses.
pub fn check_witness(circuit: &ark_circom::CircomCircuit<Fr>) -> Result<()> {
    use ark_std::Zero;
    let witness = circuit.witness.as_ref().ok_or_else(|| anyhow!("circuit has no witness"))?;
    let r1cs = &circuit.r1cs;
    let value = |wire: usize| match &r1cs.wire_mapping {
        Some(map) => witness[map[wire]],
        None => witness[wire],
    };
    let eval = |lc: &[(usize, Fr)]| lc.iter().fold(Fr::zero(), |acc, (wire, coeff)| acc + *coeff * value(*wire));
    let total = r1cs.constraints.len();
    for (i, (a, b, c)) in r1cs.constraints.iter().enumerate() {
        if eval(a) * eval(b) != eval(c) {
            return Err(WitnessRejected { constraint: i, total }.into());
        }
    }
    Ok(())
}

/// Generate a proof. Unless `options.check_witness` is off, an input the
/// circuit rejects fails with a `WitnessRejected` error before proving.
pub fn generate_proof_native_with(
    circuit_inputs: &CircuitInputs,
    paths: &NativeCircuitPaths,
    options: ProveOptions,
) -> Result<NativeProof> {
    if !paths.setup_complete() {
        bail!("Setup not complete. Run native_setup first.");
    }
    
    println!("Loading circuit and computing witness...");
    let cfg = CircomConfig::<Fr>::new(&paths.wasm, &paths.r1cs)
        .map_err(|e| anyhow!("failed to load circuit: {e}"))?;
    let mut builder = CircomBuilder::new(cfg);
    
    // Set circuit inputs
    set_circuit_inputs(&mut builder, circuit_inputs)?;

    let circom = builder.build()
        .map_err(|e| anyhow!("failed to build circuit with witness: {e}"))?;

    if options.check_witness {
        println!("Checking witness against the circuit's constraints...");
        check_witness(&circom)?;
    }
    
    let public_inputs = circom.get_public_inputs()
        .ok_or_else(|| anyhow!("failed to get public inputs"))?;
    
    // Load proving key
    println!("Loading proving key...");
    let pk = load_proving_key(&paths.proving_key)?;
    
    // Generate proof
    println!("Generating proof...");
    let mut rng = thread_rng();
    let proof = GrothBn::prove(&pk, circom, &mut rng)
        .map_err(|e| anyhow!("failed to generate proof: {e}"))?;
    
    // Convert public inputs to strings
    let public_input_strings: Vec<String> = public_inputs
        .iter()
        .map(|f| format!("{}", f))
        .collect();
    
    println!("✅ Proof generated!");
    Ok(NativeProof {
        proof,
        public_inputs: public_input_strings,
    })
}

/// Verify a ZK proof using native Rust
pub fn verify_proof_native(
    proof: &NativeProof,
    paths: &NativeCircuitPaths,
) -> Result<bool> {
    use std::str::FromStr;
    
    println!("Loading verifying key...");
    let vk = load_verifying_key(&paths.verifying_key)?;
    let pvk = GrothBn::process_vk(&vk)
        .map_err(|e| anyhow!("failed to process verifying key: {e}"))?;
    
    // Parse public inputs back to field elements
    let public_inputs: Result<Vec<Fr>> = proof.public_inputs
        .iter()
        .map(|s| {
            Fr::from_str(s).map_err(|_| anyhow!("invalid public input: {s}"))
        })
        .collect();
    let public_inputs = public_inputs?;
    
    // Verify
    println!("Verifying proof...");
    let valid = GrothBn::verify_with_processed_vk(&pvk, &public_inputs, &proof.proof)
        .map_err(|e| anyhow!("verification error: {e}"))?;
    
    if valid {
        println!("✅ Proof verified!");
    } else {
        println!("❌ Proof verification failed!");
    }
    
    Ok(valid)
}

/// Set circuit inputs on the builder using the x509_issue_and_possession signal layout.
fn set_circuit_inputs(builder: &mut CircomBuilder<Fr>, inputs: &CircuitInputs) -> Result<()> {
    // caPubKeyX[6] — trusted CA public key X, public input
    for val in inputs.ca_pub_key_x.iter() {
        let bigint: BigInt = val.parse()
            .map_err(|e| anyhow!("invalid caPubKeyX value: {e}"))?;
        builder.push_input("caPubKeyX", bigint);
    }

    // caPubKeyY[6] — trusted CA public key Y, public input
    for val in inputs.ca_pub_key_y.iter() {
        let bigint: BigInt = val.parse()
            .map_err(|e| anyhow!("invalid caPubKeyY value: {e}"))?;
        builder.push_input("caPubKeyY", bigint);
    }

    // claimHash[6] — public input
    for val in inputs.claim_hash.iter() {
        let bigint: BigInt = val.parse()
            .map_err(|e| anyhow!("invalid claimHash value: {e}"))?;
        builder.push_input("claimHash", bigint);
    }

    // photoTimestamp — public input (single field element)
    {
        let bigint: BigInt = inputs.photo_timestamp.parse()
            .map_err(|e| anyhow!("invalid photoTimestamp value: {e}"))?;
        builder.push_input("photoTimestamp", bigint);
    }

    // certDer[1500] — raw certificate bytes, zero-padded, private input
    for val in inputs.cert_der.iter() {
        let bigint: BigInt = val.parse()
            .map_err(|e| anyhow!("invalid certDer byte value: {e}"))?;
        builder.push_input("certDer", bigint);
    }

    // certLen — private input (single field element)
    {
        let bigint: BigInt = inputs.cert_len.parse()
            .map_err(|e| anyhow!("invalid certLen value: {e}"))?;
        builder.push_input("certLen", bigint);
    }

    // certSigR[6] — private input
    for val in inputs.cert_sig_r.iter() {
        let bigint: BigInt = val.parse()
            .map_err(|e| anyhow!("invalid certSigR value: {e}"))?;
        builder.push_input("certSigR", bigint);
    }

    // certSigS[6] — private input
    for val in inputs.cert_sig_s.iter() {
        let bigint: BigInt = val.parse()
            .map_err(|e| anyhow!("invalid certSigS value: {e}"))?;
        builder.push_input("certSigS", bigint);
    }

    // claimSigR[6] — private input
    for val in inputs.claim_sig_r.iter() {
        let bigint: BigInt = val.parse()
            .map_err(|e| anyhow!("invalid claimSigR value: {e}"))?;
        builder.push_input("claimSigR", bigint);
    }

    // claimSigS[6] — private input
    for val in inputs.claim_sig_s.iter() {
        let bigint: BigInt = val.parse()
            .map_err(|e| anyhow!("invalid claimSigS value: {e}"))?;
        builder.push_input("claimSigS", bigint);
    }

    // certNotBefore / certNotAfter — REMOVED: now computed in-circuit by
    // UTCTimeToUnix inside X509Parse.  Only offsets are needed.

    // tbsOffset — private DER structural hint
    {
        let bigint: BigInt = inputs.tbs_offset.parse()
            .map_err(|e| anyhow!("invalid tbsOffset value: {e}"))?;
        builder.push_input("tbsOffset", bigint);
    }

    // tbsLen — private DER structural hint
    {
        let bigint: BigInt = inputs.tbs_len.parse()
            .map_err(|e| anyhow!("invalid tbsLen value: {e}"))?;
        builder.push_input("tbsLen", bigint);
    }

    // spkiXOffset — private DER structural hint
    {
        let bigint: BigInt = inputs.spki_x_offset.parse()
            .map_err(|e| anyhow!("invalid spkiXOffset value: {e}"))?;
        builder.push_input("spkiXOffset", bigint);
    }

    // notBeforeOffset — byte offset of notBefore UTCTime tag (0x17) in certDer
    {
        let bigint: BigInt = inputs.not_before_offset.parse()
            .map_err(|e| anyhow!("invalid notBeforeOffset value: {e}"))?;
        builder.push_input("notBeforeOffset", bigint);
    }

    // notAfterOffset — byte offset of notAfter UTCTime tag (0x17) in certDer
    {
        let bigint: BigInt = inputs.not_after_offset.parse()
            .map_err(|e| anyhow!("invalid notAfterOffset value: {e}"))?;
        builder.push_input("notAfterOffset", bigint);
    }

    // tbsHashPaddedLen — padded byte length for Sha256Bytes(1536)
    {
        let bigint: BigInt = inputs.tbs_hash_padded_len.parse()
            .map_err(|e| anyhow!("invalid tbsHashPaddedLen value: {e}"))?;
        builder.push_input("tbsHashPaddedLen", bigint);
    }

    // tbsHashPaddedBytes[1536] — SHA-256-padded TBS bytes; circuit hashes
    // these in-circuit via Sha256Bytes(1536) inside X509Parse.
    for val in inputs.tbs_padded_bytes.iter() {
        let bigint: BigInt = val.parse()
            .map_err(|e| anyhow!("invalid tbsHashPaddedBytes value: {e}"))?;
        builder.push_input("tbsHashPaddedBytes", bigint);
    }

    Ok(())
}