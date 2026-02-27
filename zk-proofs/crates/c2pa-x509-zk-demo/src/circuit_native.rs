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
        }
    }
    
    /// Check if setup has been completed
    pub fn setup_complete(&self) -> bool {
        self.proving_key.exists() && self.verifying_key.exists()
    }
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
    if !paths.setup_complete() {
        bail!("Setup not complete. Run native_setup first.");
    }
    
    println!("Loading circuit and proving key...");
    let cfg = CircomConfig::<Fr>::new(&paths.wasm, &paths.r1cs)
        .map_err(|e| anyhow!("failed to load circuit: {e}"))?;
    let mut builder = CircomBuilder::new(cfg);
    
    // Set circuit inputs
    set_circuit_inputs(&mut builder, circuit_inputs)?;
    
    // Build the circuit with inputs
    let circom = builder.build()
        .map_err(|e| anyhow!("failed to build circuit with witness: {e}"))?;
    
    let public_inputs = circom.get_public_inputs()
        .ok_or_else(|| anyhow!("failed to get public inputs"))?;
    
    // Load proving key
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

    // certNotBefore — private input (single field element)
    {
        let bigint: BigInt = inputs.cert_not_before.parse()
            .map_err(|e| anyhow!("invalid certNotBefore value: {e}"))?;
        builder.push_input("certNotBefore", bigint);
    }

    // certNotAfter — private input (single field element)
    {
        let bigint: BigInt = inputs.cert_not_after.parse()
            .map_err(|e| anyhow!("invalid certNotAfter value: {e}"))?;
        builder.push_input("certNotAfter", bigint);
    }

    Ok(())
}
