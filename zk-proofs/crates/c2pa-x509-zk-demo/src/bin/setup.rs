//! Native Rust ZK setup command
//!
//! Run Groth16 trusted setup using ark-groth16 (much faster than snarkjs)

use anyhow::Result;
use c2pa_x509_zk_demo::circuit_native::{NativeCircuitPaths, native_setup};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "c2pa-x509-zk-setup")]
#[command(about = "Run native Groth16 trusted setup for the ZK circuit")]
struct Args {
    /// Path to circuits directory (containing build/ with .r1cs and .wasm)
    #[arg(long, default_value = "circuits")]
    circuits_dir: PathBuf,
    
    /// Circuit name (without extension)
    #[arg(long, default_value = "c2pa_signer_proof")]
    circuit_name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    println!("=== Native Groth16 Trusted Setup ===\n");
    
    let paths = NativeCircuitPaths::default_for_circuit(&args.circuits_dir, &args.circuit_name);
    
    println!("Circuit paths:");
    println!("  R1CS: {:?}", paths.r1cs);
    println!("  WASM: {:?}", paths.wasm);
    println!("  Proving key output: {:?}", paths.proving_key);
    println!("  Verifying key output: {:?}", paths.verifying_key);
    println!();
    
    if paths.setup_complete() {
        println!("⚠️  Setup already complete. Keys exist at:");
        println!("    {:?}", paths.proving_key);
        println!("    {:?}", paths.verifying_key);
        println!("\nDelete these files to re-run setup.");
        return Ok(());
    }
    
    native_setup(&paths)?;
    
    println!("\n✅ Setup complete! You can now generate proofs.");
    
    Ok(())
}
