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
    #[arg(long, default_value = "x509_issue_and_possession")]
    circuit_name: String,

    /// Regenerate the keys even if they already exist
    #[arg(long)]
    force: bool,
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
    
    if paths.setup_complete() && !args.force {
        if paths.keys_match_circuit()? {
            println!("✅ Setup already complete for the current circuit. Keys exist at:");
            println!("    {:?}", paths.proving_key);
            println!("    {:?}", paths.verifying_key);
            println!("\nUse --force to regenerate them.");
            return Ok(());
        }
        anyhow::bail!(
            "keys at {:?} were not generated from the current circuit ({:?}); \
             re-run with --force to regenerate them",
            paths.proving_key,
            paths.r1cs,
        );
    }
    
    native_setup(&paths)?;
    
    println!("\n✅ Setup complete! You can now generate proofs.");
    
    Ok(())
}
