//! Prepare the third-party statement's inputs from a signed asset (roadmap E2b).
//!
//! Usage:
//!   c2pa-x509-zk-statement-inputs --input signed.png --trust-list trust-list.pem \
//!       --out inputs.json [--public-out public.json]
//!
//! inputs.json is for `c2pa-zk-gnark prove`/`check`; public.json (the public
//! part only) for `c2pa-zk-gnark verify`.

use anyhow::Result;
use c2pa_x509_zk_demo::third_party::statement_inputs;
use c2pa_x509_zk_demo::TrustList;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "c2pa-x509-zk-statement-inputs", about = "Prepare the third-party statement's inputs from a signed asset")]
struct Args {
    /// The signed asset
    #[arg(long)]
    input: PathBuf,
    /// Trust anchors (PEM, DER, or C2PA trust list JSON)
    #[arg(long)]
    trust_list: PathBuf,
    /// Where to write the prover's inputs (JSON)
    #[arg(long)]
    out: PathBuf,
    /// Where to write the public inputs (JSON)
    #[arg(long)]
    public_out: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let inputs = statement_inputs(&args.input, &TrustList::from_file(&args.trust_list)?)?;
    std::fs::write(&args.out, serde_json::to_vec_pretty(&inputs)?)?;
    if let Some(path) = args.public_out {
        std::fs::write(path, serde_json::to_vec_pretty(&inputs.public)?)?;
    }
    Ok(())
}
