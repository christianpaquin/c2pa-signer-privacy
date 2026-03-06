use anyhow::Result;
use clap::Parser;
use c2pa_bbs_demo::{
    compute_claim_hash, embed_bbs_assertion_into_manifest, generate_bbs_proof_from_credential,
    ClaimHash, IssuedCredential,
};

/// Creates a C2PA manifest by presenting a previously issued BBS credential.
#[derive(Debug, Parser)]
#[command(name = "c2pa-bbs-sign", about = "Create BBS-based private C2PA manifests.")]
struct SignArgs {
    /// Input asset path (existing media file without embedded manifest modifications).
    #[arg(long)]
    input: String,

    /// Output path for the signed asset.
    #[arg(long)]
    output: String,

    /// Path to a previously issued toy BBS credential (JSON).
    #[arg(long)]
    credential: String,
}

fn main() -> Result<()> {
    let args = SignArgs::parse();
    run(args)
}

fn run(args: SignArgs) -> Result<()> {
    let claim_hash: ClaimHash = compute_claim_hash(&args.input)?;
    let credential: IssuedCredential = serde_json::from_str(&std::fs::read_to_string(&args.credential)?)?;
    let generated = generate_bbs_proof_from_credential(&credential, &claim_hash)?;

    let assertion = c2pa_bbs_demo::BbsSignerProofAssertion::new(
        credential.public_attributes,
        claim_hash,
        generated.proof,
        generated.issuer_public_key,
    );

    embed_bbs_assertion_into_manifest(&args.input, &args.output, assertion)?;

    Ok(())
}
