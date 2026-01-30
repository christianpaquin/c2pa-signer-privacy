use anyhow::Result;
use clap::Parser;
use c2pa_bbs_demo::{
    compute_claim_hash, embed_bbs_assertion_into_manifest, generate_bbs_proof, ClaimHash,
    HiddenAttributes, PublicAttributes,
};

/// Creates a C2PA manifest that replaces the COSE signature with a BBS signer proof.
#[derive(Debug, Parser)]
#[command(name = "c2pa-bbs-sign", about = "Create BBS-based private C2PA manifests.")]
struct SignArgs {
    /// Input asset path (existing media file without embedded manifest modifications).
    #[arg(long)]
    input: String,

    /// Output path for the signed asset.
    #[arg(long)]
    output: String,

    /// Issuer attribute revealed in the proof.
    #[arg(long, default_value = "ExampleOrg")]
    issuer: String,

    /// Policy attribute revealed in the proof.
    #[arg(long, default_value = "trusted-editor-v1")]
    policy: String,

    /// Hidden editor identifier for local demos.
    #[arg(long, default_value = "editor-1234")]
    editor_id: String,

    /// Hidden device identifier for local demos.
    #[arg(long, default_value = "device-9876")]
    device_id: String,
}

fn main() -> Result<()> {
    let args = SignArgs::parse();
    run(args)
}

fn run(args: SignArgs) -> Result<()> {
    let claim_hash: ClaimHash = compute_claim_hash(&args.input)?;

    let public_attributes = PublicAttributes {
        issuer: args.issuer,
        policy: args.policy,
    };

    let hidden_attributes = HiddenAttributes {
        editor_id: args.editor_id,
        device_id: args.device_id,
    };

    let generated = generate_bbs_proof(&public_attributes, &hidden_attributes, &claim_hash)?;

    let assertion = c2pa_bbs_demo::BbsSignerProofAssertion::new(
        public_attributes,
        claim_hash,
        generated.proof,
        generated.public_key,
    );

    embed_bbs_assertion_into_manifest(&args.input, &args.output, assertion)?;

    Ok(())
}
