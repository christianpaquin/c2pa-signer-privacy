use anyhow::{bail, Result};
use clap::Parser;
use c2pa_bbs_demo::{
    compute_claim_hash_for_embedded_asset,
    extract_bbs_assertion_from_manifest,
    verify_bbs_proof,
    PublicAttributes,
};

/// Validates the embedded BBS signer proof inside a C2PA manifest.
#[derive(Debug, Parser)]
#[command(name = "c2pa-bbs-verify", about = "Verify BBS signer privacy manifests.")]
struct VerifyArgs {
    /// Asset path to verify.
    #[arg(long)]
    input: String,

    /// Expected issuer attribute.
    #[arg(long)]
    issuer: Option<String>,

    /// Expected policy attribute.
    #[arg(long)]
    policy: Option<String>,
}

fn main() -> Result<()> {
    let args = VerifyArgs::parse();
    run(args)
}

fn run(args: VerifyArgs) -> Result<()> {
    // Disable c2pa's built-in COSE signature verification so we can extract the
    // manifest even though our custom BBS algorithm (-65535) is not recognized.
    // We perform our own BBS proof verification below.
    c2pa::settings::Settings::from_string(
        r#"{ "verify": { "verify_after_reading": false } }"#,
        "json",
    )
    .map_err(|e| anyhow::anyhow!("failed to configure c2pa settings: {e}"))?;

    let assertion = extract_bbs_assertion_from_manifest(&args.input)?;

    ensure_expected_attributes(&assertion.public_attributes, args.issuer.as_ref(), args.policy.as_ref())?;

    let expected_hash = compute_claim_hash_for_embedded_asset(&args.input)?;
    verify_bbs_proof(&assertion, &expected_hash)?;

    println!("BBS signer proof verified successfully.");
    println!("  issuer: {}", assertion.public_attributes.issuer);
    println!("  policy: {}", assertion.public_attributes.policy);
    println!("  claim_hash: {}", expected_hash.0);

    Ok(())
}

fn ensure_expected_attributes(attrs: &PublicAttributes, issuer: Option<&String>, policy: Option<&String>) -> Result<()> {
    if let Some(expected_issuer) = issuer {
        if attrs.issuer != *expected_issuer {
            bail!("issuer mismatch: expected {}, found {}", expected_issuer, attrs.issuer);
        }
    }

    if let Some(expected_policy) = policy {
        if attrs.policy != *expected_policy {
            bail!("policy mismatch: expected {}, found {}", expected_policy, attrs.policy);
        }
    }

    Ok(())
}
