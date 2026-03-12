use anyhow::Result;
use clap::Parser;
use c2pa_bbs_demo::{HiddenAttributes, PublicAttributes, issue_demo_credential};

/// Issues a toy BBS credential that a holder can later present over a C2PA hash.
#[derive(Debug, Parser)]
#[command(name = "c2pa-bbs-issue", about = "Issue a toy BBS credential for the holder demo.")]
struct IssueArgs {
    /// Output path for the issued credential JSON.
    #[arg(long)]
    output: String,

    /// Revealed issuer attribute embedded in the credential.
    #[arg(long, default_value = "ExampleOrg")]
    issuer: String,

    /// Revealed policy attribute embedded in the credential.
    #[arg(long, default_value = "issuance-policy-v1")]
    policy: String,

    /// Hidden user identifier embedded in the credential.
    #[arg(long, default_value = "user-1234")]
    user_id: String,

    /// Hidden device identifier embedded in the credential.
    #[arg(long, default_value = "device-9876")]
    device_id: String,
}

fn main() -> Result<()> {
    let args = IssueArgs::parse();

    let public_attributes = PublicAttributes {
        issuer: args.issuer,
        policy: args.policy,
    };
    let hidden_attributes = HiddenAttributes {
        user_id: args.user_id,
        device_id: args.device_id,
    };

    let credential = issue_demo_credential(&public_attributes, &hidden_attributes)?;
    std::fs::write(&args.output, serde_json::to_vec_pretty(&credential)?)?;
    Ok(())
}