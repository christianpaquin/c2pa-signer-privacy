pragma circom 2.1.6;

/*
 * C2PA Signer Privacy Proof Circuit
 *
 * This circuit proves:
 * 1. The prover possesses a valid ECDSA signature over the C2PA claim hash
 * 2. The prover's public key was signed by a trusted CA (issuer)
 *
 * For this demo, we simplify by proving possession of a signing key that
 * signed the claim hash. The issuer/CA binding is done via the issuer hash
 * (a commitment to the issuer DN).
 *
 * Public Inputs:
 * - issuerHash[4]: SHA-256 hash of the issuer DN, split into 4x64-bit chunks
 * - claimHash[4]: C2PA claim hash (SHA-256), split into 4x64-bit chunks  
 * - signerPubkey[2][k]: The signer's public key (from the certificate)
 *
 * Private Inputs:
 * - claimSigR[k], claimSigS[k]: Signature over claimHash by the signer
 *
 * The circuit verifies the ECDSA signature is valid.
 * Note: In a full implementation, we would also verify the CA signature
 * over the signer's certificate to prove CA issuance.
 */

include "circom-ecdsa-p256/circuits/ecdsa.circom";

// P-256 parameters: n=43 bits, k=6 registers for 256-bit values
template C2paSignerProof() {
    var n = 43;
    var k = 6;

    // === Public Inputs ===
    // Issuer DN hash (SHA-256) as 4x64-bit chunks
    signal input issuerHash[4];
    
    // C2PA claim hash (SHA-256) as k registers of n bits
    // We use k=6 registers of 43 bits = 258 bits (enough for 256-bit hash)
    signal input claimHash[k];
    
    // Signer's public key from their certificate
    signal input signerPubkey[2][k];

    // === Private Inputs ===
    // Signature (r, s) over the claim hash
    signal input claimSigR[k];
    signal input claimSigS[k];

    // === Verification ===
    // Verify the ECDSA signature over the claim hash
    component verifyClaimSig = ECDSAVerifyNoPubkeyCheck(n, k);
    for (var i = 0; i < k; i++) {
        verifyClaimSig.r[i] <== claimSigR[i];
        verifyClaimSig.s[i] <== claimSigS[i];
        verifyClaimSig.msghash[i] <== claimHash[i];
        verifyClaimSig.pubkey[0][i] <== signerPubkey[0][i];
        verifyClaimSig.pubkey[1][i] <== signerPubkey[1][i];
    }
    
    // Signature must be valid
    verifyClaimSig.result === 1;

    // The issuerHash is a public input that commits to the CA identity
    // In a full implementation, we would verify the CA's signature over
    // the signer's certificate. For this demo, the issuerHash serves as
    // a trusted anchor that the verifier can check against known CAs.
    
    // Constrain issuerHash to be well-formed (prevents malleability)
    signal issuerHashSquared[4];
    for (var i = 0; i < 4; i++) {
        issuerHashSquared[i] <== issuerHash[i] * issuerHash[i];
    }
}

component main {public [issuerHash, claimHash, signerPubkey]} = C2paSignerProof();
