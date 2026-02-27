pragma circom 2.1.6;

include "./x509_parse.circom";
include "circom-ecdsa-p256/circuits/ecdsa.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

/*
 * X.509 Issuance and Key Possession Proof Circuit
 *
 * This is the primary C2PA signer-privacy circuit.  It proves membership of
 * the prover in the set of certificate holders whose certificate was issued by
 * a known, trusted CA, without revealing WHICH certificate was used.
 *
 * The design takes the raw DER certificate bytes as a private input and parses
 * them inside the circuit.  This is the architecturally sound approach because
 * the parser binds every extracted field (SPKI, validity, issuer) to the same
 * certificate whose CA signature is being checked.  Any design that pre-computes
 * the TBS hash outside the circuit and passes it as a witness would allow a
 * prover to mix a real cert (for the CA sig) with an unrelated key pair (for
 * the claim sig) — breaking the issuance proof.
 *
 * NOTE: X509Parse is currently a scaffold with placeholder outputs.  The
 * constraints that depend on its outputs are shown with working structure but
 * commented where blocked, each with a clear TODO.  The circuit is runnable
 * and produces a valid R1CS, but the proof is not yet sound until X509Parse
 * is fully implemented.
 *
 * Proves (when X509Parse is complete):
 *   1. certDer was signed by the CA whose public key is caPubKeyX/Y
 *   2. The prover holds the private key corresponding to the subject public key
 *      inside certDer (demonstrated by signing claimHash)
 *   3. certNotBefore <= photoTimestamp <= certNotAfter
 *
 * Public Inputs:
 * - caPubKeyX[k], caPubKeyY[k]: Trusted CA's P-256 public key (verifier supplies)
 * - claimHash[k]:                C2PA claim hash (SHA-256) as k n-bit registers
 * - photoTimestamp:               Unix timestamp of when the photo was taken
 *
 * Private Inputs:
 * - certDer[maxCertBytes]: DER-encoded end-entity certificate
 * - certLen:               Actual byte length of certDer
 * - certSigR[k], certSigS[k]: CA's ECDSA signature over TBSCertificate
 * - claimSigR[k], claimSigS[k]: Prover's ECDSA signature over claimHash
 * - certNotBefore, certNotAfter: Certificate validity bounds (Unix timestamps)
 *
 * Parameters for P-256 / secp256r1: n = 43 bits per chunk, k = 6 chunks.
 */

template X509IssueAndPossession(maxCertBytes, n, k) {
    // === Public Inputs ===
    signal input caPubKeyX[k];         // Trusted CA public key X coordinate
    signal input caPubKeyY[k];         // Trusted CA public key Y coordinate
    signal input claimHash[k];         // C2PA claim hash (256 bits as k n-bit chunks)
    signal input photoTimestamp;       // Unix timestamp of photo capture

    // === Private Inputs ===
    signal input certDer[maxCertBytes]; // DER-encoded certificate bytes
    signal input certLen;               // Actual certificate length

    // CA signature over TBSCertificate (r, s)
    signal input certSigR[k];
    signal input certSigS[k];

    // Prover's signature over claimHash (r, s)
    signal input claimSigR[k];
    signal input claimSigS[k];

    // Certificate validity window
    signal input certNotBefore;        // Cert validity start (Unix timestamp)
    signal input certNotAfter;         // Cert validity end (Unix timestamp)

    // === Step 1: Parse Certificate ===
    // Feed the raw DER bytes into X509Parse, which will extract the
    // TBSCertificate byte range, the SPKI, and the issuer DN — all from the
    // same certificate.  Doing this in-circuit is what prevents the key-mixing
    // attack where a prover pairs someone else's cert with their own key pair.
    // X509Parse is currently a scaffold (placeholder zero outputs); real ASN.1
    // parsing is the next implementation step (see x509_parse.circom).
    component parser = X509Parse(maxCertBytes);
    for (var i = 0; i < maxCertBytes; i++) {
        parser.certDer[i] <== certDer[i];
    }
    parser.certLen <== certLen;

    // === Step 2: Verify CA Signature over TBSCertificate ===
    // Proves the certificate was issued by the CA whose public key is
    // caPubKeyX/Y.  The CA's ECDSA signature covers the DER-encoded
    // TBSCertificate, which includes the SPKI, validity, issuer DN, and all
    // extensions — authenticating them all at once.
    //
    // BLOCKED ON: X509Parse must output tbsStart/tbsEnd so that an in-circuit
    // SHA-256 over certDer[tbsStart..tbsEnd] can be computed.
    //
    // TODO (once X509Parse outputs real tbsStart/tbsEnd):
    //   component tbsHash = Sha256Bytes(maxCertBytes);
    //   // mux certDer bytes into tbsHash using tbsStart/tbsEnd
    //
    //   component caVerify = ECDSAVerifyNoPubkeyCheck(n, k);
    //   for (var i = 0; i < k; i++) {
    //       caVerify.r[i]         <== certSigR[i];
    //       caVerify.s[i]         <== certSigS[i];
    //       caVerify.msghash[i]   <== tbsHash.out[i];
    //       caVerify.pubkey[0][i] <== caPubKeyX[i];
    //       caVerify.pubkey[1][i] <== caPubKeyY[i];
    //   }
    //   caVerify.result === 1;

    // === Step 3: Extract Subject Public Key from Certificate ===
    // The SPKI must come from the parsed certificate, not a separate input.
    //
    // BLOCKED ON: X509Parse must output raw P-256 (X, Y) register arrays
    // (parser.spkiX[k] and parser.spkiY[k]).
    //
    // TODO (once X509Parse outputs parser.spkiX and parser.spkiY):
    //   for (var i = 0; i < k; i++) {
    //       subjectPubKeyX[i] <== parser.spkiX[i];
    //       subjectPubKeyY[i] <== parser.spkiY[i];
    //   }
    signal subjectPubKeyX[k];
    signal subjectPubKeyY[k];
    for (var i = 0; i < k; i++) {
        subjectPubKeyX[i] <== 0;  // placeholder — replace with parser.spkiX[i]
        subjectPubKeyY[i] <== 0;  // placeholder — replace with parser.spkiY[i]
    }

    // === Step 4: Verify Claim Signature (key possession) ===
    // Proves the prover holds the private key corresponding to subjectPubKeyX/Y
    // by verifying a fresh ECDSA signature over the C2PA claim hash.
    //
    // BLOCKED ON: Step 3 (real subjectPubKey values from the parsed cert).
    //
    // TODO (once Step 3 is unblocked):
    //   component claimVerify = ECDSAVerifyNoPubkeyCheck(n, k);
    //   for (var i = 0; i < k; i++) {
    //       claimVerify.r[i]         <== claimSigR[i];
    //       claimVerify.s[i]         <== claimSigS[i];
    //       claimVerify.msghash[i]   <== claimHash[i];
    //       claimVerify.pubkey[0][i] <== subjectPubKeyX[i];
    //       claimVerify.pubkey[1][i] <== subjectPubKeyY[i];
    //   }
    //   claimVerify.result === 1;

    // === Step 5: Check Certificate Validity Period ===
    // Enforces certNotBefore <= photoTimestamp <= certNotAfter.
    // The prover supplies certNotBefore/certNotAfter as private inputs; once
    // X509Parse is complete they will be constrained to match the parsed cert
    // fields, eliminating the prover's freedom to choose arbitrary values.
    //
    // Range check: difference fits in 32 bits iff it is non-negative
    // (assuming timestamps are < 2^32).
    signal sinceStart <== photoTimestamp - certNotBefore;
    signal untilEnd   <== certNotAfter   - photoTimestamp;

    component sinceStartBits = Num2Bits(32);
    component untilEndBits   = Num2Bits(32);
    sinceStartBits.in <== sinceStart;
    untilEndBits.in   <== untilEnd;

    // Suppress unused-signal warnings for inputs that are wired only via
    // placeholder paths while the TODOs above are unresolved.
    signal _unusedCertSig   <== certSigR[0]  + certSigS[0];
    signal _unusedClaimSig  <== claimSigR[0] + claimSigS[0];
    signal _unusedCaPubKey  <== caPubKeyX[0] + caPubKeyY[0];
    signal _unusedClaimHash <== claimHash[0];
}

// Parameters: max 1500-byte cert, n=43 bits/chunk, k=6 chunks (P-256 / secp256r1)
component main {public [caPubKeyX, caPubKeyY, claimHash, photoTimestamp]} = X509IssueAndPossession(1500, 43, 6);
