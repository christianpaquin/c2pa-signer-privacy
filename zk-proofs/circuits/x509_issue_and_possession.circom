pragma circom 2.1.6;

include "./x509_parse.circom";
include "circom-ecdsa-p256/circuits/ecdsa.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

/*
 * X.509 Issuance and Key Possession Proof Circuit
 *
 * This is the primary C2PA signer-privacy circuit.  It proves that the prover
 * holds a private key whose corresponding certificate was issued by a trusted
 * CA, without revealing which certificate was used.
 *
 * The raw DER certificate bytes are a private input.  X509Parse verifies the
 * DER structure and extracts the subject public key in-circuit.  Binding the
 * SPKI to the same DER bytes that carry the CA signature (Step 2) prevents
 * the key-mixing attack where a prover pairs someone else's CA-signed cert
 * with their own key pair.
 *
 * Current implementation status:
 *
 *   Step 1 — DER parsing (X509Parse): ACTIVE
 *     Verifies DER structure, extracts SPKI (spkiX, spkiY).
 *
 *   Step 2 — CA signature over TBSCertificate: ACTIVE (in-circuit SHA-256)
 *     X509Parse extracts the raw TBS bytes from certDer, runs Sha256Bytes
 *     in-circuit (from @zk-email/circuits), and packs the resulting 256 bits
 *     into k registers used as the ECDSA message hash for the CA signature
 *     check.  The prover supplies tbsHashPaddedLen (the SHA-256-padded byte
 *     length) as a structural hint verified by Sha256Bytes.
 *
 *   Step 3 — Extract subject public key: ACTIVE
 *     Wires parser.spkiX/Y to subjectPubKeyX/Y.
 *
 *   Step 4 — Signer's claim signature (key possession): ACTIVE
 *     Verifies that the prover's ECDSA signature over claimHash is valid
 *     under the parsed subject public key.  This proves the prover holds
 *     the private key corresponding to the certificate's SPKI.
 *
 *   Step 5 — Certificate validity period: ACTIVE
 *     X509Parse parses the notBefore and notAfter UTCTime fields from certDer
 *     in-circuit and converts them to Unix timestamps.  The circuit enforces
 *     parser.notBefore ≤ photoTimestamp ≤ parser.notAfter.
 *
 * Proves:
 *   1. SHA-256(TBSCertificate bytes from certDer) is signed by caPubKeyX/Y
 *      — certDer was issued by the trusted CA
 *   2. The prover holds the private key corresponding to the SPKI in certDer
 *      — demonstrated by a fresh ECDSA signature over claimHash
 *   3. parser.notBefore ≤ photoTimestamp ≤ parser.notAfter
 *      — the certificate was valid when the photo was taken
 *
 * Public Inputs:
 *   caPubKeyX[k], caPubKeyY[k] — Trusted CA's P-256 public key (verifier-supplied)
 *   claimHash[k]               — C2PA claim hash (SHA-256) as k n-bit registers
 *   photoTimestamp             — Unix timestamp of when the photo was taken
 *
 * Private Inputs:
 *   certDer[maxCertBytes]           — DER-encoded end-entity certificate
 *   certLen                         — Actual byte length of certDer
 *   tbsOffset                       — Byte offset of TBSCertificate SEQUENCE tag
 *   tbsLen                          — Declared length value from TBS DER header
 *   spkiXOffset                     — Byte offset of the X coordinate (after 0x04)
 *   notBeforeOffset                 — Byte offset of notBefore UTCTime tag (0x17)
 *   notAfterOffset                  — Byte offset of notAfter  UTCTime tag (0x17)
 *   tbsHashPaddedLen                — Padded byte length for SHA-256 of TBS slice
 *   certSigR[k], certSigS[k]       — CA's ECDSA signature over TBSCertificate
 *   claimSigR[k], claimSigS[k]     — Prover's ECDSA signature over claimHash
 *
 * Parameters for P-256 / secp256r1: n = 43 bits per chunk, k = 6 chunks.
 */

template X509IssueAndPossession(maxCertBytes, n, k) {
    // === Public Inputs ===
    signal input caPubKeyX[k];         // Trusted CA public key X coordinate
    signal input caPubKeyY[k];         // Trusted CA public key Y coordinate
    signal input claimHash[k];         // C2PA claim hash (256 bits as k n-bit chunks)
    signal input photoTimestamp;       // Unix timestamp of photo capture

    // === Private Inputs — certificate bytes ===
    signal input certDer[maxCertBytes]; // DER-encoded certificate bytes
    signal input certLen;               // Actual certificate length

    // === Private Inputs — DER structural hints (verified by X509Parse) ===
    signal input tbsOffset;        // Byte offset of TBSCertificate SEQUENCE tag
    signal input tbsLen;           // Declared byte-length value from TBS DER header
    signal input spkiXOffset;      // Byte offset of the 32-byte X coordinate (after 0x04)
    signal input notBeforeOffset;  // Byte offset of notBefore UTCTime tag (0x17)
    signal input notAfterOffset;   // Byte offset of notAfter  UTCTime tag (0x17)
    signal input tbsHashPaddedLen; // SHA-256 padded byte length of TBS slice
    signal input tbsHashPaddedBytes[1536]; // TBS bytes + SHA-256 padding, zero-padded to 1536

    // === Private Inputs — signatures ===
    signal input certSigR[k];   // CA's ECDSA signature r over TBSCertificate
    signal input certSigS[k];   // CA's ECDSA signature s over TBSCertificate
    signal input claimSigR[k];  // Prover's ECDSA signature r over claimHash
    signal input claimSigS[k];  // Prover's ECDSA signature s over claimHash

    // =========================================================================
    // Step 1: Parse Certificate
    // =========================================================================
    // Feed the raw DER bytes into X509Parse, which verifies the DER structure
    // and extracts the subject public key.  Doing this in-circuit is what
    // prevents the key-mixing attack: the SPKI is provably from the same
    // certificate bytes that the CA signed (once Step 2 is complete).
    // maxTbsPadded = next multiple of 64 >= maxCertBytes-16 = 1536 for 1500.
    var maxTbsPadded = 1536;
    component parser = X509Parse(maxCertBytes, maxTbsPadded, n, k);
    for (var i = 0; i < maxCertBytes; i++) {
        parser.certDer[i] <== certDer[i];
    }
    parser.certLen          <== certLen;
    parser.tbsOffset        <== tbsOffset;
    parser.tbsLen           <== tbsLen;
    parser.spkiXOffset      <== spkiXOffset;
    parser.notBeforeOffset  <== notBeforeOffset;
    parser.notAfterOffset   <== notAfterOffset;
    parser.tbsHashPaddedLen <== tbsHashPaddedLen;
    for (var i = 0; i < 1536; i++) {
        parser.tbsHashPaddedBytes[i] <== tbsHashPaddedBytes[i];
    }

    // =========================================================================
    // Step 2: Verify CA Signature over TBSCertificate
    // =========================================================================
    // Proves the certificate was issued by the CA whose public key is caPubKeyX/Y.
    //
    // parser.tbsHashBits[256] is the SHA-256 of the raw TBS bytes, computed
    // fully in-circuit by X509Parse using Sha256Bytes from @zk-email/circuits.
    // We pack these 256 bits into k n-bit BigInt registers and verify the CA's
    // ECDSA signature over them.
    //
    // Soundness: the hash is computed over certDer[tbsOffset..tbsOffset+4+tbsLen]
    // — the exact same bytes that carry certSigR/S — so a malicious prover
    // cannot substitute a foreign TBS hash.
    component tbsHashPack = BitsToRegisters(n, k);
    for (var i = 0; i < 256; i++) {
        tbsHashPack.bits[i] <== parser.tbsHashBits[i];
    }

    component caVerify = ECDSAVerifyNoPubkeyCheck(n, k);
    for (var i = 0; i < k; i++) {
        caVerify.r[i]         <== certSigR[i];
        caVerify.s[i]         <== certSigS[i];
        caVerify.msghash[i]   <== tbsHashPack.regs[i];
        caVerify.pubkey[0][i] <== caPubKeyX[i];
        caVerify.pubkey[1][i] <== caPubKeyY[i];
    }
    caVerify.result === 1;

    // =========================================================================
    // Step 3: Wire Subject Public Key from Certificate
    // =========================================================================
    // parser.spkiX/Y are the X509Parse-extracted P-256 coordinates, verified to
    // reside at spkiXOffset within certDer via the 0x04 EC point marker check.
    signal subjectPubKeyX[k];
    signal subjectPubKeyY[k];
    for (var i = 0; i < k; i++) {
        subjectPubKeyX[i] <== parser.spkiX[i];
        subjectPubKeyY[i] <== parser.spkiY[i];
    }

    // =========================================================================
    // Step 4: Verify Claim Signature (key possession)
    // =========================================================================
    // Proves the prover holds the private key corresponding to subjectPubKeyX/Y
    // by verifying a fresh ECDSA signature over the C2PA claim hash.
    //
    // Privacy note: claimSigR and claimSigS are private inputs.  A fresh
    // signing nonce is used each time, so the proof does not reveal the
    // certificate or the private key.
    component claimVerify = ECDSAVerifyNoPubkeyCheck(n, k);
    for (var i = 0; i < k; i++) {
        claimVerify.r[i]         <== claimSigR[i];
        claimVerify.s[i]         <== claimSigS[i];
        claimVerify.msghash[i]   <== claimHash[i];
        claimVerify.pubkey[0][i] <== subjectPubKeyX[i];
        claimVerify.pubkey[1][i] <== subjectPubKeyY[i];
    }
    claimVerify.result === 1;

    // =========================================================================
    // Step 5: Check Certificate Validity Period
    // =========================================================================
    // Enforces parser.notBefore ≤ photoTimestamp ≤ parser.notAfter.
    //
    // parser.notBefore and parser.notAfter are Unix timestamps produced by
    // UTCTimeToUnix inside X509Parse — they are derived from the certDer bytes
    // verified in Step 1 and are no longer free prover inputs.
    //
    // Range check via Num2Bits(32): a difference fits in 32 unsigned bits iff it
    // is non-negative and ≤ 2^32-1.  Unix timestamps fit in 32 bits through 2106.
    signal sinceStart <== photoTimestamp - parser.notBefore;
    signal untilEnd   <== parser.notAfter - photoTimestamp;

    component sinceStartBits = Num2Bits(32);
    component untilEndBits   = Num2Bits(32);
    sinceStartBits.in <== sinceStart;
    untilEndBits.in   <== untilEnd;

}

// Parameters: max 1500-byte cert, n=43 bits/chunk, k=6 chunks (P-256 / secp256r1)
component main {public [caPubKeyX, caPubKeyY, claimHash, photoTimestamp]} = X509IssueAndPossession(1500, 43, 6);
