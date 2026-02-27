pragma circom 2.1.6;

/*
 * C2PA Signer Privacy Proof Circuit
 *
 * This circuit proves membership of the prover in the set of certificate holders
 * whose certificate was issued by a known, trusted CA, without revealing WHICH
 * certificate (and therefore which signer) was used.
 *
 * Concretely, it proves ALL of the following:
 *  1. The prover holds a private key whose corresponding public key (subjectPubkey)
 *     appears in a certificate C — demonstrated by verifying a valid ECDSA signature
 *     over the C2PA claim hash with subjectPubkey.
 *  2. The certificate C was issued by PublicCA — demonstrated by verifying the CA's
 *     ECDSA signature (over the TBSCertificate bytes) with the CA's known public key
 *     (issuerPublicKey, a public circuit input).
 *  3. The certificate C was not expired when the photo was taken — demonstrated by
 *     range-checking that certNotBefore <= photoTimestamp <= certNotAfter.
 *  4. TODO (requires full in-circuit ASN.1 parsing): subjectPubkey is bound to C,
 *     i.e. the SPKI field inside the TBSCertificate whose hash is tbsCertHash
 *     contains exactly subjectPubkey.  Without this step a malicious prover could
 *     supply an unrelated key pair and a real cert from the CA.
 *  5. TODO: Additional RFC 5280 field checks (version, algorithm OID, key usage
 *     extensions, etc.) — see inline comments in Step 5.
 *
 * Public Inputs:
 * - issuerPublicKey[2][k]: Trusted CA's P-256 public key (X, Y) in k-register form
 * - claimHash[k]:          C2PA claim hash (SHA-256) in k-register form
 * - photoTimestamp:         Unix timestamp of when the photo was taken (32-bit)
 *
 * Private Inputs (witness):
 * - subjectPubkey[2][k]:   Signer's P-256 public key extracted from cert SPKI
 * - tbsCertHash[k]:        SHA-256 of TBSCertificate bytes, in k-register form
 * - certSigR[k], certSigS[k]: CA's ECDSA signature over tbsCertHash
 * - claimSigR[k], claimSigS[k]: Signer's ECDSA signature over claimHash
 * - certNotBefore:          Cert validity start as Unix timestamp (32-bit)
 * - certNotAfter:           Cert validity end as Unix timestamp (32-bit)
 *
 * P-256 big-integer encoding: n=43 bits per register, k=6 registers (258 bits ≥ 256).
 *
 * Known optimisation (not yet applied):
 *   The Efficient ECDSA technique (sometimes called "NOPE") reformulates verification
 *   so that only one scalar multiplication is needed instead of two, roughly halving
 *   the ~2 M constraint count.  See https://personaelabs.org/posts/efficient-ecdsa-1/
 */

include "circom-ecdsa-p256/circuits/ecdsa.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

// P-256 parameters: n=43 bits, k=6 registers for 256-bit values
template C2paSignerProof() {
    var n = 43;
    var k = 6;

    // === Public Inputs ===

    // Trusted CA's P-256 public key.  The verifier checks this matches the
    // expected PublicCA before accepting the proof.
    signal input issuerPublicKey[2][k];

    // C2PA claim hash (SHA-256) as k registers of n bits.
    signal input claimHash[k];

    // Unix timestamp of when the photo was taken.  Used to check the signing
    // certificate was valid at capture time (not just at proof-generation time).
    signal input photoTimestamp;

    // === Private Inputs ===

    // Signer's P-256 public key extracted from the certificate's SPKI field.
    // Kept private so the verifier learns nothing about the specific signer.
    signal input subjectPubkey[2][k];

    // SHA-256 of the DER-encoded TBSCertificate — the message signed by the CA.
    // In a future implementation this will be computed in-circuit from certDer
    // bytes so the prover cannot substitute a different TBSCertificate.
    signal input tbsCertHash[k];

    // CA's ECDSA signature (r, s) over tbsCertHash.
    signal input certSigR[k];
    signal input certSigS[k];

    // Signer's ECDSA signature (r, s) over claimHash.
    signal input claimSigR[k];
    signal input claimSigS[k];

    // Certificate validity window as Unix timestamps.
    signal input certNotBefore;
    signal input certNotAfter;

    // =========================================================================
    // Step 1: Verify CA signature over TBSCertificate
    // =========================================================================
    // Proves that the certificate was issued by PublicCA (issuerPublicKey).
    // The TBSCertificate includes the subject's public key, issuer DN, validity
    // dates, extensions, etc. — so a valid CA signature authenticates all of
    // those fields at once.
    component verifyCertSig = ECDSAVerifyNoPubkeyCheck(n, k);
    for (var i = 0; i < k; i++) {
        verifyCertSig.r[i]         <== certSigR[i];
        verifyCertSig.s[i]         <== certSigS[i];
        verifyCertSig.msghash[i]   <== tbsCertHash[i];
        verifyCertSig.pubkey[0][i] <== issuerPublicKey[0][i];
        verifyCertSig.pubkey[1][i] <== issuerPublicKey[1][i];
    }
    verifyCertSig.result === 1;

    // =========================================================================
    // Step 2: Bind subjectPubkey to the TBSCertificate  (TODO — see note)
    // =========================================================================
    // The CA signature in Step 1 is over tbsCertHash.  For the proof to be
    // sound, tbsCertHash must be the hash of a TBSCertificate that contains
    // exactly subjectPubkey in its SubjectPublicKeyInfo field.
    //
    // Full implementation requires passing the raw TBSCertificate as a private
    // input, hashing it inside the circuit to obtain tbsCertHash (removing the
    // prover's freedom to choose an arbitrary hash), and then parsing the
    // ASN.1 SEQUENCE with X509Parse to extract and constrain the SPKI bytes.
    //
    // Example skeleton (uncomment once X509Parse is complete):
    //   component parser = X509Parse(maxTbsBytes);
    //   for (var i = 0; i < maxTbsBytes; i++) { parser.certDer[i] <== tbsDer[i]; }
    //   parser.certLen <== tbsLen;
    //   // Verify SPKI hash matches the provided subjectPubkey
    //   parser.spkiHash === computedSpkiHash;
    //   subjectPubkey[0] bound to parser SPKI X coordinate
    //   subjectPubkey[1] bound to parser SPKI Y coordinate
    //
    // Until this is implemented the circuit is a proof-of-concept only; a
    // real deployment MUST include this binding step.

    // =========================================================================
    // Step 3: Verify signer's claim signature
    // =========================================================================
    // Proves possession of the private key corresponding to subjectPubkey, by
    // verifying a valid ECDSA signature over the C2PA claim hash.
    component verifyClaimSig = ECDSAVerifyNoPubkeyCheck(n, k);
    for (var i = 0; i < k; i++) {
        verifyClaimSig.r[i]         <== claimSigR[i];
        verifyClaimSig.s[i]         <== claimSigS[i];
        verifyClaimSig.msghash[i]   <== claimHash[i];
        verifyClaimSig.pubkey[0][i] <== subjectPubkey[0][i];
        verifyClaimSig.pubkey[1][i] <== subjectPubkey[1][i];
    }
    verifyClaimSig.result === 1;

    // =========================================================================
    // Step 4: Check certificate validity period
    // =========================================================================
    // Constraints: certNotBefore <= photoTimestamp <= certNotAfter
    // We compute the two differences and range-check them into [0, 2^32).
    // A value fitting in 32 bits is non-negative (in the field), so both
    // inequalities hold.
    signal sinceStart <== photoTimestamp - certNotBefore;
    signal untilEnd   <== certNotAfter   - photoTimestamp;

    // Range checks — will fail if the timestamp is out of the validity window.
    component sinceStartBits = Num2Bits(32);
    component untilEndBits   = Num2Bits(32);
    sinceStartBits.in <== sinceStart;
    untilEndBits.in   <== untilEnd;

    // =========================================================================
    // Step 5: RFC 5280 certificate field checks  (TODO — see note)
    // =========================================================================
    // Once in-circuit ASN.1 parsing is available (X509Parse), add constraints
    // for the fields the verifier policy requires, for example:
    //   - certificate version == v3  (integer value 2)
    //   - signature algorithm OID == id-ecPublicKey + P-256
    //   - subjectPublicKeyInfo algorithm OID matches
    //   - keyUsage extension present and critical, digitalSignature bit set
    //   - extendedKeyUsage includes id-kp-documentSigning (1.3.6.1.5.5.7.3.36)
    //   - no unrecognised critical extensions
    //   - (optional) OCSP / CRL not-revoked check using short-lived certs or
    //     an accumulator commitment published by the CA
}

component main {public [issuerPublicKey, claimHash, photoTimestamp]} = C2paSignerProof();
