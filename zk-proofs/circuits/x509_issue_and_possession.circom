pragma circom 2.1.6;

include "./x509_parse.circom";
// include "../node_modules/circom-ecdsa/circuits/ecdsa.circom";

/*
 * X.509 Issuance and Key Possession Circuit
 *
 * This circuit proves:
 * 1. A certificate was issued by a specific CA (signature verification)
 * 2. The prover possesses the private key for that certificate
 *    (by verifying their signature over a message)
 *
 * Public Inputs:
 * - issuerHash: Hash of the expected issuer DN
 * - caPublicKey: CA's public key (for cert signature verification)
 * - claimHash: The C2PA claim hash that was signed
 *
 * Private Inputs:
 * - certDer: The DER-encoded certificate
 * - certSignature: CA's signature over the TBSCertificate
 * - claimSignature: Prover's signature over claimHash
 *
 * The circuit outputs nothing additional - the constraints prove the relations.
 */

// Parameters for P-256 / secp256r1
// n = 64 bits per chunk, k = 4 chunks for 256-bit values

template X509IssueAndPossession(maxCertBytes, n, k) {
    // === Public Inputs ===
    signal input issuerHash;           // Expected hash of issuer DN
    signal input claimHash[k];         // C2PA claim hash (256 bits as k chunks)
    signal input caPubKeyX[k];         // CA public key X coordinate
    signal input caPubKeyY[k];         // CA public key Y coordinate

    // === Private Inputs ===
    signal input certDer[maxCertBytes]; // DER-encoded certificate
    signal input certLen;                // Actual certificate length
    
    // CA signature over TBSCertificate (r, s components)
    signal input certSigR[k];
    signal input certSigS[k];
    
    // Prover's signature over claim hash (r, s components)
    signal input claimSigR[k];
    signal input claimSigS[k];

    // === Step 1: Parse Certificate ===
    component parser = X509Parse(maxCertBytes);
    for (var i = 0; i < maxCertBytes; i++) {
        parser.certDer[i] <== certDer[i];
    }
    parser.certLen <== certLen;

    // === Step 2: Verify Issuer Matches ===
    // The parsed issuer hash must match the expected issuer
    issuerHash === parser.issuerHash;

    // === Step 3: Verify CA Signature ===
    // Hash the TBSCertificate and verify CA signature
    // This proves the certificate was issued by the CA
    //
    // TODO: Implement using circom-ecdsa ECDSAVerifyNoPubkeyCheck
    // component caVerify = ECDSAVerifyNoPubkeyCheck(n, k);
    // caVerify.r <== certSigR;
    // caVerify.s <== certSigS;
    // caVerify.msghash <== sha256(certDer[tbsStart..tbsEnd]);
    // caVerify.pubkey[0] <== caPubKeyX;
    // caVerify.pubkey[1] <== caPubKeyY;
    // caVerify.result === 1;

    // === Step 4: Extract Subject Public Key ===
    // Get the public key from the certificate SPKI
    // This is the key we'll verify the claim signature against
    //
    // TODO: Extract from parser.spkiHash or parse SPKI directly
    signal subjectPubKeyX[k];
    signal subjectPubKeyY[k];
    
    // Placeholder - would be extracted from cert
    for (var i = 0; i < k; i++) {
        subjectPubKeyX[i] <== 0;
        subjectPubKeyY[i] <== 0;
    }

    // === Step 5: Verify Claim Signature ===
    // Verify the prover's signature over the claim hash
    // This proves possession of the private key
    //
    // TODO: Implement using circom-ecdsa ECDSAVerifyNoPubkeyCheck
    // component claimVerify = ECDSAVerifyNoPubkeyCheck(n, k);
    // claimVerify.r <== claimSigR;
    // claimVerify.s <== claimSigS;
    // claimVerify.msghash <== claimHash;
    // claimVerify.pubkey[0] <== subjectPubKeyX;
    // claimVerify.pubkey[1] <== subjectPubKeyY;
    // claimVerify.result === 1;

    // === Constraint Check ===
    // For now, just add a dummy constraint to make the circuit valid
    signal dummy;
    dummy <== issuerHash * issuerHash;
}

// Default parameters:
// - 1500 byte max cert size
// - n=64 bits per chunk
// - k=4 chunks for 256-bit values
component main {public [issuerHash, claimHash, caPubKeyX, caPubKeyY]} = X509IssueAndPossession(1500, 64, 4);
