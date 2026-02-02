#!/usr/bin/env bash
#
# Generate test certificates and a C2PA-signed asset for testing the ZK anonymizer
#
# This creates:
# - A root CA certificate and key
# - A leaf certificate signed by the root CA
# - A C2PA-signed asset using the leaf certificate
#
# Usage:
#   ./generate-test-assets.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESOURCES_DIR="${SCRIPT_DIR}/crates/c2pa-x509-zk-demo/resources"
FIXTURES_DIR="${SCRIPT_DIR}/fixtures"

# Colors
GREEN='\033[0;32m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }

# Create directories
mkdir -p "$RESOURCES_DIR"
mkdir -p "$FIXTURES_DIR"

info "=== Generating Test PKI ==="

# Generate Root CA
if [[ ! -f "$RESOURCES_DIR/root-ca.key" ]]; then
    info "Generating Root CA private key..."
    openssl ecparam -genkey -name prime256v1 -noout -out "$RESOURCES_DIR/root-ca.key"
    
    info "Generating Root CA certificate..."
    openssl req -x509 -new -nodes \
        -key "$RESOURCES_DIR/root-ca.key" \
        -sha256 \
        -days 365 \
        -out "$RESOURCES_DIR/root-ca.pem" \
        -subj "/CN=C2PA ZK Demo Root CA/O=C2PA Privacy Demo/C=US" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
    
    info "Root CA created"
else
    info "Root CA already exists"
fi

# Generate Leaf Certificate
if [[ ! -f "$RESOURCES_DIR/signer.key" ]]; then
    info "Generating signer private key..."
    openssl ecparam -genkey -name prime256v1 -noout -out "$RESOURCES_DIR/signer.key"
    
    info "Creating CSR..."
    openssl req -new \
        -key "$RESOURCES_DIR/signer.key" \
        -out "$RESOURCES_DIR/signer.csr" \
        -subj "/CN=Test Signer/O=C2PA Privacy Demo/C=US"
    
    # Create extension file for leaf cert
    cat > "$RESOURCES_DIR/signer.ext" << EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
extendedKeyUsage=critical,1.3.6.1.5.5.7.3.36
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF

    info "Signing leaf certificate with Root CA..."
    openssl x509 -req \
        -in "$RESOURCES_DIR/signer.csr" \
        -CA "$RESOURCES_DIR/root-ca.pem" \
        -CAkey "$RESOURCES_DIR/root-ca.key" \
        -CAcreateserial \
        -out "$RESOURCES_DIR/signer.pem" \
        -days 90 \
        -sha256 \
        -extfile "$RESOURCES_DIR/signer.ext"
    
    info "Signer certificate created"
else
    info "Signer certificate already exists"
fi

# Export to DER format
info "Exporting certificates to DER format..."
openssl x509 -in "$RESOURCES_DIR/root-ca.pem" -outform DER -out "$RESOURCES_DIR/root-ca.der"
openssl x509 -in "$RESOURCES_DIR/signer.pem" -outform DER -out "$RESOURCES_DIR/signer.der"

# Create combined certificate chain (leaf + CA)
cat "$RESOURCES_DIR/signer.pem" "$RESOURCES_DIR/root-ca.pem" > "$RESOURCES_DIR/chain.pem"

info ""
info "=== Certificate Chain Summary ==="
info "Root CA: $RESOURCES_DIR/root-ca.pem"
info "Signer:  $RESOURCES_DIR/signer.pem"
info "Chain:   $RESOURCES_DIR/chain.pem"
info ""

# Check if c2patool is available
if command -v c2patool &> /dev/null; then
    info "=== Creating C2PA-Signed Asset ==="
    
    if [[ -f "$FIXTURES_DIR/cards.png" ]]; then
        # Create a simple manifest definition with signing credentials
        cat > "$FIXTURES_DIR/manifest.json" << EOF
{
    "alg": "es256",
    "private_key": "$RESOURCES_DIR/signer.key",
    "sign_cert": "$RESOURCES_DIR/chain.pem",
    "claim_generator": "c2pa-x509-zk-demo/test-signer",
    "title": "Test Image for ZK Anonymizer",
    "assertions": [
        {
            "label": "c2pa.actions",
            "data": {
                "actions": [
                    {
                        "action": "c2pa.created",
                        "when": "2026-01-12T00:00:00Z",
                        "softwareAgent": "Test Signer"
                    }
                ]
            }
        }
    ]
}
EOF
        
        info "Signing cards.png with c2patool..."
        c2patool "$FIXTURES_DIR/cards.png" \
            -m "$FIXTURES_DIR/manifest.json" \
            -o "$FIXTURES_DIR/signed-cards.png" \
            --force
        
        info "Signed asset created: $FIXTURES_DIR/signed-cards.png"
        info ""
        info "Verify with: c2patool $FIXTURES_DIR/signed-cards.png"
    else
        info "No cards.png found in fixtures, skipping C2PA signing"
    fi
else
    info ""
    info "⚠️  c2patool not found - cannot create signed test asset"
    info "   Install c2patool: cargo install c2patool"
    info "   Or download from: https://github.com/contentauth/c2patool"
    info ""
    info "   After installing, run this script again to create a signed asset."
fi

info ""
info "=== Done ==="
info ""
info "Next steps:"
info "1. If c2patool is not installed, install it and re-run this script"
info "2. Run the editor: cargo run --bin c2pa-x509-zk-editor -- --input fixtures/signed-cards.png --output /tmp/anon.png --ca crates/c2pa-x509-zk-demo/resources/root-ca.pem"
