#!/usr/bin/env bash
#
# Build script for X.509 ZK circuits
#
# Prerequisites:
# - circom >= 2.1.6 (https://docs.circom.io/getting-started/installation/)
# - Node.js >= 18
# - Powers of Tau file (pot20_final.ptau or larger)
#
# Usage:
#   ./build.sh [--download-ptau]
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
CIRCUIT_NAME="x509_issue_and_possession"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check prerequisites
check_prereqs() {
    info "Checking prerequisites..."
    
    if ! command -v circom &> /dev/null; then
        error "circom not found. Install from https://docs.circom.io/getting-started/installation/"
    fi
    
    if ! command -v node &> /dev/null; then
        error "Node.js not found. Install Node.js >= 18"
    fi
    
    if ! command -v snarkjs &> /dev/null; then
        warn "snarkjs not in PATH, will use npx"
    fi
    
    info "All prerequisites found"
}

# Download Powers of Tau if requested
download_ptau() {
    local PTAU_FILE="${SCRIPT_DIR}/pot20_final.ptau"
    
    if [[ -f "$PTAU_FILE" ]]; then
        info "Powers of Tau file already exists"
        return
    fi
    
    info "Downloading Powers of Tau (pot20, ~600MB)..."
    warn "This may take several minutes..."
    
    curl -L -o "$PTAU_FILE" \
        "https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_20.ptau"
    
    info "Powers of Tau downloaded"
}

# Install npm dependencies
install_deps() {
    info "Installing npm dependencies..."
    cd "$SCRIPT_DIR"
    npm install
}

# Compile circuits
compile_circuits() {
    info "Compiling ${CIRCUIT_NAME}.circom..."
    
    mkdir -p "$BUILD_DIR"
    
    circom "${SCRIPT_DIR}/${CIRCUIT_NAME}.circom" \
        --r1cs \
        --wasm \
        --sym \
        -o "$BUILD_DIR"
    
    info "Circuit compiled successfully"
    info "  R1CS: ${BUILD_DIR}/${CIRCUIT_NAME}.r1cs"
    info "  WASM: ${BUILD_DIR}/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm"
}

# Generate proving/verification keys
generate_keys() {
    local PTAU_FILE="${SCRIPT_DIR}/pot20_final.ptau"
    
    if [[ ! -f "$PTAU_FILE" ]]; then
        error "Powers of Tau file not found. Run with --download-ptau first."
    fi
    
    info "Generating initial zkey (Groth16 setup)..."
    npx snarkjs groth16 setup \
        "${BUILD_DIR}/${CIRCUIT_NAME}.r1cs" \
        "$PTAU_FILE" \
        "${BUILD_DIR}/${CIRCUIT_NAME}_0000.zkey"
    
    info "Contributing to ceremony (demo contribution)..."
    npx snarkjs zkey contribute \
        "${BUILD_DIR}/${CIRCUIT_NAME}_0000.zkey" \
        "${BUILD_DIR}/${CIRCUIT_NAME}.zkey" \
        --name="C2PA Demo Contribution" \
        -v
    
    info "Exporting verification key..."
    npx snarkjs zkey export verificationkey \
        "${BUILD_DIR}/${CIRCUIT_NAME}.zkey" \
        "${BUILD_DIR}/verification_key.json"
    
    info "Keys generated successfully"
    info "  Proving key: ${BUILD_DIR}/${CIRCUIT_NAME}.zkey"
    info "  Verification key: ${BUILD_DIR}/verification_key.json"
}

# Main
main() {
    cd "$SCRIPT_DIR"
    
    # Parse arguments
    DOWNLOAD_PTAU=false
    for arg in "$@"; do
        case $arg in
            --download-ptau)
                DOWNLOAD_PTAU=true
                ;;
        esac
    done
    
    info "=== Building C2PA X.509 ZK Circuits ==="
    
    check_prereqs
    
    if $DOWNLOAD_PTAU; then
        download_ptau
    fi
    
    install_deps
    compile_circuits
    
    if [[ -f "${SCRIPT_DIR}/pot20_final.ptau" ]]; then
        generate_keys
        info "=== Build complete! ==="
    else
        warn "Skipping key generation (no Powers of Tau file)"
        warn "Run with --download-ptau to download and generate keys"
        info "=== Compilation complete (keys not generated) ==="
    fi
}

main "$@"
