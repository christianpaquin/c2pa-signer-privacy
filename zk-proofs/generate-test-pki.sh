#!/usr/bin/env bash
#
# Generate a test PKI that mimics a real C2PA deployment, with a 3-cert chain:
#
#   root CA  ->  issuing CA (pathlen:0, itself a trust anchor)  ->  signer
#
# All keys are P-256 and all certificates are signed with ECDSA-SHA256, the
# combination the circuit currently verifies. The signer certificate carries
# the C2PA claim-signing EKU and a ~90-day lifetime.
#
# --mirror instead mirrors a real device deployment on the official trust
# list (roadmap E2b): P-384 root and issuing CA signing with ECDSA-SHA384, a
# P-256 signer certificate with the extensions real ones carry (key usage
# digitalSignature and nonRepudiation; EKU emailProtection and C2PA claim
# signing; an OCSP and CA-issuers AIA), and a test time-stamp authority:
#   tsa-root.{pem,der,key}      TSA root (P-384)
#   tsa-ca.{pem,der,key}        TSA issuing CA (P-384, pathlen:0, timeStamping
#                               EKU; itself a TSA trust anchor)
#   tsa.{pem,der,key}           TSA certificate (P-256, critical timeStamping
#                               EKU), issued by the TSA issuing CA (ECDSA-SHA384)
#   tsa-trust-list.pem          TSA trust anchors: the TSA root and issuing CA
#
# Writes to OUT_DIR (default: fixtures/pki, gitignored):
#   root.{pem,der,key}          root CA
#   issuing-ca.{pem,der,key}    issuing CA
#   signer.{pem,der,key}        signer (key is SEC1 PEM)
#   trust-list.pem              trust anchors: root + issuing CA
#   trust-list.json             the same anchors in the C2PA trust list JSON format
#
# Usage:
#   ./generate-test-pki.sh [--mirror] [OUT_DIR] [NAME]
#   ./generate-test-pki.sh --renew-signer [--mirror] [OUT_DIR]
# NAME (default "ZK Demo") distinguishes independent PKIs in subject names.
#
# Generating replaces every key and certificate in OUT_DIR, so earlier
# anonymized assets no longer validate against the new trust list.
# --renew-signer instead reissues only the signer certificate, for the same
# signer key and subject, under the existing issuing CA: the trust anchors
# and the signer key are unchanged.

set -euo pipefail

RENEW_SIGNER=false
MIRROR=false
while [[ "${1:-}" == --* ]]; do
    case "$1" in
        --renew-signer) RENEW_SIGNER=true ;;
        --mirror) MIRROR=true ;;
        *) echo "unknown option $1" >&2; exit 1 ;;
    esac
    shift
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-${SCRIPT_DIR}/fixtures/pki}"
NAME="${2:-ZK Demo}"
C2PA_CLAIM_SIGNING_EKU="1.3.6.1.4.1.62558.2.1"

# Curves and digests: the CAs' (and the TSA's) depend on the profile; the
# signer key is P-256 in both, as on real devices.
if $MIRROR; then
    CA_CURVE=secp384r1
    CA_DIGEST=-sha384
else
    CA_CURVE=prime256v1
    CA_DIGEST=-sha256
fi

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

# Issue signer.pem/.der from signer.csr with the issuing CA (90 days, C2PA
# claim-signing EKU).
issue_signer() {
    if $MIRROR; then
        cat > signer.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
extendedKeyUsage=emailProtection,${C2PA_CLAIM_SIGNING_EKU}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
authorityInfoAccess=OCSP;URI:http://ocsp.example.invalid/,caIssuers;URI:http://pki.example.invalid/issuing-ca.crt
EOF
    else
        cat > signer.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=${C2PA_CLAIM_SIGNING_EKU}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF
    fi
    openssl x509 -req -in signer.csr -CA issuing-ca.pem -CAkey issuing-ca.key -CAcreateserial \
        $CA_DIGEST -days 90 -extfile signer.ext -out signer.pem
    openssl x509 -in signer.pem -outform DER -out signer.der
}

if $RENEW_SIGNER; then
    for f in issuing-ca.pem issuing-ca.key signer.pem signer.key; do
        [[ -f "$f" ]] || { echo "--renew-signer: missing $OUT_DIR/$f" >&2; exit 1; }
    done
    # A request for the same subject and key as the current certificate.
    openssl x509 -x509toreq -in signer.pem -signkey signer.key -out signer.csr
    issue_signer
    rm -f ./*.csr ./*.srl ./*.ext
    echo "Signer certificate renewed in ${OUT_DIR}"
    exit 0
fi

# Root CA (10 years)
openssl ecparam -genkey -name $CA_CURVE -noout -out root.key
cat > root.ext <<EOF
basicConstraints=critical,CA:TRUE,pathlen:1
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EOF
openssl req -x509 -new -key root.key $CA_DIGEST -days 3650 -out root.pem \
    -subj "/C=US/O=${NAME} PKI/CN=${NAME} Root CA" -extensions v3_ca \
    -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\n'; cat root.ext)

# Issuing CA (5 years), issues end-entity certificates only
openssl ecparam -genkey -name $CA_CURVE -noout -out issuing-ca.key
openssl req -new -key issuing-ca.key -out issuing-ca.csr \
    -subj "/C=US/O=${NAME} PKI/CN=${NAME} Issuing CA"
cat > issuing-ca.ext <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF
openssl x509 -req -in issuing-ca.csr -CA root.pem -CAkey root.key -CAcreateserial \
    $CA_DIGEST -days 1825 -extfile issuing-ca.ext -out issuing-ca.pem

# Signer
openssl ecparam -genkey -name prime256v1 -noout -out signer.key
openssl req -new -key signer.key -out signer.csr \
    -subj "/C=US/O=${NAME} Signer Org/CN=${NAME} Signer"
issue_signer

for c in root issuing-ca; do
    openssl x509 -in "$c.pem" -outform DER -out "$c.der"
done

# Trust lists: both the root and the issuing CA are anchors
cat root.pem issuing-ca.pem > trust-list.pem
python3 -I - root.der issuing-ca.der "$NAME" > trust-list.json <<'PY'
import base64, json, sys
certs = [base64.b64encode(open(p, "rb").read()).decode() for p in sys.argv[1:3]]
name = sys.argv[3]
service = lambda label, cert: {"ServiceInformation": {
    "ServiceDigitalIdentity": {"X509Certificates": [{"val": cert}]},
    "ServiceName": [{"lang": "en", "value": label}],
    "ServiceStatus": "http://c2pa.org/conformance/trust-list/trusted",
}}
print(json.dumps({"LoTE": {
    "ListAndSchemeInformation": {"SchemeName": [{"lang": "en", "value": f"{name} test trust list"}]},
    "TrustedEntitiesList": [{
        "TrustedEntityInformation": {"TEName": [{"lang": "en", "value": f"{name} PKI"}]},
        "TrustedEntityServices": [service(f"{name} Root CA", certs[0]),
                                  service(f"{name} Issuing CA", certs[1])],
    }],
}}, indent=2))
PY

# Time-stamp authority (mirror profile), as a real device photo's time stamp:
# a root, a P-384 issuing CA (itself on the TSA trust list) with the
# timeStamping EKU, and a P-256 TSA certificate with the critical timeStamping
# EKU, issued with ECDSA-SHA384: the same shape as the signer's chain.
if $MIRROR; then
    openssl ecparam -genkey -name $CA_CURVE -noout -out tsa-root.key
    openssl req -x509 -new -key tsa-root.key $CA_DIGEST -days 3650 -out tsa-root.pem \
        -subj "/C=US/O=${NAME} PKI/CN=${NAME} TSA Root CA" -extensions v3_ca \
        -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\n'; cat root.ext)
    openssl ecparam -genkey -name $CA_CURVE -noout -out tsa-ca.key
    openssl req -new -key tsa-ca.key -out tsa-ca.csr -subj "/C=US/O=${NAME} PKI/CN=${NAME} Time-Stamping CA"
    cat > tsa-ca.ext <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
extendedKeyUsage=timeStamping
certificatePolicies=1.3.6.1.4.1.62558.1.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF
    openssl x509 -req -in tsa-ca.csr -CA tsa-root.pem -CAkey tsa-root.key -CAcreateserial \
        $CA_DIGEST -days 1825 -extfile tsa-ca.ext -out tsa-ca.pem
    openssl ecparam -genkey -name prime256v1 -noout -out tsa.key
    openssl req -new -key tsa.key -out tsa.csr -subj "/C=US/O=${NAME} PKI/CN=${NAME} Time Stamping Authority"
    cat > tsa.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
extendedKeyUsage=critical,timeStamping
certificatePolicies=1.3.6.1.4.1.62558.1.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF
    openssl x509 -req -in tsa.csr -CA tsa-ca.pem -CAkey tsa-ca.key -CAcreateserial \
        $CA_DIGEST -days 825 -extfile tsa.ext -out tsa.pem
    for c in tsa-root tsa-ca tsa; do
        openssl x509 -in "$c.pem" -outform DER -out "$c.der"
    done
    cat tsa-root.pem tsa-ca.pem > tsa-trust-list.pem
fi

rm -f ./*.csr ./*.srl ./*.ext
echo "Test PKI written to ${OUT_DIR}"
