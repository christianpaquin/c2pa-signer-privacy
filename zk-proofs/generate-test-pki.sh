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
# Writes to OUT_DIR (default: fixtures/pki, gitignored):
#   root.{pem,der,key}          root CA
#   issuing-ca.{pem,der,key}    issuing CA
#   signer.{pem,der,key}        signer (key is SEC1 PEM)
#   trust-list.pem              trust anchors: root + issuing CA
#   trust-list.json             the same anchors in the C2PA trust list JSON format
#
# Usage:
#   ./generate-test-pki.sh [OUT_DIR] [NAME]
# NAME (default "ZK Demo") distinguishes independent PKIs in subject names.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-${SCRIPT_DIR}/fixtures/pki}"
NAME="${2:-ZK Demo}"
C2PA_CLAIM_SIGNING_EKU="1.3.6.1.4.1.62558.2.1"

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

# Root CA (10 years)
openssl ecparam -genkey -name prime256v1 -noout -out root.key
cat > root.ext <<EOF
basicConstraints=critical,CA:TRUE,pathlen:1
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EOF
openssl req -x509 -new -key root.key -sha256 -days 3650 -out root.pem \
    -subj "/C=US/O=${NAME} PKI/CN=${NAME} Root CA" -extensions v3_ca \
    -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\n'; cat root.ext)

# Issuing CA (5 years), issues end-entity certificates only
openssl ecparam -genkey -name prime256v1 -noout -out issuing-ca.key
openssl req -new -key issuing-ca.key -out issuing-ca.csr \
    -subj "/C=US/O=${NAME} PKI/CN=${NAME} Issuing CA"
cat > issuing-ca.ext <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF
openssl x509 -req -in issuing-ca.csr -CA root.pem -CAkey root.key -CAcreateserial \
    -sha256 -days 1825 -extfile issuing-ca.ext -out issuing-ca.pem

# Signer (90 days), C2PA claim-signing EKU
openssl ecparam -genkey -name prime256v1 -noout -out signer.key
openssl req -new -key signer.key -out signer.csr \
    -subj "/C=US/O=${NAME} Signer Org/CN=${NAME} Signer"
cat > signer.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=${C2PA_CLAIM_SIGNING_EKU}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF
openssl x509 -req -in signer.csr -CA issuing-ca.pem -CAkey issuing-ca.key -CAcreateserial \
    -sha256 -days 90 -extfile signer.ext -out signer.pem

for c in root issuing-ca signer; do
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

rm -f ./*.csr ./*.srl ./*.ext
echo "Test PKI written to ${OUT_DIR}"
