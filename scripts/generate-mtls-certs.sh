#!/bin/bash
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

CERTS_DIR="certs"
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

echo "Generating Axonwall Root CA..."
# Root CA Key
openssl genrsa -out ca.key 4096

# Root CA Certificate
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt \
    -subj "/C=US/ST=State/L=City/O=Axonwall/OU=Security/CN=Axonwall Root CA"

echo "Generating Core Hub Server Certificate..."
# Hub Key
openssl genrsa -out hub.key 2048

# Hub CSR
openssl req -new -key hub.key -out hub.csr \
    -subj "/C=US/ST=State/L=City/O=Axonwall/OU=Core/CN=hub.axonwall.local"

# Hub Cert
cat > hub_ext.cnf << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = hub.axonwall.local
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in hub.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out hub.crt -days 825 -sha256 -extfile hub_ext.cnf

echo "Generating Satellite Client Certificate..."
# Satellite Key
openssl genrsa -out satellite.key 2048

# Satellite CSR
openssl req -new -key satellite.key -out satellite.csr \
    -subj "/C=US/ST=State/L=City/O=Axonwall/OU=Satellite/CN=satellite.axonwall.local"

# Satellite Cert
cat > sat_ext.cnf << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
subjectAltName = DNS:satellite.axonwall.local
EOF

openssl x509 -req -in satellite.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out satellite.crt -days 825 -sha256 -extfile sat_ext.cnf

# Cleanup CSRs and ext files
rm *.csr *_ext.cnf

echo "====================================="
echo "mTLS Certificates generated in ./certs/"
echo "CA Certificate:      certs/ca.crt"
echo "Hub Certificate:     certs/hub.crt / certs/hub.key"
echo "Satellite Cert:      certs/satellite.crt / certs/satellite.key"
echo "====================================="
echo "To test the satellite locally, copy these to /etc/axonwall/certs/:"
echo "  sudo mkdir -p /etc/axonwall/certs"
echo "  sudo cp certs/satellite.crt certs/satellite.key certs/ca.crt /etc/axonwall/certs/"
