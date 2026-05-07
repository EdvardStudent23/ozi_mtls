#!/usr/bin/env bash
# Reproducible PKI for ozi_mtls.
# Creates Root CA, server cert (serverAuth + SAN), client cert (clientAuth).
# Idempotent: re-running re-issues leaf certs but reuses the existing Root CA.

set -euo pipefail

PKI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PKI_DIR"

DAYS_CA=1024
DAYS_LEAF=500

ROOT_SUBJ="/C=UA/ST=Lviv/L=Lviv/O=UCU/OU=OZI/CN=ozi-mtls Root CA"
SERVER_SUBJ="/C=UA/ST=Lviv/L=Lviv/O=UCU/OU=OZI/CN=mtls-server"
CLIENT_SUBJ="/C=UA/ST=Lviv/L=Lviv/O=UCU/OU=OZI/CN=mtls-client-01"

# --- Root CA ----------------------------------------------------------------
if [[ -f rootCA.pem && -f rootCA.key ]]; then
  echo "[skip] Root CA exists: $PKI_DIR/rootCA.pem"
else
  echo "[+] Root CA"
  openssl genrsa -out rootCA.key 2048
  openssl req -x509 -new -nodes -sha256 \
    -key rootCA.key -days "$DAYS_CA" \
    -subj "$ROOT_SUBJ" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out rootCA.pem
fi

# --- Server cert (serverAuth, SAN) ------------------------------------------
echo "[+] Server cert"
openssl genrsa -out server.key 2048

cat > server.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

openssl req -new -key server.key -subj "$SERVER_SUBJ" -out server.csr
openssl x509 -req -in server.csr -sha256 \
  -CA rootCA.pem -CAkey rootCA.key -CAcreateserial \
  -extfile server.ext -days "$DAYS_LEAF" -out server.pem

# --- Client cert (clientAuth) -----------------------------------------------
echo "[+] Client cert"
openssl genrsa -out client.key 2048

cat > client.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=DNS:mtls-client-01
EOF

openssl req -new -key client.key -subj "$CLIENT_SUBJ" -out client.csr
openssl x509 -req -in client.csr -sha256 \
  -CA rootCA.pem -CAkey rootCA.key -CAcreateserial \
  -extfile client.ext -days "$DAYS_LEAF" -out client.pem

rm -f server.csr client.csr server.ext client.ext

echo
echo "=== PKI ready in $PKI_DIR ==="
ls -la rootCA.pem server.pem client.pem
echo
echo "Inspect:"
echo "  openssl x509 -in $PKI_DIR/server.pem -noout -text | grep -A1 'Subject Alternative\\|Key Usage'"
