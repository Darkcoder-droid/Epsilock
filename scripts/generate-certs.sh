#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="$ROOT_DIR/certs"

mkdir -p "$CERT_DIR"

openssl ecparam -genkey -name prime256v1 -noout -out "$CERT_DIR/localhost-key.pem"
openssl req -new -x509 -key "$CERT_DIR/localhost-key.pem" \
  -out "$CERT_DIR/localhost-cert.pem" -days 365 -subj "/CN=localhost"

echo "Generated local ECC certs at $CERT_DIR"
echo "TLS 1.3 + ECC ready for local HTTPS/WSS testing."
