#!/usr/bin/env bash
set -euo pipefail
mkdir -p certs
openssl ecparam -genkey -name prime256v1 -out certs/localhost-key.pem
openssl req -new -x509 -key certs/localhost-key.pem -out certs/localhost-cert.pem -days 365 \
  -subj "/C=US/ST=Local/L=Local/O=EPSILOCK Demo/CN=localhost"
echo "Generated certs/localhost-key.pem and certs/localhost-cert.pem (ECC)."
