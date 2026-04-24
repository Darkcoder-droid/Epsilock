# Local TLS Certificates (Phase 1)

EPSILOCK Phase 1 is HTTPS/WSS ready with configurable certificate paths.

Recommended local config:
- TLS protocol target: TLS 1.3
- Key algorithm target: ECC (`prime256v1`)

Generate local dev certs:

```bash
cd epsilock-phase1
mkdir -p certs
openssl ecparam -genkey -name prime256v1 -noout -out certs/localhost-key.pem
openssl req -new -x509 -key certs/localhost-key.pem -out certs/localhost-cert.pem -days 365 -subj "/CN=localhost"
```

Use `.env` to point to cert files:

```env
TLS_KEY_PATH=./certs/localhost-key.pem
TLS_CERT_PATH=./certs/localhost-cert.pem
```

If certs are missing, servers fall back to HTTP/WS for local development only.
