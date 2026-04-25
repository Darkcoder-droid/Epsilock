const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

function createTlsServer(app) {
  const keyPath = path.resolve(process.cwd(), process.env.TLS_KEY_PATH || './certs/localhost-key.pem');
  const certPath = path.resolve(process.cwd(), process.env.TLS_CERT_PATH || './certs/localhost-cert.pem');

  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    const key = fs.readFileSync(keyPath);
    const cert = fs.readFileSync(certPath);
    console.log('[tls] HTTPS enabled (TLS 1.3 + ECC recommended in cert generation script).');
    return { server: https.createServer({ key, cert }, app), protocol: 'https' };
  }

  console.warn('[tls] TLS certs missing. Falling back to HTTP for local dev only.');
  return { server: http.createServer(app), protocol: 'http' };
}

module.exports = { createTlsServer };
