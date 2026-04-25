const http = require('http');
const https = require('https');
const { signPayload } = require('./requestSigner');

function requestJson(url, method, payload) {
  const parsed = new URL(url);
  const lib = parsed.protocol === 'https:' ? https : http;
  const ts = Date.now().toString();
  const signature = signPayload(payload || {}, ts);

  return new Promise((resolve, reject) => {
    const req = lib.request(
      {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port,
        path: `${parsed.pathname}${parsed.search}`,
        method,
        headers: {
          'content-type': 'application/json',
          'x-main-node-id': process.env.MAIN_NODE_ID || 'main-node-1',
          'x-signature-ts': ts,
          'x-signature': signature
        },
        rejectUnauthorized: false
      },
      (res) => {
        let body = '';
        res.on('data', (chunk) => {
          body += chunk.toString();
        });
        res.on('end', () => {
          let parsedBody = {};
          try {
            parsedBody = body ? JSON.parse(body) : {};
          } catch (_err) {
            parsedBody = { raw: body };
          }

          if (res.statusCode >= 400) {
            reject(new Error(`Backup node error ${res.statusCode}: ${JSON.stringify(parsedBody)}`));
            return;
          }

          resolve(parsedBody);
        });
      }
    );

    req.on('error', reject);
    if (payload) req.write(JSON.stringify(payload));
    req.end();
  });
}

function getBackupBase() {
  return process.env.BACKUP_NODE_URL || 'https://localhost:5000';
}

async function createRecoveryRequest(payload) {
  return requestJson(`${getBackupBase()}/backup/recovery/request`, 'POST', payload);
}

async function getRecoveryStatus(recoveryId) {
  return requestJson(`${getBackupBase()}/backup/recovery/${recoveryId}/status`, 'GET');
}

async function verifyUserForRecovery(recoveryId, payload) {
  return requestJson(`${getBackupBase()}/backup/recovery/${recoveryId}/verify-user`, 'POST', payload);
}

async function completeRecovery(recoveryId) {
  return requestJson(`${getBackupBase()}/backup/recovery/${recoveryId}/complete`, 'POST', {});
}

module.exports = {
  createRecoveryRequest,
  getRecoveryStatus,
  verifyUserForRecovery,
  completeRecovery
};
