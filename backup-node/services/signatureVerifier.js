const crypto = require('crypto');

function verifyMainNodeSignature(req) {
  const mainNodeId = req.get('x-main-node-id');
  const ts = req.get('x-signature-ts');
  const signature = req.get('x-signature');

  if (!mainNodeId || !ts || !signature) {
    return { ok: false, reason: 'Missing signature headers' };
  }

  const skewMs = Math.abs(Date.now() - Number(ts));
  if (Number.isNaN(skewMs) || skewMs > 5 * 60 * 1000) {
    return { ok: false, reason: 'Signature timestamp expired' };
  }

  const secret = process.env.BACKUP_NODE_SECRET;
  if (!secret) return { ok: false, reason: 'BACKUP_NODE_SECRET missing' };

  const body = JSON.stringify(req.body || {});
  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${ts}.${body}`)
    .digest('hex');

  if (expected !== signature) {
    return { ok: false, reason: 'Invalid request signature' };
  }

  return { ok: true };
}

module.exports = { verifyMainNodeSignature };
