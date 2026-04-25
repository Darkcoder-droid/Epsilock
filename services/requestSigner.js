const crypto = require('crypto');

function signPayload(payload, ts) {
  const secret = process.env.BACKUP_NODE_SECRET;
  if (!secret) throw new Error('BACKUP_NODE_SECRET is required');

  const body = JSON.stringify(payload || {});
  return crypto
    .createHmac('sha256', secret)
    .update(`${ts}.${body}`)
    .digest('hex');
}

module.exports = { signPayload };
