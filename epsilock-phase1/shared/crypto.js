const crypto = require('crypto');

function getKey() {
  const raw = process.env.DEMO_SHARED_KEY || '';
  if (!raw) {
    throw new Error('DEMO_SHARED_KEY is required');
  }

  const hexLike = /^[0-9a-fA-F]{64}$/;
  if (hexLike.test(raw)) {
    return Buffer.from(raw, 'hex');
  }

  // Demo fallback: deterministic key from non-hex string.
  return crypto.createHash('sha256').update(String(raw)).digest();
}

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function padBuffer(input, minBytes = 256, maxBytes = 1024) {
  const source = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  const target = Math.max(source.length, randomInt(minBytes, maxBytes));
  if (source.length >= target) return source;
  const pad = crypto.randomBytes(target - source.length);
  return Buffer.concat([source, pad]);
}

function encryptText(plainText, { minBytes = 256, maxBytes = 1024 } = {}) {
  const key = getKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const source = Buffer.from(String(plainText), 'utf8');
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(source.length, 0);
  const framed = Buffer.concat([header, source]);
  const padded = padBuffer(framed, minBytes, maxBytes);
  const encrypted = Buffer.concat([cipher.update(padded), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: encrypted.toString('base64'),
    nonce: iv.toString('base64'),
    authTag: tag.toString('base64'),
    sizeBytes: encrypted.length
  };
}

function decryptText({ ciphertext, nonce, authTag }) {
  const key = getKey();
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(String(nonce), 'base64')
  );
  decipher.setAuthTag(Buffer.from(String(authTag), 'base64'));
  const out = Buffer.concat([
    decipher.update(Buffer.from(String(ciphertext), 'base64')),
    decipher.final()
  ]);
  if (out.length >= 4) {
    const len = out.readUInt32BE(0);
    if (Number.isInteger(len) && len >= 0 && len <= out.length - 4) {
      return out.subarray(4, 4 + len).toString('utf8');
    }
  }
  return out.toString('utf8').replace(/[\x00-\x1F\x7F-\x9F]+$/g, '').trim();
}

function decryptTextInMemory(packet) {
  return decryptText(packet);
}

module.exports = {
  encryptText,
  decryptText,
  decryptTextInMemory,
  padBuffer
};
