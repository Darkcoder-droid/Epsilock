function sizeOfJson(value) {
  return Buffer.byteLength(JSON.stringify(value), 'utf8');
}

function validatePacketShape(packet) {
  if (!packet || typeof packet !== 'object') return { ok: false, reason: 'packet must be object' };
  const required = ['packetId', 'type', 'nodeId', 'sizeBytes', 'createdAt', 'isCover'];
  for (const key of required) {
    if (!(key in packet)) return { ok: false, reason: `missing field ${key}` };
  }
  return { ok: true };
}

function validatePayloadSize(packet, maxBytes) {
  const size = sizeOfJson(packet);
  if (size > maxBytes) {
    return { ok: false, reason: `payload too large ${size}/${maxBytes}`, size };
  }
  return { ok: true, size };
}

module.exports = {
  validatePacketShape,
  validatePayloadSize,
  sizeOfJson
};
