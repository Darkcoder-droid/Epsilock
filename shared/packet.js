const { v4: uuidv4 } = require('uuid');
const { PACKET_TYPES } = require('./constants');

function createPacket({
  type,
  roomId = null,
  fromUserId = null,
  fromUsername = null,
  toUserId = null,
  nodeId,
  ciphertext = '',
  nonce = '',
  authTag = '',
  sizeBytes = 0,
  isCover = false
}) {
  if (!Object.values(PACKET_TYPES).includes(type)) {
    throw new Error(`Unsupported packet type: ${type}`);
  }

  return {
    packetId: `PKT-${uuidv4().slice(0, 10)}`,
    type,
    roomId,
    fromUserId,
    fromUsername,
    toUserId,
    nodeId,
    ciphertext,
    nonce,
    authTag,
    sizeBytes,
    createdAt: new Date().toISOString(),
    isCover: Boolean(isCover)
  };
}

module.exports = { createPacket };
