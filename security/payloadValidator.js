function byteLengthSafe(value) {
  return Buffer.byteLength(String(value || ''), 'utf8');
}

function validateWsPayloadSize(rawPayload) {
  const max = Number(process.env.MAX_WS_PAYLOAD_BYTES || 16384);
  const size = Buffer.byteLength(rawPayload || '', 'utf8');
  return {
    ok: size <= max,
    size,
    max
  };
}

function validateChatMessageText(text) {
  const max = Number(process.env.MAX_WS_PAYLOAD_BYTES || 16384);
  const size = byteLengthSafe(text);
  return {
    ok: size > 0 && size <= max,
    size,
    max
  };
}

function validateFileMetadata({ fileName, mimeType, fileSize }) {
  const maxFileSize = Number(process.env.MAX_FILE_SIZE_BYTES || 1048576);
  if (!fileName || !mimeType || !Number.isFinite(fileSize) || fileSize <= 0) {
    return { ok: false, reason: 'Invalid file metadata' };
  }

  if (fileSize > maxFileSize) {
    return { ok: false, reason: 'File exceeds max size' };
  }

  const blockedMimeExact = new Set([
    'application/x-msdownload',
    'application/x-sh',
    'application/x-bat',
    'application/java-archive'
  ]);

  if (blockedMimeExact.has(mimeType)) {
    return { ok: false, reason: 'Blocked file type' };
  }

  return { ok: true };
}

module.exports = {
  validateWsPayloadSize,
  validateChatMessageText,
  validateFileMetadata
};
