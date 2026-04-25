const express = require('express');
const { requireAuth } = require('../middleware/auth');
const Room = require('../models/Room');
const { detectFileAbuse } = require('../security/anomalyDetector');
const { validateFileMetadata } = require('../security/payloadValidator');
const { createIncident, freezeRoom } = require('../security/incidentService');
const { revokeToken } = require('../security/tokenRevocation');

function buildFilesRouter(fileStore) {
  const router = express.Router();

  router.post('/files/temp-upload', requireAuth, async (req, res) => {
    const { roomId, fileName, mimeType, dataBase64 } = req.body;

    const room = await Room.findOne({ roomId, participantUserIds: req.auth.sub, status: 'active' });
    if (!room) {
      await createIncident({
        roomId,
        userId: req.auth.sub,
        type: 'invalid_room_access',
        severity: 'high',
        reason: 'User attempted temporary upload to unauthorized room',
        sourceIp: req.ip,
        userAgent: req.get('user-agent') || null,
        origin: req.get('origin') || null,
        actionTaken: 'upload_rejected'
      });
      return res.status(403).json({ error: 'No access to room' });
    }

    if (room.frozen) {
      return res.status(423).json({ error: 'Room is frozen due to suspicious activity' });
    }

    if (!dataBase64 || !fileName || !mimeType) {
      return res.status(400).json({ error: 'Missing file payload' });
    }

    const size = Buffer.byteLength(dataBase64, 'base64');
    const max = Number(process.env.MAX_FILE_SIZE_BYTES || process.env.MAX_FILE_BYTES || 1048576);
    const fileMetaValidation = validateFileMetadata({ fileName, mimeType, fileSize: size });
    if (!size || size > max || !fileMetaValidation.ok) {
      await createIncident({
        roomId,
        userId: req.auth.sub,
        type: 'oversized_payload_detection',
        severity: 'high',
        reason: fileMetaValidation.ok ? `File payload too large (${size} bytes)` : fileMetaValidation.reason,
        sourceIp: req.ip,
        userAgent: req.get('user-agent') || null,
        origin: req.get('origin') || null,
        actionTaken: 'upload_rejected'
      });
      revokeToken({ jti: req.auth.jti, exp: req.auth.exp, reason: 'oversized_payload_detection' });
      req.app.locals.wsState?.forceLogoutUser?.(req.auth.sub, 'Oversized payload detected. Session revoked.');
      return res.status(400).json({ error: 'Invalid file size or type' });
    }

    const fileAbuse = detectFileAbuse({ userId: req.auth.sub });
    if (fileAbuse) {
      await createIncident({
        roomId,
        userId: req.auth.sub,
        type: fileAbuse.type,
        severity: fileAbuse.severity,
        reason: fileAbuse.reason,
        sourceIp: req.ip,
        userAgent: req.get('user-agent') || null,
        origin: req.get('origin') || null,
        actionTaken: 'room_frozen_and_token_revoked'
      });
      await freezeRoom(roomId, fileAbuse.reason, 'system');
      revokeToken({ jti: req.auth.jti, exp: req.auth.exp, reason: 'file_abuse_detection' });
      req.app.locals.wsState?.forceLogoutUser?.(req.auth.sub, 'File abuse detected. Session revoked.');
      return res.status(429).json({ error: 'Suspicious activity detected. Room frozen for safety.' });
    }

    const allowedPrefixes = (process.env.ALLOWED_FILE_MIME_PREFIXES || 'image/,text/,application/pdf')
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean);

    const allowed = allowedPrefixes.some((prefix) => mimeType.startsWith(prefix));
    if (!allowed) {
      await createIncident({
        roomId,
        userId: req.auth.sub,
        type: 'file_abuse_detection',
        severity: 'medium',
        reason: `Blocked or disallowed file type: ${mimeType}`,
        sourceIp: req.ip,
        userAgent: req.get('user-agent') || null,
        origin: req.get('origin') || null,
        actionTaken: 'upload_rejected'
      });
      return res.status(400).json({ error: 'File type not allowed' });
    }

    const ttl = Number(process.env.FILE_TTL_MS || 120000);
    const temp = fileStore.createTemp({
      ownerUserId: req.auth.sub,
      roomId,
      fileName,
      mimeType,
      dataBase64,
      size,
      ttlMs: ttl
    });

    return res.json({
      ok: true,
      fileName,
      fileSize: size,
      mimeType,
      tempDownloadUrl: `/files/temp/${temp.token}`,
      tempToken: temp.token,
      expiresAt: temp.expiresAt.toISOString()
    });
  });

  router.get('/files/temp/:token', requireAuth, async (req, res) => {
    const record = fileStore.consume(req.params.token);
    if (!record) return res.status(404).send('File expired or already consumed');

    const room = await Room.findOne({ roomId: record.roomId, participantUserIds: req.auth.sub, status: 'active' });
    if (!room) return res.status(403).send('Forbidden');

    const buffer = Buffer.from(record.dataBase64, 'base64');
    res.setHeader('Content-Type', record.mimeType);
    res.setHeader('Content-Disposition', `attachment; filename="${record.fileName}"`);
    return res.send(buffer);
  });

  return router;
}

module.exports = { buildFilesRouter };
