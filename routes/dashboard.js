const express = require('express');
const { requireAuth } = require('../middleware/auth');
const Room = require('../models/Room');
const RecoveryRequest = require('../models/RecoveryRequest');

const router = express.Router();

router.use(requireAuth);

function buildUiSecurityContext() {
  return {
    certificates: {
      current: {
        issuer: process.env.TLS_CERT_ISSUER || 'EPSILOCK Local Root CA',
        subject: process.env.TLS_CERT_SUBJECT || 'localhost',
        validFrom: process.env.TLS_CERT_VALID_FROM || 'N/A',
        expires: process.env.TLS_CERT_EXPIRES || 'N/A',
        serial: process.env.TLS_CERT_SERIAL || 'local-dev'
      }
    },
    roles: {
      Admin: { chat: true, fileTransfer: true, certView: true, userMgmt: true, breachDetails: true },
      Officer: { chat: true, fileTransfer: true, certView: true, userMgmt: false, breachDetails: false },
      User: { chat: true, fileTransfer: true, certView: true, userMgmt: false, breachDetails: false },
      Family: { chat: true, fileTransfer: false, certView: false, userMgmt: false, breachDetails: false }
    }
  };
}

router.get('/dashboard', async (req, res) => {
  if (req.auth.role === 'admin') return res.redirect('/admin');

  const rooms = await Room.find({
    participantUserIds: req.auth.sub,
    status: 'active'
  }).sort({ updatedAt: -1 });

  const frozenRoomIds = rooms.filter((r) => r.frozen).map((r) => r.roomId);
  const recoveryRows = frozenRoomIds.length
    ? await RecoveryRequest.find({
      oldRoomId: { $in: frozenRoomIds },
      status: { $in: ['pending', 'verified', 'completed'] }
    }).sort({ createdAt: -1 }).lean()
    : [];

  const latestRecoveryByOldRoom = {};
  for (const row of recoveryRows) {
    if (!latestRecoveryByOldRoom[row.oldRoomId]) {
      latestRecoveryByOldRoom[row.oldRoomId] = row.recoveryId;
    }
  }

  return res.render('dashboard', {
    user: {
      ...req.auth,
      name: req.auth.username,
      role: req.auth.role === 'admin' ? 'Admin' : 'User',
      token: req.auth.jti || 'session'
    },
    rooms,
    activeRoomId: null,
    maxFileBytes: Number(process.env.MAX_FILE_SIZE_BYTES || process.env.MAX_FILE_BYTES || 1048576),
    latestRecoveryByOldRoom,
    ...buildUiSecurityContext()
  });
});

router.get('/chat/:roomId', async (req, res) => {
  if (req.auth.role === 'admin') return res.status(403).send('Admins do not join chats');

  const room = await Room.findOne({
    roomId: req.params.roomId,
    participantUserIds: req.auth.sub,
    status: 'active'
  });

  if (!room) return res.status(404).send('Room not found or no access');

  if (room.recoveredFromRoomId) {
    const recoveryAccess = Array.isArray(req.auth.recoveryAccess) ? req.auth.recoveryAccess : [];
    if (!recoveryAccess.includes(room.roomId)) {
      return res.status(403).send('Recovered room requires secure re-authenticated recovery join');
    }
  }

  return res.render('chat', {
    user: {
      ...req.auth,
      name: req.auth.username,
      role: req.auth.role === 'admin' ? 'Admin' : 'User',
      token: req.auth.jti || 'session'
    },
    room,
    rooms: [room],
    activeRoomId: room.roomId,
    maxFileBytes: Number(process.env.MAX_FILE_SIZE_BYTES || process.env.MAX_FILE_BYTES || 1048576),
    recovered: req.query.recovered === '1'
  });
});

module.exports = router;
