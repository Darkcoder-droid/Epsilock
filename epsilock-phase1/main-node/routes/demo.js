const express = require('express');
const PacketMeta = require('../../models/PacketMeta');
const Room = require('../../models/Room');
const User = require('../../models/User');
const { requireAdmin } = require('./auth');
const { createPacket } = require('../../shared/packet');
const { PACKET_TYPES } = require('../../shared/constants');
const { encryptText } = require('../../shared/crypto');
const { getSecuritySettings } = require('../../services/securitySettingsService');

const router = express.Router();
router.use(requireAdmin);

function calcConfidence(real, cover) {
  if (cover === 0) return 'HIGH';
  const ratio = cover / Math.max(real, 1);
  if (ratio >= 3) return 'LOW';
  return 'MEDIUM';
}

async function buildDemoData(req) {
  const [packetMetaRows, rooms, users, settings] = await Promise.all([
    PacketMeta.find({ attackerDemoVisible: true }).sort({ createdAt: -1 }).limit(250).lean(),
    Room.find({ status: 'active' }).lean(),
    User.find({ role: 'user' }).lean(),
    getSecuritySettings()
  ]);

  const liveRows = req.app.locals.wsHub.getDemoState().recentPackets || [];
  const packets = liveRows.length ? liveRows : packetMetaRows.map((p) => ({ ...p, decrypted: '[not captured in memory]' }));
  const withoutCover = packets.filter((p) => !p.isCover);
  const withCover = packets;
  const confidenceWithout = calcConfidence(withoutCover.length, 0);
  const confidenceWith = calcConfidence(withCover.filter((p) => !p.isCover).length, withCover.filter((p) => p.isCover).length);

  return {
    rooms,
    users,
    packets,
    withoutCover,
    withCover,
    confidenceWithout,
    confidenceWith,
    coverEnabled: !!settings.coverTrafficEnabled,
    securitySettings: settings,
    admin: { ...req.auth, token: req.cookies?.epsi_access || '' }
  };
}

router.get('/admin/attacker-demo', async (req, res) => {
  const data = await buildDemoData(req);

  res.render('layout', {
    title: 'Attacker Demo',
    bodyView: 'admin_attacker_demo',
    data
  });
});

router.post('/admin/attacker-demo/clear', (_req, res) => {
  PacketMeta.deleteMany({ attackerDemoVisible: true }).catch(() => {});
  res.app.locals.wsHub.clearDemoLogs();
  return res.redirect('/admin/attacker-demo');
});

router.post('/admin/attacker-demo/send-sample', async (req, res) => {
  const { roomId, fromUserId, toUserId, nodeId } = req.body;
  const enc = encryptText('Demo sample REAL message for attacker comparison');
  const packet = createPacket({
    type: PACKET_TYPES.REAL_MESSAGE,
    roomId,
    fromUserId,
    toUserId,
    nodeId,
    ciphertext: enc.ciphertext,
    nonce: enc.nonce,
    authTag: enc.authTag,
    sizeBytes: enc.sizeBytes,
    isCover: false
  });

  await PacketMeta.create({
    packetId: packet.packetId,
    type: packet.type,
    roomId,
    fromUserId,
    toUserId,
    nodeId,
    sizeBytes: packet.sizeBytes,
    isCover: false,
    createdAt: new Date(),
    routeHint: 'admin_demo',
    attackerDemoVisible: true
  });

  req.app.locals.wsHub.recordDemoPacket({
    packetId: packet.packetId,
    type: packet.type,
    roomId,
    fromUserId,
    toUserId,
    nodeId,
    sizeBytes: packet.sizeBytes,
    isCover: false,
    createdAt: new Date(),
    decrypted: 'Demo sample REAL message for attacker comparison'
  });

  req.app.locals.wsHub.emitAdmin({ type: 'ATTACKER_DEMO_UPDATE', packetId: packet.packetId });
  return res.redirect('/admin/attacker-demo');
});

router.post('/admin/attacker-demo/cover-burst', async (req, res) => {
  const { roomId, fromUserId, toUserId, nodeId } = req.body;
  await req.app.locals.wsHub.generateCoverBurst(roomId, fromUserId, toUserId, nodeId);
  return res.redirect('/admin/attacker-demo');
});

module.exports = { demoRouter: router };
