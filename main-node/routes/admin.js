const express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const User = require('../../models/User');
const Room = require('../../models/Room');
const NodeSession = require('../../models/NodeSession');
const PacketMeta = require('../../models/PacketMeta');
const Incident = require('../../models/Incident');
const SessionLog = require('../../models/SessionLog');
const { requireAdmin } = require('./auth');
const { forceLogoutUser, revokeUserSessions } = require('../../services/enforcementService');
const { WS_EVENTS } = require('../../shared/constants');
const sessionRegistry = require('../../services/sessionRegistry');
const {
  getSecuritySettings,
  updateSecuritySettings,
  broadcastSecuritySettings
} = require('../../services/securitySettingsService');

const router = express.Router();
router.use(requireAdmin);

router.get('/admin', async (req, res) => {
  const wsHub = req.app.locals.wsHub;
  const attackerStatus = wsHub && typeof wsHub.getAttackerStatus === 'function'
    ? wsHub.getAttackerStatus()
    : { connected: false, totalSockets: 0 };
  const [users, rooms, nodes, incidents, packetAgg, securitySettings] = await Promise.all([
    User.find({ role: 'user' }).lean(),
    Room.find().lean(),
    NodeSession.find({ status: 'online' }).sort({ lastSeenAt: -1 }).limit(20).lean(),
    Incident.find().sort({ createdAt: -1 }).limit(20).lean(),
    PacketMeta.aggregate([
      { $group: { _id: '$isCover', count: { $sum: 1 } } }
    ]),
    getSecuritySettings()
  ]);
  const [activeAnomalyCount, criticalIncidentCount] = await Promise.all([
    Incident.countDocuments({ status: 'open' }),
    Incident.countDocuments({ severity: 'critical', status: 'open' })
  ]);

  const cover = packetAgg.find((x) => x._id === true)?.count || 0;
  const real = packetAgg.find((x) => x._id === false)?.count || 0;
  const total = cover + real;
  const confidence = cover === 0 ? 'HIGH' : cover / Math.max(real, 1) >= 3 ? 'LOW' : 'MEDIUM';

  res.render('layout', {
    title: 'Admin Dashboard',
    bodyView: 'admin_dashboard',
    data: {
      admin: { ...req.auth, token: req.cookies?.epsi_access || '' },
      stats: {
        users: users.length,
        rooms: rooms.length,
        onlineNodes: nodes.length,
        incidents: incidents.length,
        real,
        cover,
        total,
        confidence,
        activeAnomalyCount,
        criticalIncidentCount
      },
      securitySettings,
      attackerStatus,
      attackerNodeUrl: process.env.ATTACKER_NODE_URL || 'https://localhost:4001/attacker',
      incidents
    }
  });
});

router.get('/admin/users', async (_req, res) => {
  const users = await User.find().sort({ createdAt: -1 }).lean();
  res.render('layout', { title: 'Admin Users', bodyView: 'admin_users', data: { users, error: null, admin: { ..._req.auth, token: _req.cookies?.epsi_access || '' } } });
});

router.post('/admin/users/create', async (req, res) => {
  const { username, password, role = 'user' } = req.body;
  const existing = await User.findOne({ username }).lean();
  if (existing) {
    const users = await User.find().sort({ createdAt: -1 }).lean();
    return res.status(409).render('layout', { title: 'Admin Users', bodyView: 'admin_users', data: { users, error: 'Username already exists', admin: { ...req.auth, token: req.cookies?.epsi_access || '' } } });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  await User.create({ username, passwordHash, role: role === 'admin' ? 'admin' : 'user' });
  return res.redirect('/admin/users');
});

router.post('/admin/users/:id/reset-password', async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || String(newPassword).length < 8) return res.redirect('/admin/users');
  const passwordHash = await bcrypt.hash(newPassword, 12);
  await User.updateOne(
    { _id: req.params.id },
    {
      passwordHash,
      blocked: false,
      blockedUntil: null,
      blockReason: null,
      requirePasswordReset: false,
      revokedJtis: [],
      $inc: { tokenVersion: 1 }
    }
  );
  await revokeUserSessions(req.params.id, 'Password reset by admin');
  await req.app.locals.wsHub.disconnectUserById(req.params.id, 'Password reset by admin');
  return res.redirect('/admin/users');
});

router.post('/admin/users/:id/block', async (req, res) => {
  await User.updateOne(
    { _id: req.params.id },
    { blocked: true, blockReason: 'Blocked by admin', blockedUntil: null, requirePasswordReset: true, $inc: { tokenVersion: 1 } }
  );
  await revokeUserSessions(req.params.id, 'Blocked by admin');
  await forceLogoutUser(req.params.id, 'Blocked by admin');
  return res.redirect('/admin/users');
});

router.post('/admin/users/:id/unblock', async (req, res) => {
  await User.updateOne({ _id: req.params.id }, { blocked: false, blockReason: null, blockedUntil: null, requirePasswordReset: false });
  return res.redirect('/admin/users');
});

router.post('/admin/users/:id/disconnect', async (req, res) => {
  await User.updateOne({ _id: req.params.id }, { $inc: { tokenVersion: 1 } });
  await revokeUserSessions(req.params.id, 'Disconnected by admin');
  await forceLogoutUser(req.params.id, 'Disconnected by admin');
  req.app.locals.wsHub.emitAdmin({
    type: WS_EVENTS.USER_FORCE_LOGOUT_DONE || 'USER_FORCE_LOGOUT_DONE',
    userId: req.params.id,
    reason: 'Disconnected by admin'
  });
  return res.redirect('/admin/users');
});

router.get('/admin/rooms', async (_req, res) => {
  const [rooms, users] = await Promise.all([
    Room.find().sort({ createdAt: -1 }).lean(),
    User.find({ role: 'user' }).sort({ username: 1 }).lean()
  ]);
  const userMap = {};
  users.forEach((u) => userMap[String(u._id)] = u.username);
  res.render('layout', { title: 'Admin Rooms', bodyView: 'admin_rooms', data: { rooms, users, userMap, error: null, admin: { ..._req.auth, token: _req.cookies?.epsi_access || '' } } });
});

router.post('/admin/rooms/create', async (req, res) => {
  const { name } = req.body;
  await Room.create({ roomId: `ROOM-${uuidv4().slice(0, 8)}`, name, participantUserIds: [], status: 'active' });
  return res.redirect('/admin/rooms');
});

router.post('/admin/rooms/:roomId/add-user', async (req, res) => {
  const { userId } = req.body;
  await Room.updateOne({ roomId: req.params.roomId }, { $addToSet: { participantUserIds: userId } });
  return res.redirect('/admin/rooms');
});

router.post('/admin/rooms/:roomId/remove-user', async (req, res) => {
  const { userId } = req.body;
  await Room.updateOne({ roomId: req.params.roomId }, { $pull: { participantUserIds: userId } });
  return res.redirect('/admin/rooms');
});

router.post('/admin/rooms/:roomId/freeze', async (req, res) => {
  await Room.updateOne(
    { roomId: req.params.roomId },
    { frozen: true, frozenReason: 'Frozen by admin', frozenAt: new Date(), frozenBy: 'admin' }
  );
  req.app.locals.wsHub.emitAdmin({ type: 'ROOM_FROZEN', roomId: req.params.roomId, reason: 'Frozen by admin' });
  sessionRegistry.broadcastToRoom(req.params.roomId, { type: WS_EVENTS.ROOM_FROZEN, roomId: req.params.roomId, reason: 'Frozen by admin' });
  return res.redirect('/admin/rooms');
});

router.post('/admin/rooms/:roomId/unfreeze', async (req, res) => {
  await Room.updateOne(
    { roomId: req.params.roomId },
    { frozen: false, frozenReason: null, frozenAt: null, frozenBy: null }
  );
  req.app.locals.wsHub.emitAdmin({ type: 'ROOM_UNFROZEN', roomId: req.params.roomId });
  sessionRegistry.broadcastToRoom(req.params.roomId, { type: WS_EVENTS.ROOM_UNFROZEN, roomId: req.params.roomId });
  return res.redirect('/admin/rooms');
});
router.get('/admin/nodes', async (req, res) => {
  const [sessions, users] = await Promise.all([
    NodeSession.find().sort({ connectedAt: -1 }).limit(200).lean(),
    User.find({ role: 'user' }).lean()
  ]);
  const userMapObj = {};
  users.forEach((u) => userMapObj[String(u._id)] = u.username);
  const rows = sessions.map((s) => ({
    ...s,
    username: userMapObj[String(s.userId)] || s.userId
  }));
  res.render('layout', { title: 'Admin Nodes', bodyView: 'admin_nodes', data: { rows, admin: { ...req.auth, token: req.cookies?.epsi_access || '' } } });
});

router.post('/admin/nodes/:nodeId/disconnect', async (req, res) => {
  await req.app.locals.wsHub.disconnectNodeById(req.params.nodeId, 'Disconnected by admin panel');
  return res.redirect('/admin/nodes');
});

router.get('/admin/incidents', async (req, res) => {
  const { severity = '', type = '', status = '', user = '', room = '' } = req.query;
  const filter = {};
  const viewFilter = { severity, type, status, user, room };
  if (severity) filter.severity = severity;
  if (type) filter.type = new RegExp(type, 'i');
  if (status) filter.status = status;
  if (user) filter.$or = [{ username: new RegExp(user, 'i') }, { userId: user }];
  if (room) filter.roomId = new RegExp(room, 'i');
  const incidents = await Incident.find(filter).sort({ createdAt: -1 }).limit(300).lean();
  res.render('layout', { title: 'Admin Incidents', bodyView: 'admin_incidents', data: { incidents, filter: viewFilter, admin: { ...req.auth, token: req.cookies?.epsi_access || '' } } });
});

router.get('/admin/incidents/:id', async (req, res) => {
  const incident = await Incident.findOne({ incidentId: req.params.id }).lean();
  if (!incident) return res.redirect('/admin/incidents');
  return res.render('layout', {
    title: `Incident ${incident.incidentId}`,
    bodyView: 'admin_incidents',
    data: { incidents: [incident], filter: {}, admin: { ...req.auth, token: req.cookies?.epsi_access || '' } }
  });
});

router.post('/admin/incidents/:id/resolve', async (req, res) => {
  await Incident.updateOne(
    { incidentId: req.params.id },
    { status: 'resolved', resolvedAt: new Date(), actionTaken: 'resolved_by_admin' }
  );
  return res.redirect('/admin/incidents');
});

router.get('/admin/security-settings', async (req, res) => {
  const settings = await getSecuritySettings();
  res.render('layout', { title: 'Security Settings', bodyView: 'admin_security_settings', data: { settings, admin: { ...req.auth, token: req.cookies?.epsi_access || '' } } });
});

router.get('/admin/api/security-settings', async (_req, res) => {
  const settings = await getSecuritySettings();
  return res.json({
    attackerDemoEnabled: !!settings.attackerDemoEnabled,
    coverTrafficEnabled: !!settings.coverTrafficEnabled,
    coverTrafficIntervalMs: Number(settings.coverTrafficIntervalMs || 1500),
    coverTrafficJitterMs: Number(settings.coverTrafficJitterMs || 1000),
    coverTrafficRatio: Number(settings.coverTrafficRatio || 3),
    updatedAt: settings.updatedAt,
    updatedBy: settings.updatedBy || null
  });
});

router.post('/admin/api/security-settings', async (req, res) => {
  const saved = await updateSecuritySettings(req.auth.sub, req.body || {});
  await broadcastSecuritySettings(saved);
  return res.json({
    ok: true,
    settings: {
      attackerDemoEnabled: !!saved.attackerDemoEnabled,
      coverTrafficEnabled: !!saved.coverTrafficEnabled,
      coverTrafficIntervalMs: Number(saved.coverTrafficIntervalMs || 1500),
      coverTrafficJitterMs: Number(saved.coverTrafficJitterMs || 1000),
      coverTrafficRatio: Number(saved.coverTrafficRatio || 3),
      updatedAt: saved.updatedAt,
      updatedBy: saved.updatedBy || null
    }
  });
});

module.exports = { adminRouter: router };
