const express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const User = require('../models/User');
const Room = require('../models/Room');
const SessionLog = require('../models/SessionLog');
const Incident = require('../models/Incident');
const { requireAuth } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/requireAdmin');
const {
  freezeRoom,
  unfreezeRoom,
  markIncidentReviewed,
  markIncidentResolved
} = require('../security/incidentService');

const router = express.Router();

router.use(requireAuth, requireAdmin);

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

router.get('/admin', async (req, res) => {
  const [users, rooms, activeSessions, openIncidents, suspiciousSessions] = await Promise.all([
    User.find().sort({ createdAt: -1 }).lean(),
    Room.find().sort({ updatedAt: -1 }).lean(),
    SessionLog.find({ status: 'online' }).sort({ lastActivityAt: -1 }).lean(),
    Incident.find({ status: { $in: ['open', 'reviewed'] } }).sort({ createdAt: -1 }).limit(20).lean(),
    SessionLog.find({ suspicious: true }).sort({ lastSecurityEventAt: -1 }).limit(20).lean()
  ]);

  const onlineFromSockets = req.app.locals.wsState?.onlineUsers?.() || [];
  const onlineUserIds = new Set(onlineFromSockets.map((id) => String(id)));

  const uiUsers = users
    .filter((u) => u.role !== 'admin')
    .map((u) => ({
      id: String(u._id),
      name: u.username,
      role: u.role === 'admin' ? 'Admin' : 'User',
      status: u.blocked ? 'Suspended' : 'Active',
      requirePasswordReset: !!u.requirePasswordReset,
      lastLogin: '-',
      token: u.blocked ? 'revoked' : 'active'
    }));

  const breachLogs = openIncidents.slice(0, 50).map((inc) => ({
    timestamp: new Date(inc.createdAt).toISOString().replace('T', ' ').slice(0, 16),
    status: inc.status || 'open',
    type: inc.type,
    ip: inc.sourceIp || '-',
    location: [inc?.sourceGeo?.city, inc?.sourceGeo?.region, inc?.sourceGeo?.country].filter(Boolean).join(', ') || 'Unknown',
    severity: inc.severity === 'critical' ? 'High' : inc.severity === 'high' ? 'High' : inc.severity === 'medium' ? 'Medium' : 'Low'
  }));

  const dashboardSummary = {
    totalUsers: uiUsers.length,
    activeUsers: uiUsers.filter((u) => u.status === 'Active').length,
    suspendedUsers: uiUsers.filter((u) => u.status !== 'Active').length,
    totalRooms: rooms.length,
    frozenRooms: rooms.filter((r) => r.frozen).length,
    onlineSessions: activeSessions.length,
    suspiciousSessions: suspiciousSessions.length,
    openIncidents: openIncidents.length
  };

  res.render('admin_dashboard', {
    admin: req.auth,
    user: {
      name: req.auth.username,
      role: 'Admin',
      token: req.auth.jti || 'session'
    },
    users: uiUsers,
    allUsers: users,
    breachLogs,
    rooms,
    activeSessions,
    suspiciousSessions,
    openIncidents,
    dashboardSummary,
    onlineUserIds,
    ...buildUiSecurityContext()
  });
});

router.get('/admin/users', async (_req, res) => {
  const users = await User.find({ role: 'user' }).sort({ createdAt: -1 }).lean();
  const mapped = users.map((u) => ({
    id: String(u._id),
    name: u.username,
    role: 'User',
    status: u.blocked ? 'Suspended' : 'Active',
    requirePasswordReset: !!u.requirePasswordReset,
    lastLogin: '-',
    token: u.blocked ? 'revoked' : 'active'
  }));
  res.render('create_user', { users: mapped, error: null });
});

router.post('/admin/users/create', async (req, res) => {
  const { username, password, role } = req.body;
  const requestedRole = role === 'admin' ? 'admin' : 'user';

  const existing = await User.findOne({ username });
  if (existing) {
    const users = await User.find({ role: 'user' }).sort({ createdAt: -1 }).lean();
    const mapped = users.map((u) => ({
      id: String(u._id),
      name: u.username,
      role: 'User',
      status: u.blocked ? 'Suspended' : 'Active',
      requirePasswordReset: !!u.requirePasswordReset,
      lastLogin: '-',
      token: u.blocked ? 'revoked' : 'active'
    }));
    return res.status(409).render('create_user', { users: mapped, error: 'Username already exists' });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  await User.create({ username, passwordHash, role: requestedRole });
  return res.redirect('/admin/users');
});

router.post('/admin/users/delete/:id', async (req, res) => {
  const userId = req.params.id;
  await User.deleteOne({ _id: userId, role: 'user' });
  await Room.updateMany({}, { $pull: { participantUserIds: userId } });
  await SessionLog.updateMany({ userId }, { status: 'offline', disconnectedAt: new Date() });
  return res.redirect('/admin/users');
});

router.post('/admin/users/edit/:id', async (req, res) => {
  const { username, password } = req.body;
  const update = { username };
  if (password && password.trim()) {
    update.passwordHash = await bcrypt.hash(password, 12);
  }
  await User.updateOne({ _id: req.params.id, role: 'user' }, update);
  return res.redirect('/admin/users');
});

router.post('/admin/users/:userId/block', async (req, res) => {
  const userId = req.params.userId;
  await User.updateOne(
    { _id: userId, role: 'user' },
    {
      $inc: { tokenVersion: 1 },
      blocked: true,
      blockedUntil: null,
      blockReason: 'Blocked by admin due to suspicious activity'
    }
  );
  await SessionLog.updateMany(
    { userId, status: 'online' },
    {
      suspicious: true,
      frozen: true,
      revokedAt: new Date(),
      disconnectReason: 'Blocked by admin',
      lastSecurityEventAt: new Date()
    }
  );
  req.app.locals.wsState?.forceLogoutUser?.(userId, 'Blocked by admin');
  return res.redirect('/admin/users');
});

router.post('/admin/users/:userId/disconnect', async (req, res) => {
  const userId = req.params.userId;
  await User.updateOne(
    { _id: userId, role: 'user' },
    { $inc: { tokenVersion: 1 } }
  );
  await SessionLog.updateMany(
    { userId, status: 'online' },
    {
      status: 'offline',
      disconnectedAt: new Date(),
      lastActivityAt: new Date(),
      disconnectReason: 'Disconnected by admin'
    }
  );
  req.app.locals.wsState?.forceLogoutUser?.(userId, 'Disconnected by admin');
  return res.redirect('/admin/users');
});

router.post('/admin/users/:userId/unblock', async (req, res) => {
  const userId = req.params.userId;
  await User.updateOne(
    { _id: userId, role: 'user' },
    {
      blocked: false,
      blockedUntil: null,
      blockReason: null
    }
  );
  return res.redirect('/admin/users');
});

router.post('/admin/users/:userId/reset-password', async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || String(newPassword).trim().length < 8) {
    return res.redirect('/admin/users');
  }

  const userId = req.params.userId;
  const passwordHash = await bcrypt.hash(String(newPassword).trim(), 12);
  await User.updateOne(
    { _id: userId, role: 'user' },
    {
      passwordHash,
      $inc: { tokenVersion: 1 },
      blocked: false,
      blockedUntil: null,
      blockReason: null,
      requirePasswordReset: false
    }
  );

  req.app.locals.wsState?.forceLogoutUser?.(userId, 'Password reset by admin. Please login again.');
  return res.redirect('/admin/users');
});

router.get('/admin/rooms', async (_req, res) => {
  const [rooms, users] = await Promise.all([
    Room.find().sort({ updatedAt: -1 }).lean(),
    User.find({ role: 'user' }).sort({ username: 1 }).lean()
  ]);

  res.render('rooms', { rooms, users, error: null });
});

router.post('/admin/rooms/create', async (req, res) => {
  const { name } = req.body;
  await Room.create({
    roomId: `ROOM-${uuidv4().slice(0, 8)}`,
    name,
    createdByAdminId: req.auth.sub,
    participantUserIds: [],
    status: 'active',
    frozen: false,
    frozenReason: null,
    frozenAt: null,
    frozenBy: null
  });

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
  await freezeRoom(req.params.roomId, 'Frozen by admin', 'admin');
  await SessionLog.updateMany(
    { roomId: req.params.roomId, status: 'online' },
    {
      frozen: true,
      suspicious: true,
      lastSecurityEventAt: new Date(),
      disconnectReason: 'Room frozen by admin'
    }
  );
  req.app.locals.wsState?.broadcastAdminSecurityAlert?.({
    severity: 'medium',
    reason: `Admin froze room ${req.params.roomId}`,
    roomId: req.params.roomId
  });
  req.app.locals.wsState?.broadcastRoomSecurityAlert?.(
    req.params.roomId,
    'Suspicious activity was detected. This room has been frozen for safety.'
  );
  return res.redirect('/admin/rooms');
});

router.post('/admin/rooms/:roomId/unfreeze', async (req, res) => {
  await unfreezeRoom(req.params.roomId);
  await SessionLog.updateMany(
    { roomId: req.params.roomId },
    {
      frozen: false,
      disconnectReason: null
    }
  );
  return res.redirect('/admin/rooms');
});

router.get('/admin/incidents', async (req, res) => {
  const { severity, status, type } = req.query;
  const filter = {};
  if (severity) filter.severity = severity;
  if (status) filter.status = status;
  if (type) filter.type = type;

  const incidents = await Incident.find(filter).sort({ createdAt: -1 }).limit(200).lean();
  return res.render('incidents', { incidents, filter });
});

router.get('/admin/incidents/:id', async (req, res) => {
  const incident = await Incident.findById(req.params.id).lean();
  if (!incident) return res.status(404).send('Incident not found');
  return res.render('incident_detail', { incident });
});

router.post('/admin/incidents/:id/review', async (req, res) => {
  await markIncidentReviewed(req.params.id);
  return res.redirect(`/admin/incidents/${req.params.id}`);
});

router.post('/admin/incidents/:id/resolve', async (req, res) => {
  await markIncidentResolved(req.params.id);
  const incident = await Incident.findById(req.params.id).lean();
  if (incident) {
    req.app.locals.wsState?.broadcastIncidentResolved?.(incident);
  }
  return res.redirect(`/admin/incidents/${req.params.id}`);
});

module.exports = router;
