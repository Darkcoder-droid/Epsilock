const { v4: uuidv4 } = require('uuid');
const Incident = require('../models/Incident');
const Room = require('../models/Room');
const SessionLog = require('../models/SessionLog');
const { buildSourceGeo } = require('./ipIntel');

async function createIncident(payload) {
  const { normalizedIp, sourceGeo } = await buildSourceGeo(payload.sourceIp || null);
  return Incident.create({
    incidentId: `INC-${uuidv4().slice(0, 10)}`,
    roomId: payload.roomId || null,
    userId: payload.userId || null,
    socketId: payload.socketId || null,
    type: payload.type,
    severity: payload.severity,
    reason: payload.reason,
    sourceIp: normalizedIp,
    sourceGeo,
    userAgent: payload.userAgent || null,
    origin: payload.origin || null,
    actionTaken: payload.actionTaken || 'incident_logged',
    status: 'open',
    createdAt: new Date(),
    resolvedAt: null
  });
}

async function markSessionSuspicious({ roomId, userId, socketId, frozen = true, reason, revoke = true }) {
  await SessionLog.updateMany(
    { roomId, userId, socketId, status: 'online' },
    {
      suspicious: true,
      frozen,
      revokedAt: revoke ? new Date() : null,
      disconnectReason: reason,
      lastSecurityEventAt: new Date()
    }
  );
}

async function freezeRoom(roomId, reason, frozenBy = 'system') {
  await Room.updateOne(
    { roomId },
    {
      frozen: true,
      frozenReason: reason,
      frozenAt: new Date(),
      frozenBy
    }
  );
}

async function rotateAndFreezeRoomId(roomId, reason, frozenBy = 'system') {
  const newRoomId = `ROOM-${uuidv4().slice(0, 8)}`;
  const updated = await Room.findOneAndUpdate(
    { roomId },
    {
      roomId: newRoomId,
      frozen: true,
      frozenReason: reason,
      frozenAt: new Date(),
      frozenBy
    },
    { new: true }
  );

  return {
    oldRoomId: roomId,
    newRoomId: updated ? updated.roomId : null
  };
}

async function unfreezeRoom(roomId) {
  await Room.updateOne(
    { roomId },
    {
      frozen: false,
      frozenReason: null,
      frozenAt: null,
      frozenBy: null
    }
  );
}

async function markIncidentReviewed(id) {
  await Incident.updateOne({ _id: id }, { status: 'reviewed' });
}

async function markIncidentResolved(id) {
  await Incident.updateOne({ _id: id }, { status: 'resolved', resolvedAt: new Date() });
}

module.exports = {
  createIncident,
  markSessionSuspicious,
  freezeRoom,
  rotateAndFreezeRoomId,
  unfreezeRoom,
  markIncidentReviewed,
  markIncidentResolved
};
