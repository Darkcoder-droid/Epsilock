const jwt = require('jsonwebtoken');
const Room = require('../models/Room');
const Incident = require('../models/Incident');
const RecoveryRequest = require('../models/RecoveryRequest');
const RecoveryToken = require('../models/RecoveryToken');
const SessionLog = require('../models/SessionLog');
const {
  createRecoveryRequest: requestToBackup,
  verifyUserForRecovery,
  completeRecovery,
  getRecoveryStatus
} = require('./backupClient');

async function startRecoveryFromIncident(incident) {
  if (!incident || !incident.roomId) throw new Error('Incident missing roomId');

  const room = await Room.findOne({ roomId: incident.roomId });
  if (!room) throw new Error('Old room not found');

  const affectedUserIds = room.participantUserIds.map((id) => String(id));

  const backupResponse = await requestToBackup({
    incidentId: incident.incidentId,
    oldRoomId: incident.roomId,
    affectedUserIds
  });

  await RecoveryRequest.findOneAndUpdate(
    { recoveryId: backupResponse.recoveryId },
    {
      recoveryId: backupResponse.recoveryId,
      incidentId: incident.incidentId,
      oldRoomId: incident.roomId,
      newRoomId: null,
      affectedUserIds,
      status: backupResponse.status || 'pending',
      challengeCodeHash: backupResponse.challengeCodeHash || 'managed-by-backup',
      expiresAt: backupResponse.expiresAt ? new Date(backupResponse.expiresAt) : new Date(Date.now() + 15 * 60 * 1000),
      createdAt: new Date(),
      completedAt: null
    },
    { upsert: true }
  );

  await Incident.updateOne(
    { _id: incident._id },
    {
      recoveryId: backupResponse.recoveryId,
      recoveryStatus: 'pending'
    }
  );

  await Room.updateOne(
    { roomId: incident.roomId },
    { recoveryStatus: 'in_progress' }
  );

  return backupResponse;
}

async function registerUserRecoveryVerification({ recoveryId, userId, username }) {
  const res = await verifyUserForRecovery(recoveryId, { userId, username, verifiedByMain: true });

  const decoded = jwt.verify(res.recoveryToken, process.env.BACKUP_NODE_SECRET);

  await RecoveryToken.findOneAndUpdate(
    { jti: decoded.jti, recoveryId, userId },
    {
      used: false,
      expiresAt: new Date(decoded.exp * 1000)
    }
  );

  await RecoveryRequest.updateOne(
    { recoveryId },
    { status: 'verified' }
  );

  return {
    recoveryToken: res.recoveryToken,
    expiresAt: res.expiresAt
  };
}

async function finalizeRecovery(recoveryId) {
  const backup = await completeRecovery(recoveryId);
  const local = await RecoveryRequest.findOne({ recoveryId });
  if (!local) throw new Error('Local recovery request not found');

  const oldRoom = await Room.findOne({ roomId: local.oldRoomId });
  if (!oldRoom) throw new Error('Old room missing');

  await Room.create({
    roomId: backup.newRoomId,
    name: `${oldRoom.name} (Recovered)`,
    createdByAdminId: oldRoom.createdByAdminId,
    participantUserIds: oldRoom.participantUserIds,
    status: 'active',
    frozen: false,
    frozenReason: null,
    frozenAt: null,
    frozenBy: null,
    replacedByRoomId: null,
    recoveredFromRoomId: oldRoom.roomId,
    recoveryStatus: 'completed'
  });

  await Room.updateOne(
    { roomId: oldRoom.roomId },
    {
      status: 'closed',
      frozen: true,
      frozenReason: 'Replaced by recovery room',
      frozenBy: 'system',
      replacedByRoomId: backup.newRoomId,
      recoveryStatus: 'completed'
    }
  );

  await RecoveryRequest.updateOne(
    { recoveryId },
    {
      newRoomId: backup.newRoomId,
      status: 'completed',
      completedAt: new Date()
    }
  );

  await Incident.updateOne(
    { recoveryId },
    {
      recoveryStatus: 'completed',
      resolvedByRecovery: true,
      status: 'resolved',
      resolvedAt: new Date()
    }
  );

  await SessionLog.updateMany(
    { roomId: oldRoom.roomId, status: 'online' },
    {
      status: 'offline',
      disconnectedAt: new Date(),
      disconnectReason: 'Recovery cutover'
    }
  );

  return backup;
}

async function consumeRecoveryTokenForUser({ recoveryId, userId, token }) {
  const decoded = jwt.verify(token, process.env.BACKUP_NODE_SECRET);
  if (decoded.recoveryId !== recoveryId || String(decoded.userId) !== String(userId)) {
    throw new Error('Recovery token mismatch');
  }

  const tokenRow = await RecoveryToken.findOne({ jti: decoded.jti, recoveryId, userId });
  if (!tokenRow || tokenRow.used) throw new Error('Recovery token already used or missing');
  if (new Date(tokenRow.expiresAt).getTime() <= Date.now()) throw new Error('Recovery token expired');

  tokenRow.used = true;
  await tokenRow.save();

  const recovery = await RecoveryRequest.findOne({ recoveryId });
  if (!recovery || recovery.status !== 'completed' || !recovery.newRoomId) {
    throw new Error('Recovery not completed yet');
  }

  return {
    newRoomId: recovery.newRoomId
  };
}

async function getRecoveryStatusMerged(recoveryId) {
  const [local, remote] = await Promise.all([
    RecoveryRequest.findOne({ recoveryId }).lean(),
    getRecoveryStatus(recoveryId)
  ]);

  return {
    local,
    remote
  };
}

module.exports = {
  startRecoveryFromIncident,
  registerUserRecoveryVerification,
  finalizeRecovery,
  consumeRecoveryTokenForUser,
  getRecoveryStatusMerged
};
