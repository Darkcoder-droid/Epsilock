const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const Incident = require('../../models/Incident');
const RecoveryRequest = require('../../models/RecoveryRequest');
const RecoveryToken = require('../../models/RecoveryToken');
const { issueRecoveryJwt } = require('./tokenService');

function hashChallenge(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

async function createRecoveryRequest({ incidentId, oldRoomId, affectedUserIds }) {
  const incident = await Incident.findOne({ incidentId });
  if (!incident) throw new Error('Incident not found');
  if (!['open', 'reviewed'].includes(incident.status)) throw new Error('Incident is not recoverable');

  const challengeCode = Math.random().toString(36).slice(2, 8).toUpperCase();
  const recoveryId = `REC-${uuidv4().slice(0, 10)}`;

  const expiresInMs = Number(process.env.RECOVERY_CHALLENGE_EXPIRY_SECONDS || 900) * 1000;
  const expiresAt = new Date(Date.now() + expiresInMs);

  await RecoveryRequest.create({
    recoveryId,
    incidentId,
    oldRoomId,
    newRoomId: null,
    affectedUserIds,
    status: 'pending',
    challengeCodeHash: hashChallenge(challengeCode),
    expiresAt,
    createdAt: new Date(),
    completedAt: null
  });

  return {
    recoveryId,
    status: 'pending',
    expiresAt,
    challengeCodeHint: `${challengeCode.slice(0, 2)}****`
  };
}

async function verifyUser({ recoveryId, userId }) {
  const request = await RecoveryRequest.findOne({ recoveryId });
  if (!request) throw new Error('Recovery request not found');
  if (request.expiresAt.getTime() <= Date.now()) {
    request.status = 'expired';
    await request.save();
    throw new Error('Recovery request expired');
  }

  if (!request.affectedUserIds.map(String).includes(String(userId))) {
    throw new Error('User not part of affected recovery set');
  }

  const { token, jti, expiresAt } = issueRecoveryJwt({ recoveryId, userId });

  await RecoveryToken.create({
    tokenId: `RTOK-${uuidv4().slice(0, 10)}`,
    recoveryId,
    userId,
    jti,
    used: false,
    expiresAt,
    createdAt: new Date()
  });

  request.status = 'verified';
  await request.save();

  return {
    recoveryToken: token,
    expiresAt
  };
}

async function completeRecovery(recoveryId) {
  const request = await RecoveryRequest.findOne({ recoveryId });
  if (!request) throw new Error('Recovery request not found');

  if (request.expiresAt.getTime() <= Date.now()) {
    request.status = 'expired';
    await request.save();
    throw new Error('Recovery request expired');
  }

  const requireAll = String(process.env.REQUIRE_ALL_USERS_FOR_RECOVERY || 'true') === 'true';
  if (requireAll) {
    const verifiedUnique = await RecoveryToken.distinct('userId', { recoveryId });
    if (verifiedUnique.length < request.affectedUserIds.length) {
      throw new Error('All affected users must verify before completion');
    }
  }

  const newRoomId = `ROOM-${uuidv4().slice(0, 8)}`;
  request.newRoomId = newRoomId;
  request.status = 'completed';
  request.completedAt = new Date();
  await request.save();

  return {
    recoveryId,
    oldRoomId: request.oldRoomId,
    newRoomId,
    status: request.status
  };
}

async function getStatus(recoveryId) {
  const request = await RecoveryRequest.findOne({ recoveryId }).lean();
  if (!request) throw new Error('Recovery request not found');

  return {
    recoveryId: request.recoveryId,
    incidentId: request.incidentId,
    oldRoomId: request.oldRoomId,
    newRoomId: request.newRoomId,
    status: request.status,
    expiresAt: request.expiresAt,
    completedAt: request.completedAt
  };
}

module.exports = {
  createRecoveryRequest,
  verifyUser,
  completeRecovery,
  getStatus
};
