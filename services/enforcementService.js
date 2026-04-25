const User = require('../models/User');
const Room = require('../models/Room');
const SessionLog = require('../models/SessionLog');
const sessionRegistry = require('./sessionRegistry');

const typeSeverityMap = {
  MESSAGE_FLOOD: 'medium',
  WS_EVENT_BURST: 'medium',
  INVALID_ROOM_JOIN: 'high',
  INVALID_ROOM_SEND: 'high',
  OVERSIZED_PAYLOAD: 'high',
  FILE_ABUSE: 'medium',
  REPEATED_AUTH_FAILURES: 'high',
  ABNORMAL_DISCONNECT: 'medium',
  ORIGIN_VALIDATION_FAILED: 'critical',
  TOKEN_SESSION_MISMATCH: 'critical',
  FROZEN_ROOM_SEND: 'high',
  BLOCKED_USER_ACTIVITY: 'critical'
};

function severityForIncident(incident) {
  return incident.severity || typeSeverityMap[incident.type] || 'medium';
}

async function revokeUserSessions(userId, reason) {
  await SessionLog.updateMany(
    { userId, status: 'active' },
    { status: 'revoked', revokedAt: new Date(), disconnectReason: reason }
  );
}

async function forceLogoutUser(userId, reason) {
  const count = sessionRegistry.disconnectUserEverywhere(userId, reason);
  sessionRegistry.broadcastToAdmins({
    type: 'USER_FORCE_LOGOUT_DONE',
    userId: String(userId),
    reason,
    disconnectedSockets: count
  });
  return count;
}

async function enforceIncident(incident) {
  const severity = severityForIncident(incident);
  const reason = incident.reason || 'Security enforcement';
  const userId = incident.userId ? String(incident.userId) : null;
  const roomId = incident.roomId ? String(incident.roomId) : null;

  let actionTaken = `incident_logged_${severity}`;

  if (severity === 'low') {
    return actionTaken;
  }

  if (severity === 'medium') {
    if (incident.socketId) {
      sessionRegistry.disconnectSocket(String(incident.socketId), reason);
      actionTaken = 'socket_disconnected';
    }
    return actionTaken;
  }

  if (userId) {
    await User.updateOne(
      { _id: userId },
      {
        $inc: { tokenVersion: 1 },
        $set: {
          blocked: true,
          blockedUntil: null,
          blockReason: reason,
          requirePasswordReset: true
        }
      }
    );
    await revokeUserSessions(userId, reason);
    await forceLogoutUser(userId, reason);
    actionTaken = 'user_revoked_blocked_force_logout';
  }

  if (severity === 'critical' && roomId) {
    await Room.updateOne(
      { roomId },
      {
        frozen: true,
        frozenReason: reason,
        frozenAt: new Date(),
        frozenBy: 'system'
      }
    );
    sessionRegistry.broadcastToRoom(roomId, {
      type: 'ROOM_FROZEN',
      roomId,
      reason
    });
    actionTaken = `${actionTaken}_room_frozen`;
  }

  return actionTaken;
}

module.exports = {
  enforceIncident,
  forceLogoutUser,
  revokeUserSessions
};
