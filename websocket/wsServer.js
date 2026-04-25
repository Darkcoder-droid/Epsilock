const { WebSocketServer } = require('ws');
const { v4: uuidv4 } = require('uuid');
const User = require('../models/User');
const Room = require('../models/Room');
const SessionLog = require('../models/SessionLog');
const RecoveryRequest = require('../models/RecoveryRequest');
const Incident = require('../models/Incident');
const { authSocketRequest } = require('./authSocket');
const { RoomManager } = require('./roomManager');
const { validateWsPayloadSize, validateChatMessageText, validateFileMetadata } = require('../security/payloadValidator');
const {
  detectMessageRateAnomaly,
  detectFileAbuse,
  detectDisconnectAnomaly,
  detectRealtimeWsEventAnomaly
} = require('../security/anomalyDetector');
const { wsChannelBlocker } = require('../security/rateLimiter');
const {
  createIncident,
  markSessionSuspicious,
  freezeRoom,
  rotateAndFreezeRoomId
} = require('../security/incidentService');
const { revokeToken, isTokenRevoked } = require('../security/tokenRevocation');

function parsePayload(raw) {
  try {
    return JSON.parse(raw.toString());
  } catch (_err) {
    return null;
  }
}

function setupWsServer(server, fileStore) {
  const wss = new WebSocketServer({
    noServer: true,
    maxPayload: Number(process.env.MAX_WS_PAYLOAD_BYTES || 16384)
  });

  const roomManager = new RoomManager();
  const userSocketMap = new Map();
  const adminSockets = new Set();
  const socketSessionIds = new Map();

  function send(ws, payload) {
    if (ws.readyState === 1) ws.send(JSON.stringify(payload));
  }

  function broadcastToRoom(roomId, payload) {
    for (const target of roomManager.socketsInRoom(roomId)) {
      send(target, payload);
    }
  }

  function broadcastAdmin(payload) {
    for (const ws of adminSockets) {
      send(ws, payload);
    }
  }

  function getUserSockets(userId) {
    return userSocketMap.get(String(userId)) || new Set();
  }

  function addUserSocket(userId, ws) {
    const key = String(userId);
    if (!userSocketMap.has(key)) userSocketMap.set(key, new Set());
    userSocketMap.get(key).add(ws);
  }

  function removeUserSocket(userId, ws) {
    const key = String(userId);
    const sockets = userSocketMap.get(key);
    if (!sockets) return;
    sockets.delete(ws);
    if (sockets.size === 0) userSocketMap.delete(key);
  }

  async function forceLogoutUser(userId, reason = 'Session revoked by security policy') {
    if (!userId) return;
    const sockets = [...(userSocketMap.get(String(userId)) || [])];
    for (const ws of sockets) {
      send(ws, { type: 'TOKEN_REVOKED', reason });
      ws.forceClosedBySecurity = true;
      ws.close(4403, 'Token revoked');
    }
  }

  async function markSession(roomId, userId, socketId, status) {
    if (status === 'online') {
      const key = `${socketId}:${roomId}`;
      const existingSessionId = socketSessionIds.get(key);
      if (existingSessionId) {
        await SessionLog.updateOne(
          { sessionId: existingSessionId },
          {
            status: 'online',
            disconnectedAt: null,
            lastActivityAt: new Date(),
            suspicious: false,
            frozen: false,
            disconnectReason: null
          }
        );
        return;
      }

      await SessionLog.updateMany(
        { roomId, userId, status: 'online' },
        { status: 'offline', disconnectedAt: new Date(), lastActivityAt: new Date() }
      );

      const now = new Date();
      const sessionId = `SESS-${uuidv4().slice(0, 10)}`;
      await SessionLog.create({
        sessionId,
        roomId,
        userId,
        socketId,
        connectedAt: now,
        disconnectedAt: null,
        lastActivityAt: now,
        status: 'online',
        suspicious: false,
        frozen: false,
        revokedAt: null,
        disconnectReason: null,
        lastSecurityEventAt: null
      });

      socketSessionIds.set(key, sessionId);
      return;
    }

    const key = `${socketId}:${roomId}`;
    const sessionId = socketSessionIds.get(key);
    if (!sessionId) {
      await SessionLog.updateMany(
        { roomId, userId, socketId, status: 'online' },
        { status: 'offline', disconnectedAt: new Date(), lastActivityAt: new Date() }
      );
      return;
    }

    await SessionLog.updateOne(
      { sessionId },
      {
        status: 'offline',
        disconnectedAt: new Date(),
        lastActivityAt: new Date()
      }
    );
    socketSessionIds.delete(key);
  }

  async function touchSessions(socketId) {
    await SessionLog.updateMany({ socketId, status: 'online' }, { lastActivityAt: new Date() });
  }

  async function handleSuspiciousActivity({
    ws,
    roomId,
    type,
    severity,
    reason,
    actionTaken,
    freezeTarget = 'room',
    disconnect = true
  }) {
    const originalRoomId = roomId || null;
    const incident = await createIncident({
      roomId: originalRoomId,
      userId: ws.user?.userId || null,
      socketId: ws.socketId || null,
      type,
      severity,
      reason,
      sourceIp: ws.sourceIp || null,
      userAgent: ws.userAgent || null,
      origin: ws.origin || null,
      actionTaken
    });

    await markSessionSuspicious({
      roomId: roomId || null,
      userId: ws.user?.userId || null,
      socketId: ws.socketId || null,
      frozen: true,
      reason,
      revoke: true
    });

    if (ws.user?.userId) {
      await User.updateOne(
        { _id: ws.user.userId, role: 'user' },
        {
          $inc: { tokenVersion: 1 },
          $set: {
            blocked: true,
            blockedUntil: null,
            blockReason: 'Anomaly detected: admin password reset required',
            requirePasswordReset: true
          }
        }
      );
      await forceLogoutUser(ws.user.userId, 'Anomaly detected. Session revoked on all devices.');
    }

    if (freezeTarget === 'room' && roomId) {
      const rotation = await rotateAndFreezeRoomId(roomId, reason, 'system');
      const rotatedRoomId = rotation.newRoomId || roomId;

      broadcastToRoom(roomId, {
        type: 'SECURITY_ALERT',
        roomId: rotatedRoomId,
        severity,
        reason: 'Suspicious activity was detected. This room has been frozen for safety. Access is blocked until admin unfreezes.'
      });
      broadcastToRoom(roomId, {
        type: 'SESSION_FROZEN',
        roomId: rotatedRoomId,
        reason: 'Suspicious activity was detected. This room has been frozen for safety. Access is blocked until admin unfreezes.'
      });

      // Disconnect every participant in the affected room to enforce immediate lockout.
      const participants = [...roomManager.socketsInRoom(roomId)];
      for (const participantSocket of participants) {
        participantSocket.forceClosedBySecurity = true;
        send(participantSocket, {
          type: 'SESSION_FROZEN',
          roomId: rotatedRoomId,
          reason: 'Suspicious activity was detected. This room has been frozen for safety. Access is blocked until admin unfreezes.'
        });
        participantSocket.close(4403, 'Room frozen due to suspicious activity');
      }

      roomId = rotatedRoomId;
      await createIncident({
        roomId,
        userId: ws.user?.userId || null,
        socketId: ws.socketId || null,
        type: 'room_id_rotated_after_incident',
        severity: 'medium',
        reason: `Room ID rotated from ${originalRoomId} to ${roomId} and access blocked`,
        sourceIp: ws.sourceIp || null,
        userAgent: ws.userAgent || null,
        origin: ws.origin || null,
        actionTaken: 'room_id_rotated_access_blocked'
      });
    }

    if (ws.tokenJti && ws.tokenExp) {
      revokeToken({ jti: ws.tokenJti, exp: ws.tokenExp, reason: type });
      send(ws, { type: 'TOKEN_REVOKED', reason: 'Session token revoked due to suspicious activity.' });
    }

    const adminPayload = {
      type: 'ADMIN_SECURITY_ALERT',
      incidentId: incident.incidentId,
      roomId,
      previousRoomId: originalRoomId,
      userId: incident.userId,
      severity: incident.severity,
      reason: incident.reason,
      status: incident.status,
      createdAt: incident.createdAt
    };
    broadcastAdmin(adminPayload);
    broadcastAdmin({ type: 'INCIDENT_CREATED', incidentId: incident.incidentId });

    if (roomId && roomId !== incident.roomId) {
      await Incident.updateOne({ _id: incident._id }, { roomId });
    }

    if (disconnect) {
      ws.forceClosedBySecurity = true;
      ws.close(4403, 'Suspicious activity detected');
    }
  }

  wss.on('connection', (ws) => {
    ws.joinedRooms = new Set();
    ws.isAdminSocket = ws.user.role === 'admin';

    if (ws.isAdminSocket) {
      adminSockets.add(ws);
      send(ws, {
        type: 'AUTH_SUCCESS',
        role: 'admin',
        userId: ws.user.userId,
        username: ws.user.username
      });
    } else {
      send(ws, {
        type: 'AUTH_SUCCESS',
        role: 'user',
        userId: ws.user.userId,
        username: ws.user.username
      });
    }

    ws.on('message', async (raw) => {
      if (ws.isAdminSocket) return;
      try {
        const payloadSize = validateWsPayloadSize(raw.toString());
        if (!payloadSize.ok) {
          await handleSuspiciousActivity({
            ws,
            type: 'oversized_payload_detection',
            severity: 'high',
            reason: `WebSocket payload exceeded max size (${payloadSize.size}/${payloadSize.max})`,
            actionTaken: 'session_frozen_token_revoked_socket_disconnected',
            freezeTarget: 'session'
          });
          return;
        }

        if (isTokenRevoked(ws.tokenJti)) {
          send(ws, { type: 'TOKEN_REVOKED', reason: 'Token already revoked.' });
          ws.forceClosedBySecurity = true;
          ws.close(4403, 'Token revoked');
          return;
        }

        const msg = parsePayload(raw);
        if (!msg || !msg.type) {
          send(ws, { type: 'ERROR', message: 'Invalid payload' });
          return;
        }

        const realtimeBurst = detectRealtimeWsEventAnomaly({ userId: ws.user.userId });
        if (realtimeBurst) {
          await handleSuspiciousActivity({
            ws,
            roomId: msg.roomId || [...ws.joinedRooms][0] || null,
            type: realtimeBurst.type,
            severity: realtimeBurst.severity,
            reason: realtimeBurst.reason,
            actionTaken: 'session_frozen_token_revoked_socket_disconnected',
            freezeTarget: 'session'
          });
          return;
        }

        if (msg.type === 'JOIN_ROOM') {
          const room = await Room.findOne({
            roomId: msg.roomId,
            participantUserIds: ws.user.userId,
            status: 'active'
          });

          if (!room) {
            await handleSuspiciousActivity({
              ws,
              roomId: msg.roomId,
              type: 'invalid_room_access',
              severity: 'high',
              reason: 'User attempted to join unauthorized room',
              actionTaken: 'session_frozen_token_revoked_socket_disconnected',
              freezeTarget: 'session'
            });
            return;
          }

          if (room.frozen) {
            send(ws, {
              type: 'SESSION_FROZEN',
              roomId: msg.roomId,
              reason: room.frozenReason || 'Suspicious activity was detected. This room has been frozen for safety.'
            });
            const recovery = await RecoveryRequest.findOne({
              oldRoomId: msg.roomId,
              status: { $in: ['pending', 'verified', 'completed'] }
            }).sort({ createdAt: -1 }).lean();
            if (recovery) {
              send(ws, {
                type: 'RECOVERY_REQUIRED',
                roomId: msg.roomId,
                recoveryId: recovery.recoveryId
              });
            }
            return;
          }

          if (room.recoveredFromRoomId) {
            const recoveryAccess = Array.isArray(ws.user.recoveryAccess) ? ws.user.recoveryAccess : [];
            if (!recoveryAccess.includes(room.roomId)) {
              send(ws, {
                type: 'RECOVERY_REQUIRED',
                roomId: room.roomId,
                reason: 'Recovered room requires verified secure recovery.'
              });
              return;
            }
          }

          if (ws.joinedRooms.has(msg.roomId)) {
            send(ws, { type: 'JOIN_ROOM', roomId: msg.roomId, ok: true, rejoined: true });
            broadcastToRoom(msg.roomId, {
              type: 'ROOM_USERS',
              roomId: msg.roomId,
              users: roomManager.roomUsers(msg.roomId)
            });
            return;
          }

          roomManager.join(msg.roomId, ws);
          ws.joinedRooms.add(msg.roomId);
          await markSession(msg.roomId, ws.user.userId, ws.socketId, 'online');
          await touchSessions(ws.socketId);

          send(ws, { type: 'JOIN_ROOM', roomId: msg.roomId, ok: true });
          broadcastToRoom(msg.roomId, {
            type: 'ROOM_USERS',
            roomId: msg.roomId,
            users: roomManager.roomUsers(msg.roomId)
          });
          broadcastToRoom(msg.roomId, {
            type: 'USER_ONLINE',
            roomId: msg.roomId,
            userId: ws.user.userId,
            username: ws.user.username
          });
          return;
        }

        if (msg.type === 'LEAVE_ROOM') {
          if (!ws.joinedRooms.has(msg.roomId)) {
            send(ws, { type: 'LEAVE_ROOM', roomId: msg.roomId, ok: true, alreadyLeft: true });
            return;
          }

          roomManager.leave(msg.roomId, ws);
          ws.joinedRooms.delete(msg.roomId);
          await markSession(msg.roomId, ws.user.userId, ws.socketId, 'offline');
          broadcastToRoom(msg.roomId, {
            type: 'USER_OFFLINE',
            roomId: msg.roomId,
            userId: ws.user.userId,
            username: ws.user.username
          });
          broadcastToRoom(msg.roomId, {
            type: 'ROOM_USERS',
            roomId: msg.roomId,
            users: roomManager.roomUsers(msg.roomId)
          });
          send(ws, { type: 'LEAVE_ROOM', roomId: msg.roomId, ok: true });
          return;
        }

        if (msg.type === 'CHAT_MESSAGE') {
          if (!roomManager.socketsInRoom(msg.roomId).has(ws)) {
            send(ws, { type: 'ERROR', message: 'Join room first' });
            return;
          }

          const room = await Room.findOne({
            roomId: msg.roomId,
            participantUserIds: ws.user.userId,
            status: 'active'
          });

          if (!room) {
            await handleSuspiciousActivity({
              ws,
              roomId: msg.roomId,
              type: 'invalid_room_access',
              severity: 'high',
              reason: 'User attempted to send chat to unauthorized room',
              actionTaken: 'session_frozen_token_revoked_socket_disconnected',
              freezeTarget: 'session'
            });
            return;
          }

          if (room.frozen) {
            send(ws, {
              type: 'SESSION_FROZEN',
              roomId: msg.roomId,
              reason: room.frozenReason || 'Suspicious activity was detected. This room has been frozen for safety.'
            });
            return;
          }

          const textValidation = validateChatMessageText(msg.text);
          if (!textValidation.ok) {
            await handleSuspiciousActivity({
              ws,
              roomId: msg.roomId,
              type: 'oversized_payload_detection',
              severity: 'high',
              reason: `Chat payload exceeded limit (${textValidation.size}/${textValidation.max})`,
              actionTaken: 'room_frozen_token_revoked_socket_disconnected',
              freezeTarget: 'room'
            });
            return;
          }

          const anomaly = detectMessageRateAnomaly({ userId: ws.user.userId });
          if (anomaly) {
            await handleSuspiciousActivity({
              ws,
              roomId: msg.roomId,
              type: anomaly.type,
              severity: anomaly.severity,
              reason: anomaly.reason,
              actionTaken: 'room_frozen_token_revoked_socket_disconnected',
              freezeTarget: 'room'
            });
            return;
          }

          broadcastToRoom(msg.roomId, {
            type: 'CHAT_MESSAGE',
            roomId: msg.roomId,
            fromUserId: ws.user.userId,
            fromUsername: ws.user.username,
            text: String(msg.text || '').slice(0, 2000),
            at: new Date().toISOString()
          });

          await touchSessions(ws.socketId);
          return;
        }

        if (msg.type === 'FILE_SHARED') {
          if (!roomManager.socketsInRoom(msg.roomId).has(ws)) {
            send(ws, { type: 'ERROR', message: 'Join room first' });
            return;
          }

          const room = await Room.findOne({
            roomId: msg.roomId,
            participantUserIds: ws.user.userId,
            status: 'active'
          });

          if (!room) {
            await handleSuspiciousActivity({
              ws,
              roomId: msg.roomId,
              type: 'invalid_room_access',
              severity: 'high',
              reason: 'User attempted to share file in unauthorized room',
              actionTaken: 'session_frozen_token_revoked_socket_disconnected',
              freezeTarget: 'session'
            });
            return;
          }

          if (room.frozen) {
            send(ws, {
              type: 'SESSION_FROZEN',
              roomId: msg.roomId,
              reason: room.frozenReason || 'Suspicious activity was detected. This room has been frozen for safety.'
            });
            return;
          }

          const fileAbuse = detectFileAbuse({ userId: ws.user.userId });
          if (fileAbuse) {
            await handleSuspiciousActivity({
              ws,
              roomId: msg.roomId,
              type: fileAbuse.type,
              severity: fileAbuse.severity,
              reason: fileAbuse.reason,
              actionTaken: 'room_frozen_token_revoked_socket_disconnected',
              freezeTarget: 'room'
            });
            return;
          }

          const record = fileStore.get(msg.tempToken);
          if (!record || record.roomId !== msg.roomId || record.ownerUserId !== ws.user.userId) {
            send(ws, { type: 'ERROR', message: 'Temporary file record not found' });
            return;
          }

          const metaValidation = validateFileMetadata({
            fileName: record.fileName,
            mimeType: record.mimeType,
            fileSize: record.size
          });

          if (!metaValidation.ok) {
            await handleSuspiciousActivity({
              ws,
              roomId: msg.roomId,
              type: 'file_abuse_detection',
              severity: 'high',
              reason: metaValidation.reason,
              actionTaken: 'room_frozen_token_revoked_socket_disconnected',
              freezeTarget: 'room'
            });
            return;
          }

          broadcastToRoom(msg.roomId, {
            type: 'FILE_SHARED',
            roomId: msg.roomId,
            byUserId: ws.user.userId,
            byUsername: ws.user.username,
            fileName: record.fileName,
            fileSize: record.size,
            mimeType: record.mimeType,
            tempDownloadUrl: `/files/temp/${record.token}`,
            expiresAt: record.expiresAt.toISOString(),
            at: new Date().toISOString()
          });

          await touchSessions(ws.socketId);
          return;
        }

        send(ws, { type: 'ERROR', message: 'Unknown message type' });
      } catch (err) {
        console.error('[ws] message handler error:', err.message);
        send(ws, { type: 'ERROR', message: 'WebSocket handler error' });
      }
    });

    ws.on('close', async () => {
      if (ws.isAdminSocket) {
        adminSockets.delete(ws);
        return;
      }

      const leftRooms = roomManager.leaveAll(ws);
      ws.joinedRooms.clear();

      const disconnectEvent = detectDisconnectAnomaly({ userId: ws.user.userId });
      if (disconnectEvent && !ws.forceClosedBySecurity) {
        const incident = await createIncident({
          roomId: leftRooms[0] || null,
          userId: ws.user.userId,
          socketId: ws.socketId,
          type: disconnectEvent.type,
          severity: disconnectEvent.severity,
          reason: disconnectEvent.reason,
          sourceIp: ws.sourceIp || null,
          userAgent: ws.userAgent || null,
          origin: ws.origin || null,
          actionTaken: 'incident_logged'
        });

        await SessionLog.updateMany(
          { socketId: ws.socketId, status: 'online' },
          { suspicious: true, lastSecurityEventAt: new Date(), disconnectReason: disconnectEvent.reason }
        );

        broadcastAdmin({
          type: 'ADMIN_SECURITY_ALERT',
          incidentId: incident.incidentId,
          severity: incident.severity,
          reason: incident.reason,
          roomId: incident.roomId,
          userId: incident.userId,
          createdAt: incident.createdAt
        });
        broadcastAdmin({ type: 'INCIDENT_CREATED', incidentId: incident.incidentId });
      }

      for (const roomId of leftRooms) {
        try {
          await markSession(roomId, ws.user.userId, ws.socketId, 'offline');
          if (!ws.replacedByNewConnection && !ws.forceClosedBySecurity) {
            broadcastToRoom(roomId, {
              type: 'USER_OFFLINE',
              roomId,
              userId: ws.user.userId,
              username: ws.user.username
            });
          }
          broadcastToRoom(roomId, {
            type: 'ROOM_USERS',
            roomId,
            users: roomManager.roomUsers(roomId)
          });
        } catch (err) {
          console.error('[ws] close handler error:', err.message);
        }
      }

      removeUserSocket(ws.user.userId, ws);

      // TODO Phase 2: suspicious socket disconnect handling can be expanded with network fingerprinting.
      // TODO Phase 3: backup node recovery and token revocation replication across nodes.
    });
  });

  server.on('upgrade', async (req, socket, head) => {
    if (!req.url || !req.url.startsWith('/ws')) {
      socket.destroy();
      return;
    }

    const sourceIp = req.socket?.remoteAddress || null;
    if (wsChannelBlocker.isBlocked(sourceIp)) {
      const info = wsChannelBlocker.getBlockInfo(sourceIp);
      await createIncident({
        roomId: null,
        userId: null,
        socketId: null,
        type: 'unauthenticated_channel_block_enforced',
        severity: 'medium',
        reason: `Blocked websocket channel access from source IP (reason=${info?.reason || 'policy'})`,
        sourceIp,
        userAgent: req.headers['user-agent'] || null,
        origin: req.headers.origin || null,
        actionTaken: 'socket_rejected_channel_block_active'
      });
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }

    const auth = await authSocketRequest(req);
    if (!auth.ok) {
      const unauthNoCookie = auth.code === 'NO_COOKIE';
      if (unauthNoCookie) {
        const blockSeconds = Number(process.env.TEMP_BLOCK_SECONDS || 180);
        wsChannelBlocker.block(sourceIp, blockSeconds * 1000, 'missing_login_credentials');
      }

      await createIncident({
        roomId: null,
        userId: null,
        socketId: null,
        type: unauthNoCookie
          ? 'unauthenticated_socket_access'
          : auth.code === 'ORIGIN_REJECTED'
            ? 'origin_validation_failure'
            : 'websocket_auth_failure',
        severity: unauthNoCookie
          ? 'high'
          : auth.code === 'ORIGIN_REJECTED'
            ? 'high'
            : 'medium',
        reason: unauthNoCookie
          ? 'WebSocket connection attempted without login credentials; channel blocked temporarily'
          : auth.reason,
        sourceIp,
        userAgent: req.headers['user-agent'] || null,
        origin: req.headers.origin || null,
        actionTaken: unauthNoCookie
          ? 'socket_rejected_and_channel_temporarily_blocked'
          : 'socket_rejected'
      });
      broadcastAdmin({
        type: 'ADMIN_SECURITY_ALERT',
        severity: unauthNoCookie ? 'high' : 'medium',
        reason: unauthNoCookie
          ? 'Unauthenticated socket access attempt detected. Channel temporarily blocked.'
          : `Socket authentication rejected (${auth.code || 'unknown'})`,
        roomId: null,
        userId: null
      });

      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    wss.handleUpgrade(req, socket, head, (ws) => {
      ws.user = {
        userId: auth.claims.sub,
        username: auth.claims.username,
        role: auth.claims.role,
        recoveryAccess: Array.isArray(auth.claims.recoveryAccess) ? auth.claims.recoveryAccess : []
      };
      ws.sourceIp = auth.sourceIp;
      ws.userAgent = auth.userAgent;
      ws.origin = auth.origin;
      ws.tokenJti = auth.claims.jti;
      ws.tokenExp = auth.claims.exp;
      ws.socketId = `SOCK-${uuidv4().slice(0, 10)}`;

      if (ws.user.role === 'user') {
        addUserSocket(ws.user.userId, ws);
      }

      wss.emit('connection', ws, req);
    });
  });

  return {
    onlineUsers() {
      return [...userSocketMap.keys()];
    },
    broadcastIncidentResolved(incident) {
      broadcastAdmin({
        type: 'INCIDENT_RESOLVED',
        incidentId: incident.incidentId,
        roomId: incident.roomId || null,
        resolvedAt: incident.resolvedAt || new Date().toISOString(),
        status: incident.status || 'resolved'
      });
    },
    broadcastAdminSecurityAlert(payload) {
      broadcastAdmin({ type: 'ADMIN_SECURITY_ALERT', ...payload });
    },
    forceLogoutUser,
    broadcastRoomSecurityAlert(roomId, reason) {
      broadcastToRoom(roomId, {
        type: 'SECURITY_ALERT',
        roomId,
        severity: 'medium',
        reason: reason || 'Suspicious activity was detected. This room has been frozen for safety.'
      });
      broadcastToRoom(roomId, {
        type: 'SESSION_FROZEN',
        roomId,
        reason: reason || 'Suspicious activity was detected. This room has been frozen for safety.'
      });
    },
    async broadcastRecoveryStarted({ roomId, recoveryId }) {
      const room = await Room.findOne({ roomId }).lean();
      if (!room) return;
      for (const userId of room.participantUserIds.map(String)) {
        const sockets = [...getUserSockets(userId)];
        for (const ws of sockets) {
          send(ws, {
            type: 'RECOVERY_STARTED',
            roomId,
            recoveryId,
            reason: 'Suspicious activity was detected. Recovery flow started.'
          });
          send(ws, {
            type: 'RECOVERY_REQUIRED',
            roomId,
            recoveryId
          });
        }
      }
    },
    async broadcastRecoveryVerified({ recoveryId, userId, username }) {
      broadcastAdmin({
        type: 'RECOVERY_VERIFIED',
        recoveryId,
        userId,
        username
      });
    },
    async broadcastRecoveryCompleted({ recoveryId, oldRoomId, newRoomId }) {
      const [oldRoom, newRoom] = await Promise.all([
        Room.findOne({ roomId: oldRoomId }).lean(),
        Room.findOne({ roomId: newRoomId }).lean()
      ]);

      const userIds = new Set();
      for (const id of (oldRoom?.participantUserIds || [])) userIds.add(String(id));
      for (const id of (newRoom?.participantUserIds || [])) userIds.add(String(id));

      for (const userId of userIds) {
        const sockets = [...getUserSockets(userId)];
        for (const ws of sockets) {
          send(ws, {
            type: 'RECOVERY_COMPLETED',
            recoveryId,
            oldRoomId,
            newRoomId
          });
          send(ws, {
            type: 'JOIN_RECOVERED_ROOM',
            recoveryId,
            newRoomId
          });
        }
      }

      broadcastAdmin({
        type: 'RECOVERY_COMPLETED',
        recoveryId,
        oldRoomId,
        newRoomId
      });
    },
    async broadcastRecoveryFailed({ recoveryId, reason }) {
      broadcastAdmin({
        type: 'RECOVERY_FAILED',
        recoveryId,
        reason
      });
    }
  };
}

module.exports = { setupWsServer };
