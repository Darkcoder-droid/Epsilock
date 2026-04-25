const jwt = require('jsonwebtoken');
const { WebSocketServer } = require('ws');
const { v4: uuidv4 } = require('uuid');
const { createPacket } = require('../../shared/packet');
const { PACKET_TYPES, WS_EVENTS } = require('../../shared/constants');
const { validatePacketShape, validatePayloadSize } = require('../../shared/validators');
const { decryptText } = require('../../shared/crypto');
const NodeSession = require('../../models/NodeSession');
const PacketMeta = require('../../models/PacketMeta');
const Incident = require('../../models/Incident');
const SessionLog = require('../../models/SessionLog');
const Room = require('../../models/Room');
const User = require('../../models/User');
const securityPolicy = require('../../config/securityPolicy');
const rateLimitStore = require('../../services/rateLimitStore');
const sessionRegistry = require('../../services/sessionRegistry');
const { recordAnomaly } = require('../../services/anomalyService');

function parseCookies(raw = '') {
  return raw.split(';').reduce((acc, piece) => {
    const [k, ...rest] = piece.trim().split('=');
    if (!k) return acc;
    acc[k] = decodeURIComponent(rest.join('='));
    return acc;
  }, {});
}

function nowTs() {
  return Date.now();
}

function makeCounter() {
  const map = new Map();
  return {
    hit(key, windowMs, limit) {
      const ts = nowTs();
      if (!map.has(key)) map.set(key, []);
      const arr = map.get(key);
      arr.push(ts);
      while (arr.length && arr[0] <= ts - windowMs) arr.shift();
      return { count: arr.length, triggered: arr.length > limit };
    }
  };
}

function allowedOrigin(origin) {
  const raw = process.env.ALLOWED_ORIGINS || 'https://localhost:8443,http://localhost:8443';
  const allowed = raw.split(',').map((v) => v.trim()).filter(Boolean);
  if (!origin) return true;
  return allowed.includes(origin);
}

function setupMainWsServer(server) {
  const wss = new WebSocketServer({ noServer: true, maxPayload: Number(process.env.MAX_WS_PAYLOAD_BYTES || 65536) });
  const nodeSockets = new Map();
  const userSockets = new Map();
  const adminSockets = new Set();
  const attackerSockets = new Set();
  const eventCounter = makeCounter();
  const msgCounter = makeCounter();
  const discCounter = makeCounter();
  const demoState = {
    attackerDemoEnabled: String(process.env.ATTACKER_DEMO_ENABLED || 'true') === 'true',
    coverEnabled: String(process.env.COVER_TRAFFIC_ENABLED || 'false') === 'true',
    coverTrafficIntervalMs: Number(process.env.COVER_TRAFFIC_INTERVAL_MS || 1500),
    coverTrafficJitterMs: Number(process.env.COVER_TRAFFIC_JITTER_MS || 1000),
    coverTrafficRatio: Number(process.env.COVER_TRAFFIC_RATIO || 3),
    recentPackets: []
  };

  function emitAdmin(payload) {
    const serialized = JSON.stringify(payload);
    for (const ws of adminSockets) {
      if (ws.readyState === 1) ws.send(serialized);
    }
  }

  function attackerSettingsPayload() {
    return {
      attackerDemoEnabled: demoState.attackerDemoEnabled,
      coverTrafficEnabled: demoState.coverEnabled,
      coverTrafficIntervalMs: demoState.coverTrafficIntervalMs,
      coverTrafficJitterMs: demoState.coverTrafficJitterMs,
      coverTrafficRatio: demoState.coverTrafficRatio
    };
  }

  function emitAttackerSettingsUpdate() {
    const serialized = JSON.stringify({
      type: WS_EVENTS.ATTACKER_DEMO_SETTINGS_UPDATED,
      settings: attackerSettingsPayload()
    });

    for (const ws of attackerSockets) {
      if (ws.readyState === 1 && ws.attackerAuthenticated) ws.send(serialized);
    }

    emitAdmin({ type: WS_EVENTS.ATTACKER_DEMO_SETTINGS_UPDATED, settings: attackerSettingsPayload() });
  }

  function emitSecuritySettingsUpdate() {
    emitAdmin({
      type: WS_EVENTS.SECURITY_SETTINGS_UPDATED,
      settings: attackerSettingsPayload()
    });
  }

  function emitCoverTrafficConfigToNodes() {
    const packet = JSON.stringify({
      type: WS_EVENTS.COVER_TRAFFIC_CONFIG_UPDATED,
      settings: {
        coverTrafficEnabled: demoState.coverEnabled,
        coverTrafficIntervalMs: demoState.coverTrafficIntervalMs,
        coverTrafficJitterMs: demoState.coverTrafficJitterMs,
        coverTrafficRatio: demoState.coverTrafficRatio
      }
    });
    for (const ws of nodeSockets.values()) {
      if (ws.readyState === 1) ws.send(packet);
    }
  }

  function emitMirroredPacketToAttackers(payload) {
    if (!demoState.attackerDemoEnabled) return;
    const mirrored = JSON.stringify({
      type: WS_EVENTS.ATTACKER_DEMO_PACKET,
      packet: {
        packetId: payload.packetId,
        type: payload.type,
        roomId: payload.roomId || null,
        fromUserId: payload.fromUserId || null,
        toUserId: payload.toUserId || null,
        nodeId: payload.nodeId,
        ciphertext: payload.ciphertext,
        nonce: payload.nonce,
        authTag: payload.authTag,
        sizeBytes: payload.sizeBytes || 0,
        isCover: Boolean(payload.isCover),
        createdAt: payload.createdAt || new Date().toISOString()
      }
    });

    for (const ws of attackerSockets) {
      if (ws.readyState === 1 && ws.attackerAuthenticated) ws.send(mirrored);
    }
  }

  function pushDemoPacket(meta, plaintext) {
    demoState.recentPackets.unshift({
      packetId: meta.packetId,
      type: meta.type,
      roomId: meta.roomId,
      fromUserId: meta.fromUserId ? String(meta.fromUserId) : null,
      toUserId: meta.toUserId ? String(meta.toUserId) : null,
      nodeId: meta.nodeId,
      sizeBytes: meta.sizeBytes,
      isCover: meta.isCover,
      createdAt: meta.createdAt,
      decrypted: plaintext
    });
    if (demoState.recentPackets.length > 300) demoState.recentPackets.length = 300;
    emitAdmin({ type: 'ATTACKER_DEMO_UPDATE', total: demoState.recentPackets.length });
  }

  async function logIncident({
    type,
    severity,
    reason,
    userId = null,
    username = null,
    roomId = null,
    nodeId = null,
    socketId = null,
    sourceIp = null,
    sourceGeo = null,
    userAgent = null,
    origin = null,
    metadata = {}
  }) {
    return recordAnomaly({
      type,
      severity,
      reason,
      userId,
      username,
      roomId,
      nodeId,
      socketId,
      sourceIp,
      sourceGeo,
      userAgent,
      origin,
      metadata
    });
  }

  async function disconnectNode(ws, reason, severity = 'high') {
    if (!ws.userId) {
      try { ws.close(4401, reason); } catch (_e) {}
      return;
    }

    await logIncident({
      type: 'BLOCKED_USER_ACTIVITY',
      severity,
      reason,
      userId: ws.userId,
      username: ws.username || null,
      roomId: ws.currentRoomId || null,
      nodeId: ws.nodeId,
      socketId: ws.socketId,
      sourceIp: ws.sourceIp,
      userAgent: ws.userAgent,
      origin: ws.origin || null
    });
    sessionRegistry.disconnectSocket(ws.socketId, reason);
  }

  function bindNodeSocket(ws, { nodeId, userId, username, sourceIp, userAgent }) {
    ws.socketId = `SOCK-${uuidv4().slice(0, 8)}`;
    ws.nodeId = nodeId;
    ws.userId = String(userId);
    ws.username = username || null;
    ws.sourceIp = sourceIp;
    ws.userAgent = userAgent;
    ws.nodeAuthenticated = false;
    ws.currentRoomId = null;

    nodeSockets.set(nodeId, ws);
    if (!userSockets.has(String(userId))) userSockets.set(String(userId), new Set());
    userSockets.get(String(userId)).add(ws);

    NodeSession.create({
      nodeId,
      userId,
      socketId: ws.socketId,
      status: 'online',
      sourceIp,
      userAgent,
      connectedAt: new Date(),
      lastSeenAt: new Date()
    }).catch(() => {});

    emitAdmin({ type: 'ADMIN_NODE_EVENT', event: 'connected', nodeId, userId: String(userId), sourceIp, userAgent });

    SessionLog.create({
      sessionId: `SESS-${uuidv4().slice(0, 10)}`,
      userId,
      username: username || null,
      nodeId,
      socketId: ws.socketId,
      sourceIp,
      userAgent,
      origin: ws.origin || null,
      status: 'active',
      connectedAt: new Date(),
      lastActivityAt: new Date()
    }).catch(() => {});

    sessionRegistry.registerSocket({
      socketId: ws.socketId,
      userId: String(userId),
      username: username || null,
      nodeId,
      role: 'user',
      roomId: null,
      ws
    });
  }

  function canUseAttackerRole() {
    if (process.env.NODE_ENV !== 'production') return true;
    return String(process.env.ATTACKER_DEMO_ENABLED || 'false') === 'true' || demoState.attackerDemoEnabled;
  }

  function sendDenied(ws, reason, roomId = null) {
    if (!ws || ws.readyState !== 1) return;
    ws.send(JSON.stringify({ type: WS_EVENTS.SEND_DENIED, reason, roomId }));
  }

  async function handleJoinRoom(ws, payload) {
    const roomId = String(payload.roomId || '').trim();
    if (!roomId) {
      ws.send(JSON.stringify({ type: WS_EVENTS.ROOM_JOIN_DENIED, roomId: null, reason: 'roomId is required' }));
      return;
    }

    if (!ws.nodeAuthenticated) {
      ws.send(JSON.stringify({ type: WS_EVENTS.ROOM_JOIN_DENIED, roomId, reason: 'Node is not authenticated' }));
      return;
    }

    const room = await Room.findOne({ roomId, status: 'active' }).lean();
    const members = (room?.participantUserIds || []).map(String);
    if (!room || !members.includes(String(ws.userId))) {
      ws.send(JSON.stringify({ type: WS_EVENTS.ROOM_JOIN_DENIED, roomId, reason: 'User is not assigned to this room' }));
      const tries = rateLimitStore.tooMany(
        `badjoin:${ws.userId}:${roomId}`,
        securityPolicy.invalidRoomAttempts.windowMs,
        securityPolicy.invalidRoomAttempts.maxAttempts
      );
      if (tries.triggered) {
        await logIncident({
          type: 'INVALID_ROOM_JOIN',
          severity: securityPolicy.invalidRoomAttempts.severity || 'high',
          reason: `Repeated invalid room join attempts for ${roomId}`,
          userId: ws.userId,
          username: ws.username || null,
          roomId,
          nodeId: ws.nodeId,
          socketId: ws.socketId,
          sourceIp: ws.sourceIp,
          userAgent: ws.userAgent || null,
          origin: ws.origin || null,
          metadata: { attempts: tries.count }
        });
      }
      return;
    }

    if (room.frozen) {
      ws.send(JSON.stringify({
        type: WS_EVENTS.ROOM_JOIN_DENIED,
        roomId,
        reason: room.frozenReason || 'Room is frozen'
      }));
      return;
    }

    ws.currentRoomId = roomId;
    sessionRegistry.updateSocketRoom(ws.socketId, roomId);
    SessionLog.updateOne({ socketId: ws.socketId, status: 'active' }, { roomId, lastActivityAt: new Date() }).catch(() => {});
    ws.send(JSON.stringify({ type: WS_EVENTS.ROOM_JOIN_OK, roomId }));
  }

  function broadcastToRoom(room, packet) {
    const serialized = JSON.stringify(packet);
    for (const uid of room?.participantUserIds || []) {
      const sockets = userSockets.get(String(uid));
      if (!sockets) continue;
      for (const client of sockets) {
        if (client.readyState !== 1) continue;
        if (!client.nodeAuthenticated) continue;
        if (String(client.currentRoomId || '') !== String(room.roomId || '')) continue;
        client.send(serialized);
      }
    }
  }

  async function handleDataPacket(ws, payload) {
    const maxPayload = Number(process.env.MAX_WS_PAYLOAD_BYTES || 65536);
    const sizeCheck = validatePayloadSize(payload, maxPayload);
    if (!sizeCheck.ok) {
      await logIncident({
        type: 'OVERSIZED_PAYLOAD',
        severity: securityPolicy.oversizedPayload.severity || 'high',
        reason: sizeCheck.reason,
        userId: ws.userId,
        username: ws.username || null,
        roomId: ws.currentRoomId || null,
        nodeId: ws.nodeId,
        socketId: ws.socketId,
        sourceIp: ws.sourceIp,
        userAgent: ws.userAgent || null,
        origin: ws.origin || null,
        metadata: { size: sizeCheck.size || null }
      });
      return;
    }

    const packetShape = validatePacketShape(payload);
    if (!packetShape.ok) {
      await logIncident({
        type: 'WS_EVENT_BURST',
        severity: 'medium',
        reason: packetShape.reason,
        userId: ws.userId,
        username: ws.username || null,
        roomId: ws.currentRoomId || null,
        nodeId: ws.nodeId,
        socketId: ws.socketId,
        sourceIp: ws.sourceIp,
        userAgent: ws.userAgent || null,
        origin: ws.origin || null
      });
      return;
    }

    if (!ws.nodeAuthenticated) {
      sendDenied(ws, 'Node authentication required', payload.roomId || null);
      return;
    }

    if (!ws.currentRoomId) {
      sendDenied(ws, 'Join a room before sending', payload.roomId || null);
      return;
    }

    if (String(payload.roomId || '') !== String(ws.currentRoomId)) {
      sendDenied(ws, 'Requested room does not match joined room', payload.roomId || null);
      await logIncident({
        type: 'INVALID_ROOM_SEND',
        severity: 'medium',
        reason: `Payload room mismatch expected ${ws.currentRoomId}, got ${payload.roomId || 'none'}`,
        userId: ws.userId,
        username: ws.username || null,
        roomId: payload.roomId || null,
        nodeId: ws.nodeId,
        socketId: ws.socketId,
        sourceIp: ws.sourceIp,
        userAgent: ws.userAgent || null,
        origin: ws.origin || null
      });
      return;
    }

    if (String(payload.fromUserId || ws.userId) !== String(ws.userId)) {
      sendDenied(ws, 'Sender identity mismatch', payload.roomId || null);
      await logIncident({
        type: 'TOKEN_SESSION_MISMATCH',
        severity: 'high',
        reason: 'Payload fromUserId does not match authenticated socket user',
        userId: ws.userId,
        username: ws.username || null,
        roomId: payload.roomId || null,
        nodeId: ws.nodeId,
        socketId: ws.socketId,
        sourceIp: ws.sourceIp,
        userAgent: ws.userAgent || null,
        origin: ws.origin || null
      });
      return;
    }

    const room = await Room.findOne({ roomId: payload.roomId, status: 'active' }).lean();
    const roomUsers = (room?.participantUserIds || []).map(String);
    if (!room || !roomUsers.includes(String(ws.userId)) || !roomUsers.includes(String(payload.fromUserId || ws.userId))) {
      sendDenied(ws, 'User is not a participant in this room', payload.roomId || null);
      await logIncident({
        type: 'INVALID_ROOM_SEND',
        severity: 'high',
        reason: 'Message sent to room without valid membership',
        userId: ws.userId,
        username: ws.username || null,
        roomId: payload.roomId || null,
        nodeId: ws.nodeId,
        socketId: ws.socketId,
        sourceIp: ws.sourceIp,
        userAgent: ws.userAgent || null,
        origin: ws.origin || null
      });
      return;
    }

    if (room.frozen) {
      sendDenied(ws, room.frozenReason || 'Room is frozen', payload.roomId || null);
      await logIncident({
        type: 'FROZEN_ROOM_SEND',
        severity: 'high',
        reason: room.frozenReason || 'Attempted send to frozen room',
        userId: ws.userId,
        username: ws.username || null,
        roomId: payload.roomId || null,
        nodeId: ws.nodeId,
        socketId: ws.socketId,
        sourceIp: ws.sourceIp,
        userAgent: ws.userAgent || null,
        origin: ws.origin || null
      });
      return;
    }

    let decrypted = '[unavailable]';
    if (payload.isCover) {
      decrypted = '[cover-noise]';
    } else {
      try {
        decrypted = decryptText(payload);
      } catch (_e) {
        decrypted = '[decrypt-failed]';
      }
    }

    if (payload.type === PACKET_TYPES.REAL_MESSAGE) {
      const flood = rateLimitStore.tooMany(
        `msg:${ws.userId}`,
        securityPolicy.messageFlood.windowMs,
        securityPolicy.messageFlood.maxMessages
      );
      if (flood.triggered) {
        await logIncident({
          type: 'MESSAGE_FLOOD',
          severity: securityPolicy.messageFlood.severity || 'medium',
          reason: `Message flood detected ${flood.count}/10s`,
          userId: ws.userId,
          username: ws.username || null,
          roomId: payload.roomId || null,
          nodeId: ws.nodeId,
          socketId: ws.socketId,
          sourceIp: ws.sourceIp,
          userAgent: ws.userAgent || null,
          origin: ws.origin || null,
          metadata: { messageCount: flood.count }
        });
        return;
      }
      if (payload.toUserId && !roomUsers.includes(String(payload.toUserId))) {
        await logIncident({
          type: 'INVALID_ROOM_SEND',
          severity: 'high',
          reason: 'Message sent to room without valid membership',
          userId: ws.userId,
          username: ws.username || null,
          roomId: payload.roomId || null,
          nodeId: ws.nodeId,
          socketId: ws.socketId,
          sourceIp: ws.sourceIp,
          userAgent: ws.userAgent || null,
          origin: ws.origin || null
        });
        return;
      }
    }

    if (payload.type === PACKET_TYPES.FILE_META || payload.type === PACKET_TYPES.FILE_PACKET) {
      const fileSize = Number(payload.fileSize || payload.sizeBytes || 0);
      const fileMime = String(payload.mimeType || '');
      const abuse = rateLimitStore.tooMany(`file:${ws.userId}`, securityPolicy.fileAbuse.windowMs, securityPolicy.fileAbuse.maxFiles);
      const mimeAllowed = securityPolicy.fileAbuse.allowedMimeTypes.includes(fileMime);
      const sizeAllowed = fileSize > 0 && fileSize <= securityPolicy.fileAbuse.maxBytes;
      if (abuse.triggered || !mimeAllowed || !sizeAllowed) {
        const severity = abuse.triggered ? 'high' : (securityPolicy.fileAbuse.severity || 'medium');
        await logIncident({
          type: 'FILE_ABUSE',
          severity,
          reason: 'File packet blocked by abuse policy',
          userId: ws.userId,
          username: ws.username || null,
          roomId: payload.roomId || null,
          nodeId: ws.nodeId,
          socketId: ws.socketId,
          sourceIp: ws.sourceIp,
          userAgent: ws.userAgent || null,
          origin: ws.origin || null,
          metadata: {
            mimeType: fileMime || null,
            fileSize,
            fileCount: abuse.count
          }
        });
        sendDenied(ws, 'File share blocked by security policy', payload.roomId || null);
        return;
      }
    }

    const meta = await PacketMeta.create({
      packetId: payload.packetId,
      type: payload.type,
      roomId: payload.roomId || null,
      fromUserId: ws.userId || null,
      toUserId: payload.toUserId || null,
      nodeId: payload.nodeId,
      sizeBytes: payload.sizeBytes || 0,
      isCover: Boolean(payload.isCover),
      createdAt: new Date(payload.createdAt || Date.now()),
      routeHint: payload.toUserId ? 'direct' : 'room',
      attackerDemoVisible: true
    });

    pushDemoPacket(meta, decrypted);
    const outboundPacket = {
      type: payload.type,
      packetId: payload.packetId,
      roomId: payload.roomId,
      fromUserId: String(ws.userId),
      fromUsername: ws.username || 'Unknown',
      toUserId: payload.toUserId || null,
      nodeId: payload.nodeId,
      ciphertext: payload.ciphertext,
      nonce: payload.nonce,
      authTag: payload.authTag,
      sizeBytes: payload.sizeBytes || 0,
      createdAt: payload.createdAt || new Date().toISOString(),
      isCover: Boolean(payload.isCover)
    };

    emitMirroredPacketToAttackers(outboundPacket);

    if (payload.type === PACKET_TYPES.REAL_MESSAGE) {
      broadcastToRoom(room, outboundPacket);
      return;
    }

    if (payload.type === PACKET_TYPES.COVER_TRAFFIC) {
      broadcastToRoom(room, outboundPacket);
    }
  }

  wss.on('connection', (ws) => {
    ws.on('message', async (raw) => {
      const rawSize = Buffer.isBuffer(raw) ? raw.length : Buffer.byteLength(String(raw || ''), 'utf8');
      if (rawSize > Number(securityPolicy.oversizedPayload.maxBytes || 8192)) {
        await logIncident({
          type: 'OVERSIZED_PAYLOAD',
          severity: securityPolicy.oversizedPayload.severity || 'high',
          reason: `Payload exceeds max bytes (${rawSize})`,
          userId: ws.userId || null,
          username: ws.username || null,
          roomId: ws.currentRoomId || null,
          nodeId: ws.nodeId || null,
          socketId: ws.socketId || null,
          sourceIp: ws.sourceIp || null,
          userAgent: ws.userAgent || null,
          origin: ws.origin || null,
          metadata: { rawSize }
        });
        ws.closeReason = 'oversized_payload';
        try { ws.close(4409, 'Oversized payload'); } catch (_e) {}
        return;
      }

      if (ws.nodeId) {
        const burst = rateLimitStore.tooMany(`wsevt:${ws.nodeId}`, securityPolicy.wsEventBurst.windowMs, securityPolicy.wsEventBurst.maxEvents);
        if (burst.triggered) {
          await logIncident({
            type: 'WS_EVENT_BURST',
            severity: securityPolicy.wsEventBurst.severity || 'medium',
            reason: `WS events exceeded threshold (${burst.count})`,
            userId: ws.userId || null,
            username: ws.username || null,
            roomId: ws.currentRoomId || null,
            nodeId: ws.nodeId,
            socketId: ws.socketId || null,
            sourceIp: ws.sourceIp || null,
            userAgent: ws.userAgent || null,
            origin: ws.origin || null,
            metadata: { eventCount: burst.count }
          });
          ws.closeReason = 'ws_event_burst';
          try { ws.close(4410, 'WS event burst'); } catch (_e) {}
          return;
        }
      }

      let payload;
      try {
        payload = JSON.parse(raw.toString());
      } catch (_e) {
        await logIncident({
          type: 'WS_EVENT_BURST',
          severity: 'medium',
          reason: 'Invalid JSON frame',
          nodeId: ws.nodeId,
          userId: ws.userId,
          username: ws.username || null,
          roomId: ws.currentRoomId || null,
          socketId: ws.socketId || null,
          sourceIp: ws.sourceIp,
          userAgent: ws.userAgent || null,
          origin: ws.origin || null
        });
        return;
      }

      if (ws.isAdmin) return;

      if (ws.isAttacker) {
        if (!ws.attackerAuthenticated) {
          if (payload.type !== PACKET_TYPES.ATTACKER_NODE_HELLO) {
            try { ws.close(4401, 'ATTACKER_NODE_HELLO required'); } catch (_e) {}
            return;
          }
          ws.attackerAuthenticated = true;
          ws.send(JSON.stringify({ type: WS_EVENTS.ATTACKER_DEMO_SETTINGS_UPDATED, settings: attackerSettingsPayload() }));
          emitAdmin({ type: 'ADMIN_NODE_EVENT', event: 'attacker_connected', client: 'attacker-node' });
        }
        return;
      }

      await NodeSession.updateOne({ socketId: ws.socketId }, { lastSeenAt: new Date() }).catch(() => {});
      await SessionLog.updateOne({ socketId: ws.socketId, status: 'active' }, { lastActivityAt: new Date() }).catch(() => {});

      if (payload.type === PACKET_TYPES.NODE_HELLO) {
        ws.helloAt = Date.now();
        if (String(payload.nodeId || '') !== String(ws.nodeId) || String(payload.fromUserId || '') !== String(ws.userId)) {
          ws.send(JSON.stringify({ type: WS_EVENTS.NODE_AUTH_DENIED, reason: 'Node identity mismatch' }));
          await logIncident({
            type: 'TOKEN_SESSION_MISMATCH',
            severity: securityPolicy.tokenMismatch.severity || 'critical',
            reason: `NODE_HELLO mismatch node=${payload.nodeId || 'none'} user=${payload.fromUserId || 'none'}`,
            userId: ws.userId,
            nodeId: ws.nodeId,
            sourceIp: ws.sourceIp,
            actionTaken: 'node_disconnected'
          });
          ws.closeReason = 'node_auth_mismatch';
          try { ws.close(4403, 'Node auth mismatch'); } catch (_e) {}
          return;
        }
        ws.nodeAuthenticated = true;
        ws.send(JSON.stringify({ type: WS_EVENTS.NODE_AUTH_OK, userId: ws.userId, nodeId: ws.nodeId }));
        ws.send(JSON.stringify({ type: WS_EVENTS.COVER_TRAFFIC_CONFIG_UPDATED, settings: {
          coverTrafficEnabled: demoState.coverEnabled,
          coverTrafficIntervalMs: demoState.coverTrafficIntervalMs,
          coverTrafficJitterMs: demoState.coverTrafficJitterMs,
          coverTrafficRatio: demoState.coverTrafficRatio
        } }));
        return;
      }

      if (payload.type === WS_EVENTS.JOIN_ROOM) {
        await handleJoinRoom(ws, payload);
        return;
      }

      if (
        payload.type === PACKET_TYPES.REAL_MESSAGE ||
        payload.type === PACKET_TYPES.COVER_TRAFFIC ||
        payload.type === PACKET_TYPES.FILE_META ||
        payload.type === PACKET_TYPES.FILE_PACKET
      ) {
        await handleDataPacket(ws, payload);
      }
    });

    ws.on('close', async () => {
      if (ws.isAdmin) {
        adminSockets.delete(ws);
        if (ws.socketId) sessionRegistry.unregisterSocket(ws.socketId);
        return;
      }

      if (ws.isAttacker) {
        attackerSockets.delete(ws);
        if (ws.socketId) sessionRegistry.unregisterSocket(ws.socketId);
        emitAdmin({ type: 'ADMIN_NODE_EVENT', event: 'attacker_disconnected', client: 'attacker-node' });
        return;
      }

      if (ws.nodeId) {
        nodeSockets.delete(ws.nodeId);
      }
      if (ws.userId && userSockets.has(String(ws.userId))) {
        const set = userSockets.get(String(ws.userId));
        set.delete(ws);
        if (set.size === 0) userSockets.delete(String(ws.userId));
      }

      await NodeSession.updateOne(
        { socketId: ws.socketId },
        { status: 'offline', disconnectedAt: new Date(), lastSeenAt: new Date() }
      ).catch(() => {});
      await SessionLog.updateOne(
        { socketId: ws.socketId, status: 'active' },
        { status: 'disconnected', disconnectedAt: new Date(), disconnectReason: ws.closeReason || 'socket_closed' }
      ).catch(() => {});
      sessionRegistry.unregisterSocket(ws.socketId);

      emitAdmin({ type: 'ADMIN_NODE_EVENT', event: 'disconnected', nodeId: ws.nodeId || null, userId: ws.userId || null });

      if (ws.nodeId) {
        const disc = discCounter.hit(`disc:${ws.nodeId}`, Number(process.env.DISCONNECT_ANOMALY_WINDOW_SECONDS || 60) * 1000, Number(process.env.DISCONNECT_ANOMALY_LIMIT || 6));
        if (disc.triggered) {
          await logIncident({
            type: 'ABNORMAL_DISCONNECT',
            severity: 'medium',
            reason: `Abnormal disconnect pattern (${disc.count})`,
            userId: ws.userId,
            username: ws.username || null,
            roomId: ws.currentRoomId || null,
            nodeId: ws.nodeId,
            socketId: ws.socketId,
            sourceIp: ws.sourceIp,
            userAgent: ws.userAgent,
            origin: ws.origin || null,
            metadata: { disconnectCount: disc.count }
          });
        }
      }
    });
  });

  server.on('upgrade', async (req, socket, head) => {
    if (!req.url.startsWith('/ws')) {
      socket.destroy();
      return;
    }

    const sourceIp = req.socket?.remoteAddress || null;
    const userAgent = req.headers['user-agent'] || null;
    const origin = req.headers.origin || null;

    if (!allowedOrigin(origin)) {
      await logIncident({
        type: 'ORIGIN_VALIDATION_FAILED',
        severity: securityPolicy.originFailure.severity || 'critical',
        reason: `Origin rejected: ${origin || 'none'}`,
        sourceIp,
        origin,
        userAgent
      });
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }

    let parsed;
    try {
      parsed = new URL(req.url, `https://${req.headers.host}`);
    } catch (_e) {
      socket.destroy();
      return;
    }

    const queryToken = parsed.searchParams.get('token');
    const nodeId = parsed.searchParams.get('nodeId');
    const userId = parsed.searchParams.get('userId');
    const clientType = parsed.searchParams.get('client');

    if (clientType === 'attacker') {
      if (!canUseAttackerRole()) {
        socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
        socket.destroy();
        return;
      }

      const expectedToken = process.env.ATTACKER_DEMO_TOKEN || '';
      if (!queryToken || !expectedToken || queryToken !== expectedToken) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }

      wss.handleUpgrade(req, socket, head, (ws) => {
        ws.isAttacker = true;
        ws.attackerAuthenticated = false;
        ws.socketId = `SOCK-${uuidv4().slice(0, 8)}`;
        ws.sourceIp = sourceIp;
        ws.userAgent = userAgent;
        ws.origin = origin;
        attackerSockets.add(ws);
        sessionRegistry.registerSocket({
          socketId: ws.socketId,
          role: 'attacker',
          roomId: null,
          ws
        });
        wss.emit('connection', ws, req);
      });
      return;
    }

    const cookies = parseCookies(req.headers.cookie || '');
    const cookieToken = cookies.epsi_access;
    const token = queryToken || cookieToken;

    if (!token) {
      await logIncident({
        type: 'BLOCKED_USER_ACTIVITY',
        severity: 'critical',
        reason: 'WebSocket upgrade attempted without authentication token',
        sourceIp,
        userAgent,
        origin
      });
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    let claims;
    try {
      claims = jwt.verify(token, process.env.JWT_SECRET);
    } catch (_e) {
      await logIncident({
        type: 'TOKEN_SESSION_MISMATCH',
        severity: securityPolicy.tokenMismatch.severity || 'critical',
        reason: 'JWT verification failed during websocket upgrade',
        sourceIp,
        userAgent,
        origin
      });
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    if (clientType === 'admin') {
      if (claims.role !== 'admin') {
        socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
        socket.destroy();
        return;
      }
      const adminUser = await User.findById(claims.sub).lean();
      if (!adminUser || adminUser.role !== 'admin' || adminUser.blocked || adminUser.requirePasswordReset) {
        socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
        socket.destroy();
        return;
      }
      if ((adminUser.revokedJtis || []).includes(String(claims.jti || '')) || Number(adminUser.tokenVersion || 0) !== Number(claims.ver || 0)) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }

      wss.handleUpgrade(req, socket, head, (ws) => {
        ws.isAdmin = true;
        ws.socketId = `SOCK-${uuidv4().slice(0, 8)}`;
        adminSockets.add(ws);
        sessionRegistry.registerSocket({
          socketId: ws.socketId,
          userId: String(claims.sub),
          username: claims.username || null,
          role: 'admin',
          roomId: null,
          ws
        });
        ws.send(JSON.stringify({ type: 'ADMIN_ALERT', code: 'ADMIN_CONNECTED' }));
        ws.send(JSON.stringify({ type: WS_EVENTS.SECURITY_SETTINGS_UPDATED, settings: attackerSettingsPayload() }));
        wss.emit('connection', ws, req);
      });
      return;
    }

    if (claims.role !== 'user' || !nodeId || !userId) {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }

    if (String(claims.sub) !== String(userId)) {
      await logIncident({
        type: 'TOKEN_SESSION_MISMATCH',
        severity: securityPolicy.tokenMismatch.severity || 'critical',
        reason: 'JWT sub does not match ws userId',
        userId,
        username: claims.username || null,
        nodeId,
        socketId: null,
        sourceIp,
        userAgent,
        origin
      });
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }

    const dbUser = await User.findById(userId).lean();
    if (!dbUser) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    if ((dbUser.revokedJtis || []).includes(String(claims.jti || ''))) {
      await logIncident({
        type: 'TOKEN_SESSION_MISMATCH',
        severity: securityPolicy.tokenMismatch.severity || 'critical',
        reason: 'JWT jti is revoked',
        userId,
        username: dbUser.username || null,
        nodeId,
        sourceIp,
        userAgent,
        origin
      });
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    if (Number(dbUser.tokenVersion || 0) !== Number(claims.ver || 0)) {
      await logIncident({
        type: 'TOKEN_SESSION_MISMATCH',
        severity: securityPolicy.tokenMismatch.severity || 'critical',
        reason: 'JWT tokenVersion mismatch',
        userId,
        username: dbUser.username || null,
        nodeId,
        sourceIp,
        userAgent,
        origin
      });
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    if (dbUser.blocked || dbUser.requirePasswordReset) {
      await logIncident({
        type: 'BLOCKED_USER_ACTIVITY',
        severity: 'critical',
        reason: dbUser.requirePasswordReset ? 'User must reset password before reconnecting' : (dbUser.blockReason || 'Blocked user attempted activity'),
        userId,
        username: dbUser.username || null,
        nodeId,
        sourceIp,
        userAgent,
        origin
      });
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }

    wss.handleUpgrade(req, socket, head, (ws) => {
      ws.isAdmin = false;
      ws.origin = origin || null;
      bindNodeSocket(ws, { nodeId, userId, username: claims.username, sourceIp, userAgent });
      wss.emit('connection', ws, req);
    });
  });

  return {
    getNodeRows() {
      return [...nodeSockets.values()].map((ws) => ({
        nodeId: ws.nodeId,
        userId: ws.userId,
        socketId: ws.socketId,
        status: 'online',
        sourceIp: ws.sourceIp,
        userAgent: ws.userAgent,
        lastSeen: new Date().toISOString()
      }));
    },
    getAttackerStatus() {
      const connected = [...attackerSockets].some((ws) => ws.readyState === 1 && ws.attackerAuthenticated);
      return {
        connected,
        totalSockets: [...attackerSockets].filter((ws) => ws.readyState === 1 && ws.attackerAuthenticated).length
      };
    },
    getDemoState() {
      return demoState;
    },
    applySecuritySettings(settings, options = {}) {
      if (settings.attackerDemoEnabled !== undefined) {
        demoState.attackerDemoEnabled = Boolean(settings.attackerDemoEnabled);
      }
      demoState.coverEnabled = Boolean(settings.coverTrafficEnabled);
      demoState.coverTrafficIntervalMs = Number(settings.coverTrafficIntervalMs || 1500);
      demoState.coverTrafficJitterMs = Number(settings.coverTrafficJitterMs || 1000);
      demoState.coverTrafficRatio = Number(settings.coverTrafficRatio || 3);
      emitCoverTrafficConfigToNodes();
      emitAttackerSettingsUpdate();
      if (options.emitAdminEvent !== false) emitSecuritySettingsUpdate();
      emitAdmin({ type: 'ATTACKER_DEMO_UPDATE', coverEnabled: demoState.coverEnabled });
    },
    setCoverEnabled(enabled) {
      this.applySecuritySettings({
        attackerDemoEnabled: demoState.attackerDemoEnabled,
        coverTrafficEnabled: Boolean(enabled),
        coverTrafficIntervalMs: demoState.coverTrafficIntervalMs,
        coverTrafficJitterMs: demoState.coverTrafficJitterMs,
        coverTrafficRatio: demoState.coverTrafficRatio
      });
    },
    clearDemoLogs() {
      demoState.recentPackets = [];
      emitAdmin({ type: 'ATTACKER_DEMO_UPDATE', total: 0 });
    },
    recordDemoPacket(entry) {
      const fallbackPacketId = entry.packetId || `DEMO-${uuidv4().slice(0, 8)}`;
      pushDemoPacket(
        {
          packetId: fallbackPacketId,
          type: entry.type || PACKET_TYPES.REAL_MESSAGE,
          roomId: entry.roomId || null,
          fromUserId: entry.fromUserId || null,
          toUserId: entry.toUserId || null,
          nodeId: entry.nodeId || 'demo',
          sizeBytes: entry.sizeBytes || 0,
          isCover: Boolean(entry.isCover),
          createdAt: entry.createdAt || new Date()
        },
        entry.decrypted || '[demo]'
      );
      emitMirroredPacketToAttackers({
        packetId: fallbackPacketId,
        type: entry.type || PACKET_TYPES.REAL_MESSAGE,
        roomId: entry.roomId || null,
        fromUserId: entry.fromUserId || null,
        toUserId: entry.toUserId || null,
        nodeId: entry.nodeId || 'demo',
        ciphertext: entry.ciphertext || '',
        nonce: entry.nonce || '',
        authTag: entry.authTag || '',
        sizeBytes: entry.sizeBytes || 0,
        isCover: Boolean(entry.isCover),
        createdAt: entry.createdAt || new Date().toISOString()
      });
    },
    async generateCoverBurst(roomId, fromUserId, toUserId, nodeId) {
      for (let i = 0; i < 15; i++) {
        const pkt = createPacket({
          type: PACKET_TYPES.COVER_TRAFFIC,
          roomId,
          fromUserId,
          toUserId,
          nodeId,
          ciphertext: 'burst-cover',
          nonce: 'n/a',
          authTag: 'n/a',
          sizeBytes: Math.floor(Math.random() * 700) + 250,
          isCover: true
        });

        const meta = await PacketMeta.create({
          packetId: pkt.packetId,
          type: pkt.type,
          roomId: pkt.roomId,
          fromUserId: pkt.fromUserId,
          toUserId: pkt.toUserId,
          nodeId: pkt.nodeId,
          sizeBytes: pkt.sizeBytes,
          isCover: true,
          createdAt: new Date(),
          routeHint: 'demo_cover_burst',
          attackerDemoVisible: true
        });
        pushDemoPacket(meta, '[cover-noise]');
        emitMirroredPacketToAttackers(pkt);
      }
    },
    async disconnectNodeById(nodeId, reason = 'Disconnected by admin') {
      const ws = nodeSockets.get(nodeId);
      if (!ws) return false;
      try {
        ws.send(JSON.stringify({ type: PACKET_TYPES.ADMIN_ALERT, code: 'DISCONNECTED_BY_ADMIN', reason }));
      } catch (_e) {}
      try {
        ws.close(4403, reason);
      } catch (_e) {}
      return true;
    },
    async disconnectUserById(userId, reason = 'Disconnected by admin') {
      const sockets = userSockets.get(String(userId));
      if (!sockets || sockets.size === 0) return false;
      for (const sock of sockets) {
        try {
          sock.send(JSON.stringify({ type: WS_EVENTS.FORCE_LOGOUT, reason }));
        } catch (_e) {}
        try {
          sock.close(4403, reason);
        } catch (_e) {}
      }
      return true;
    },
    emitAdmin
  };
}

module.exports = { setupMainWsServer };
