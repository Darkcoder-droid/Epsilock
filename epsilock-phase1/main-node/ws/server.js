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
const Room = require('../../models/Room');
const User = require('../../models/User');

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

  async function logIncident({ type, severity, reason, userId = null, nodeId = null, sourceIp = null, actionTaken = 'logged' }) {
    const incident = await Incident.create({
      incidentId: `INC-${uuidv4().slice(0, 10)}`,
      type,
      severity,
      reason,
      userId,
      nodeId,
      sourceIp,
      actionTaken,
      createdAt: new Date()
    });
    emitAdmin({ type: 'ADMIN_SECURITY_ALERT', incidentId: incident.incidentId, severity, reason, nodeId, userId });
    return incident;
  }

  async function disconnectNode(ws, reason, severity = 'high') {
    if (!ws.userId) {
      try { ws.close(4401, reason); } catch (_e) {}
      return;
    }

    await logIncident({
      type: 'node_disconnected',
      severity,
      reason,
      userId: ws.userId,
      nodeId: ws.nodeId,
      sourceIp: ws.sourceIp,
      actionTaken: 'node_session_revoked'
    });

    await User.updateOne(
      { _id: ws.userId },
      {
        $inc: { tokenVersion: 1 },
        blocked: true,
        blockedUntil: null,
        blockReason: 'Severe anomaly detected'
      }
    );

    const sockets = userSockets.get(String(ws.userId)) || new Set();
    for (const sock of sockets) {
      if (sock.readyState === 1) {
        sock.send(JSON.stringify({ type: 'ADMIN_ALERT', code: 'SESSION_REVOKED', reason }));
      }
      try { sock.close(4403, reason); } catch (_e) {}
    }
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
      await logIncident({
        type: 'invalid_room_join',
        severity: 'medium',
        reason: `Node tried joining unauthorized room ${roomId}`,
        userId: ws.userId,
        nodeId: ws.nodeId,
        sourceIp: ws.sourceIp,
        actionTaken: 'room_join_denied'
      });
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
        type: 'oversized_payload',
        severity: 'high',
        reason: sizeCheck.reason,
        userId: ws.userId,
        nodeId: ws.nodeId,
        sourceIp: ws.sourceIp,
        actionTaken: 'node_disconnected'
      });
      await disconnectNode(ws, 'Oversized payload');
      return;
    }

    const burst = eventCounter.hit(`evt:${ws.nodeId}`, 5000, Number(process.env.MAX_WS_EVENTS_PER_5_SECONDS || 40));
    if (burst.triggered) {
      await logIncident({
        type: 'ws_event_burst',
        severity: 'high',
        reason: `WS event burst ${burst.count} events/5s`,
        userId: ws.userId,
        nodeId: ws.nodeId,
        sourceIp: ws.sourceIp,
        actionTaken: 'node_disconnected'
      });
      await disconnectNode(ws, 'WS event burst detected');
      return;
    }

    const packetShape = validatePacketShape(payload);
    if (!packetShape.ok) {
      await logIncident({
        type: 'malformed_packet',
        severity: 'medium',
        reason: packetShape.reason,
        userId: ws.userId,
        nodeId: ws.nodeId,
        sourceIp: ws.sourceIp,
        actionTaken: 'packet_rejected'
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
        type: 'invalid_room_send',
        severity: 'medium',
        reason: `Payload room mismatch expected ${ws.currentRoomId}, got ${payload.roomId || 'none'}`,
        userId: ws.userId,
        nodeId: ws.nodeId,
        sourceIp: ws.sourceIp,
        actionTaken: 'send_denied'
      });
      return;
    }

    if (String(payload.fromUserId || ws.userId) !== String(ws.userId)) {
      sendDenied(ws, 'Sender identity mismatch', payload.roomId || null);
      await logIncident({
        type: 'token_session_mismatch',
        severity: 'high',
        reason: 'Payload fromUserId does not match authenticated socket user',
        userId: ws.userId,
        nodeId: ws.nodeId,
        sourceIp: ws.sourceIp,
        actionTaken: 'send_denied'
      });
      return;
    }

    const room = await Room.findOne({ roomId: payload.roomId, status: 'active' }).lean();
    const roomUsers = (room?.participantUserIds || []).map(String);
    if (!room || !roomUsers.includes(String(ws.userId)) || !roomUsers.includes(String(payload.fromUserId || ws.userId))) {
      sendDenied(ws, 'User is not a participant in this room', payload.roomId || null);
      await logIncident({
        type: 'invalid_room_send',
        severity: 'high',
        reason: 'Message sent to room without valid membership',
        userId: ws.userId,
        nodeId: ws.nodeId,
        sourceIp: ws.sourceIp,
        actionTaken: 'node_disconnected'
      });
      await disconnectNode(ws, 'Invalid room send');
      return;
    }

    if (room.frozen) {
      sendDenied(ws, room.frozenReason || 'Room is frozen', payload.roomId || null);
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
      const flood = msgCounter.hit(
        `msg:${ws.userId}`,
        10000,
        Number(process.env.MAX_MESSAGES_PER_10_SECONDS || 20)
      );
      if (flood.triggered) {
        await logIncident({
          type: 'message_flood',
          severity: 'high',
          reason: `Message flood detected ${flood.count}/10s`,
          userId: ws.userId,
          nodeId: ws.nodeId,
          sourceIp: ws.sourceIp,
          actionTaken: 'node_disconnected'
        });
        await disconnectNode(ws, 'Message flood detected');
        return;
      }
      if (payload.toUserId && !roomUsers.includes(String(payload.toUserId))) {
        await logIncident({
          type: 'invalid_room_send',
          severity: 'high',
          reason: 'Message sent to room without valid membership',
          userId: ws.userId,
          nodeId: ws.nodeId,
          sourceIp: ws.sourceIp,
          actionTaken: 'node_disconnected'
        });
        await disconnectNode(ws, 'Invalid room send');
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
      let payload;
      try {
        payload = JSON.parse(raw.toString());
      } catch (_e) {
        await logIncident({
          type: 'invalid_json',
          severity: 'medium',
          reason: 'Invalid JSON frame',
          nodeId: ws.nodeId,
          userId: ws.userId,
          sourceIp: ws.sourceIp,
          actionTaken: 'frame_rejected'
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

      if (payload.type === PACKET_TYPES.NODE_HELLO) {
        ws.helloAt = Date.now();
        if (String(payload.nodeId || '') !== String(ws.nodeId) || String(payload.fromUserId || '') !== String(ws.userId)) {
          ws.send(JSON.stringify({ type: WS_EVENTS.NODE_AUTH_DENIED, reason: 'Node identity mismatch' }));
          await logIncident({
            type: 'node_auth_mismatch',
            severity: 'high',
            reason: `NODE_HELLO mismatch node=${payload.nodeId || 'none'} user=${payload.fromUserId || 'none'}`,
            userId: ws.userId,
            nodeId: ws.nodeId,
            sourceIp: ws.sourceIp,
            actionTaken: 'node_disconnected'
          });
          await disconnectNode(ws, 'Node auth mismatch');
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

      if (payload.type === PACKET_TYPES.REAL_MESSAGE || payload.type === PACKET_TYPES.COVER_TRAFFIC) {
        await handleDataPacket(ws, payload);
      }
    });

    ws.on('close', async () => {
      if (ws.isAdmin) {
        adminSockets.delete(ws);
        return;
      }

      if (ws.isAttacker) {
        attackerSockets.delete(ws);
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

      emitAdmin({ type: 'ADMIN_NODE_EVENT', event: 'disconnected', nodeId: ws.nodeId || null, userId: ws.userId || null });

      if (ws.nodeId) {
        const disc = discCounter.hit(`disc:${ws.nodeId}`, Number(process.env.DISCONNECT_ANOMALY_WINDOW_SECONDS || 60) * 1000, Number(process.env.DISCONNECT_ANOMALY_LIMIT || 6));
        if (disc.triggered) {
          await logIncident({
            type: 'abnormal_disconnect',
            severity: 'medium',
            reason: `Abnormal disconnect pattern (${disc.count})`,
            userId: ws.userId,
            nodeId: ws.nodeId,
            sourceIp: ws.sourceIp,
            actionTaken: 'incident_logged'
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
        type: 'origin_failure',
        severity: 'high',
        reason: `Origin rejected: ${origin || 'none'}`,
        sourceIp,
        actionTaken: 'upgrade_rejected'
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
        ws.sourceIp = sourceIp;
        ws.userAgent = userAgent;
        attackerSockets.add(ws);
        wss.emit('connection', ws, req);
      });
      return;
    }

    const cookies = parseCookies(req.headers.cookie || '');
    const cookieToken = cookies.epsi_access;
    const token = queryToken || cookieToken;

    if (!token) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    let claims;
    try {
      claims = jwt.verify(token, process.env.JWT_SECRET);
    } catch (_e) {
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

      wss.handleUpgrade(req, socket, head, (ws) => {
        ws.isAdmin = true;
        adminSockets.add(ws);
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
        type: 'token_session_mismatch',
        severity: 'high',
        reason: 'JWT sub does not match ws userId',
        userId,
        nodeId,
        sourceIp,
        actionTaken: 'upgrade_rejected'
      });
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }

    const dbUser = await User.findById(userId).lean();
    if (!dbUser || dbUser.blocked || Number(dbUser.tokenVersion || 0) !== Number(claims.ver || 0)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    wss.handleUpgrade(req, socket, head, (ws) => {
      ws.isAdmin = false;
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
    emitAdmin
  };
}

module.exports = { setupMainWsServer };
