const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const express = require('express');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const { WebSocketServer, WebSocket } = require('ws');
const { connectDB } = require('../shared/db');
const { verifyToken, signServiceNodeToken } = require('../shared/auth');

require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const NODE_TYPE = process.env.NODE_TYPE || 'sender';
const NODE_ID = process.env.NODE_ID || `${NODE_TYPE.toUpperCase()}-NODE-1`;
const MAIN_NODE_URL = process.env.MAIN_NODE_URL || 'https://localhost:4000';
const PORT = Number(
  NODE_TYPE === 'receiver'
    ? process.env.RECEIVER_NODE_PORT || 4002
    : process.env.SENDER_NODE_PORT || 4001
);

const FILE_TTL_MS = Number(process.env.FILE_TTL_MS || 120000);
const MAX_FILE_BYTES = Number(process.env.MAX_FILE_BYTES || 1048576);

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(morgan('dev'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use('/public', express.static(path.join(__dirname, 'public')));

const runtime = {
  serviceToken: null,
  bridgeSocket: null,
  userSockets: new Map(),
  tempFiles: new Map()
};

function cleanupTempFiles() {
  const now = Date.now();
  for (const [token, record] of runtime.tempFiles.entries()) {
    if (record.expiresAt <= now) {
      runtime.tempFiles.delete(token);
    }
  }
}

setInterval(cleanupTempFiles, 15000).unref();

function createServerWithTLS() {
  const keyPath = path.resolve(path.join(__dirname, '..', process.env.TLS_KEY_PATH || './certs/localhost-key.pem'));
  const certPath = path.resolve(path.join(__dirname, '..', process.env.TLS_CERT_PATH || './certs/localhost-cert.pem'));

  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    const key = fs.readFileSync(keyPath);
    const cert = fs.readFileSync(certPath);
    return {
      server: https.createServer({ key, cert }, app),
      protocol: 'https'
    };
  }

  return {
    server: http.createServer(app),
    protocol: 'http'
  };
}

function parseCookieHeader(cookieHeader = '') {
  const out = {};
  const parts = cookieHeader.split(';').map((x) => x.trim()).filter(Boolean);
  for (const part of parts) {
    const [k, ...v] = part.split('=');
    out[k] = decodeURIComponent(v.join('='));
  }
  return out;
}

function requestJson(urlStr, method = 'GET', payload = null, headers = {}) {
  const parsed = new URL(urlStr);
  const lib = parsed.protocol === 'https:' ? https : http;

  return new Promise((resolve, reject) => {
    const req = lib.request(
      {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port,
        path: `${parsed.pathname}${parsed.search}`,
        method,
        headers: {
          'content-type': 'application/json',
          ...headers
        },
        rejectUnauthorized: false // Local self-signed cert support.
      },
      (res) => {
        let body = '';
        res.on('data', (chunk) => {
          body += chunk.toString();
        });
        res.on('end', () => {
          if (res.statusCode >= 400) {
            return reject(new Error(`HTTP ${res.statusCode}: ${body}`));
          }

          if (!body) return resolve({});
          try {
            return resolve(JSON.parse(body));
          } catch (_err) {
            return resolve({ raw: body });
          }
        });
      }
    );

    req.on('error', reject);
    if (payload) req.write(JSON.stringify(payload));
    req.end();
  });
}

async function getServiceToken() {
  const token = signServiceNodeToken({ nodeType: NODE_TYPE, nodeId: NODE_ID });
  runtime.serviceToken = token;
  return token;
}

async function getUserRooms(userId) {
  if (!runtime.serviceToken) {
    await getServiceToken();
  }

  const result = await requestJson(`${MAIN_NODE_URL}/internal/sessions/${userId}`, 'GET', null, {
    authorization: `Bearer ${runtime.serviceToken}`
  });

  return result.sessions || [];
}

function sendToUser(userId, payload) {
  const targets = runtime.userSockets.get(String(userId));
  if (!targets || !targets.size) return;

  const text = JSON.stringify(payload);
  for (const ws of targets) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(text);
    }
  }
}

function relayToMain(payload) {
  const ws = runtime.bridgeSocket;
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(payload));
  }
}

function connectBridge() {
  return (async () => {
    if (!runtime.serviceToken) {
      await getServiceToken();
    }

    const wsProtocol = MAIN_NODE_URL.startsWith('https') ? 'wss' : 'ws';
    const wsBase = MAIN_NODE_URL.replace(/^https?/, wsProtocol);
    const wsUrl = `${wsBase}/ws/node?token=${encodeURIComponent(runtime.serviceToken)}`;

    const bridge = new WebSocket(wsUrl, {
      rejectUnauthorized: false // Local self-signed cert support.
    });

    runtime.bridgeSocket = bridge;

    bridge.on('open', () => {
      console.log(`[user-node:${NODE_TYPE}] bridge connected`);
    });

    bridge.on('message', (raw) => {
      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch (_err) {
        return;
      }

      if (msg.type === 'chat-message') {
        sendToUser(msg.toUserId, {
          type: 'chat',
          roomId: msg.roomId,
          fromUserId: msg.fromUserId,
          text: msg.text,
          at: msg.at
        });
      }

      if (msg.type === 'file-offer') {
        sendToUser(msg.toUserId, {
          type: 'file_offer',
          roomId: msg.roomId,
          fromUserId: msg.fromUserId,
          fileToken: msg.fileToken,
          fileName: msg.fileName,
          mimeType: msg.mimeType,
          size: msg.size,
          expiresAt: msg.expiresAt
        });
      }

      if (msg.type === 'file-request') {
        const entry = runtime.tempFiles.get(msg.fileToken);
        if (!entry || entry.expiresAt <= Date.now()) {
          runtime.tempFiles.delete(msg.fileToken);
          return;
        }

        relayToMain({
          type: 'file-transfer',
          roomId: msg.roomId,
          fromUserId: msg.fromUserId,
          toUserId: msg.toUserId,
          fileToken: msg.fileToken,
          fileName: entry.fileName,
          mimeType: entry.mimeType,
          data: entry.data
        });

        runtime.tempFiles.delete(msg.fileToken);
      }

      if (msg.type === 'file-transfer') {
        sendToUser(msg.toUserId, {
          type: 'file_transfer',
          roomId: msg.roomId,
          fromUserId: msg.fromUserId,
          fileToken: msg.fileToken,
          fileName: msg.fileName,
          mimeType: msg.mimeType,
          data: msg.data
        });
      }

      if (msg.type === 'bridge-ready') {
        console.log(`[user-node:${NODE_TYPE}] main bridge ready`);
      }
    });

    bridge.on('close', () => {
      runtime.bridgeSocket = null;
      console.warn(`[user-node:${NODE_TYPE}] bridge disconnected, retrying...`);

      // TODO: token revocation and secure reconnection strategy for future phases.
      setTimeout(() => {
        connectBridge().catch((err) => {
          console.error('[user-node] bridge reconnect failed', err.message);
        });
      }, 2000);

      // TODO: Phase 2 anomaly scoring middleware hook can inspect reconnect frequency.
    });
  })();
}

function ensureUserSocketSet(userId) {
  const key = String(userId);
  if (!runtime.userSockets.has(key)) {
    runtime.userSockets.set(key, new Set());
  }
  return runtime.userSockets.get(key);
}

function removeUserSocket(userId, ws) {
  const key = String(userId);
  const set = runtime.userSockets.get(key);
  if (!set) return 0;
  set.delete(ws);
  if (set.size === 0) {
    runtime.userSockets.delete(key);
  }
  return set.size;
}

function setupBrowserWs(server) {
  const wss = new WebSocketServer({ server, path: '/ws/chat' });

  wss.on('connection', async (ws, req) => {
    try {
      const cookies = parseCookieHeader(req.headers.cookie || '');
      const token = cookies.epsi_access;
      if (!token) {
        ws.close(4001, 'No auth token');
        return;
      }

      const claims = verifyToken(token);
      if (claims.role !== 'user') {
        ws.close(4003, 'Only user role allowed');
        return;
      }

      if (claims.assignedNodeType !== NODE_TYPE) {
        ws.close(4003, 'Wrong node assignment');
        return;
      }

      ws.user = {
        userId: claims.sub,
        username: claims.username,
        assignedNodeType: claims.assignedNodeType,
        assignedNodeId: claims.assignedNodeId,
        joinedRoomId: null
      };

      const set = ensureUserSocketSet(claims.sub);
      const firstSocketForUser = set.size === 0;
      set.add(ws);

      if (firstSocketForUser) {
        relayToMain({ type: 'user-online', userId: claims.sub, nodeId: NODE_ID });
      }

      ws.send(
        JSON.stringify({
          type: 'welcome',
          nodeType: NODE_TYPE,
          nodeId: NODE_ID,
          secureConnection: true,
          policy: 'No chat history is stored.'
        })
      );

      ws.on('message', async (raw) => {
        let payload;
        try {
          payload = JSON.parse(raw.toString());
        } catch (_err) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid payload' }));
          return;
        }

        if (payload.type === 'join-room') {
          const sessions = await getUserRooms(ws.user.userId);
          const room = sessions.find((s) => s.roomId === payload.roomId);
          if (!room) {
            ws.send(JSON.stringify({ type: 'error', message: 'Room not assigned to this user' }));
            return;
          }

          ws.user.joinedRoomId = payload.roomId;
          ws.send(JSON.stringify({ type: 'joined-room', roomId: payload.roomId }));
          relayToMain({ type: 'activity', roomId: payload.roomId, userId: ws.user.userId });
          return;
        }

        if (payload.type === 'chat') {
          if (!ws.user.joinedRoomId || ws.user.joinedRoomId !== payload.roomId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Join the room first' }));
            return;
          }

          const sessions = await getUserRooms(ws.user.userId);
          const room = sessions.find((s) => s.roomId === payload.roomId);
          if (!room) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid room' }));
            return;
          }

          const senderId = String(room.senderUserId);
          const receiverId = String(room.receiverUserId);
          const fromUserId = ws.user.userId;
          const toUserId = fromUserId === senderId ? receiverId : senderId;

          relayToMain({
            type: 'chat-message',
            roomId: payload.roomId,
            fromUserId,
            toUserId,
            text: String(payload.text || '').slice(0, 2000)
          });

          ws.send(
            JSON.stringify({
              type: 'chat',
              roomId: payload.roomId,
              fromUserId,
              text: String(payload.text || '').slice(0, 2000),
              at: new Date().toISOString()
            })
          );

          return;
        }

        if (payload.type === 'file-offer') {
          if (!ws.user.joinedRoomId || ws.user.joinedRoomId !== payload.roomId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Join the room first' }));
            return;
          }

          const sessions = await getUserRooms(ws.user.userId);
          const room = sessions.find((s) => s.roomId === payload.roomId);
          if (!room) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid room' }));
            return;
          }

          const data = String(payload.data || '');
          const size = Buffer.byteLength(data, 'base64');
          if (!size || size > MAX_FILE_BYTES) {
            ws.send(JSON.stringify({ type: 'error', message: 'File too large or invalid' }));
            return;
          }

          const senderId = String(room.senderUserId);
          const receiverId = String(room.receiverUserId);
          const fromUserId = ws.user.userId;
          const toUserId = fromUserId === senderId ? receiverId : senderId;

          const fileToken = `TMP-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
          const expiresAt = Date.now() + FILE_TTL_MS;

          runtime.tempFiles.set(fileToken, {
            fileName: payload.fileName || 'shared.bin',
            mimeType: payload.mimeType || 'application/octet-stream',
            data,
            expiresAt
          });

          relayToMain({
            type: 'file-offer',
            roomId: payload.roomId,
            fromUserId,
            toUserId,
            fileToken,
            fileName: payload.fileName || 'shared.bin',
            mimeType: payload.mimeType || 'application/octet-stream',
            size,
            expiresAt: new Date(expiresAt).toISOString()
          });

          ws.send(JSON.stringify({ type: 'file_buffered', fileToken, expiresAt }));
          return;
        }

        if (payload.type === 'file-request') {
          relayToMain({
            type: 'file-request',
            roomId: payload.roomId,
            fromUserId: payload.fromUserId,
            toUserId: ws.user.userId,
            fileToken: payload.fileToken
          });
          return;
        }
      });

      ws.on('close', () => {
        const remaining = removeUserSocket(ws.user.userId, ws);
        if (remaining === 0) {
          relayToMain({ type: 'user-offline', userId: ws.user.userId, nodeId: NODE_ID });
        }

        // TODO: Phase 2 threat detection hook on abnormal socket disconnects.
      });
    } catch (err) {
      ws.close(4003, 'Unauthorized');
    }
  });
}

app.locals.phase1 = {
  nodeType: NODE_TYPE,
  nodeId: NODE_ID,
  getUserRooms
};

app.use('/auth', require('./routes/auth'));
app.use('/dashboard', require('./routes/dashboard'));

app.get('/health', (_req, res) => {
  res.json({ ok: true, nodeType: NODE_TYPE, nodeId: NODE_ID });
});

app.get('/', (_req, res) => {
  res.redirect('/auth/login');
});

async function bootstrap() {
  await connectDB();
  await connectBridge();

  const { server, protocol } = createServerWithTLS();
  setupBrowserWs(server);

  server.listen(PORT, () => {
    console.log(`[user-node:${NODE_TYPE}] listening on ${protocol}://localhost:${PORT}`);
  });

  // TODO: Phase 3 backup node recovery server integration point.
}

bootstrap().catch((err) => {
  console.error('[user-node] boot failure', err);
  process.exit(1);
});
