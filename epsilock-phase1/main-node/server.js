const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const express = require('express');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const { WebSocketServer } = require('ws');
const { connectDB } = require('../shared/db');
const { verifyToken } = require('../shared/auth');
const NodeRecord = require('../shared/models/NodeRecord');
const SessionLog = require('../shared/models/SessionLog');
const User = require('../shared/models/User');

require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const app = express();
const mainPort = Number(process.env.MAIN_NODE_PORT || 4000);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(morgan('dev'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use('/public', express.static(path.join(__dirname, 'public')));

const bridgeState = {
  nodeSockets: new Map(),
  userNodeMap: new Map(),
  roomParticipants: new Map()
};

function parseWsQuery(urlString) {
  const fakeUrl = new URL(urlString, 'https://localhost');
  return {
    token: fakeUrl.searchParams.get('token')
  };
}

function secureServerFactory() {
  const keyPath = path.resolve(path.join(__dirname, '..', process.env.TLS_KEY_PATH || './certs/localhost-key.pem'));
  const certPath = path.resolve(path.join(__dirname, '..', process.env.TLS_CERT_PATH || './certs/localhost-cert.pem'));

  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    const key = fs.readFileSync(keyPath);
    const cert = fs.readFileSync(certPath);
    console.log('[main-node] HTTPS enabled with local TLS certs (TLS 1.3 compatible).');
    return {
      server: https.createServer({ key, cert }, app),
      protocol: 'https'
    };
  }

  console.warn('[main-node] TLS certs missing. Falling back to HTTP for local dev only.');
  return {
    server: http.createServer(app),
    protocol: 'http'
  };
}

function authServiceMiddleware(req, res, next) {
  try {
    const header = req.get('authorization');
    if (!header || !header.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing token' });
    }

    const token = header.slice(7);
    const payload = verifyToken(token);
    if (payload.kind !== 'node-bridge') {
      return res.status(403).json({ error: 'Invalid node token kind' });
    }

    req.nodeAuth = payload;
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid service token' });
  }
}

function ensureRoomParticipants(roomId, senderUserId, receiverUserId) {
  if (!bridgeState.roomParticipants.has(roomId)) {
    bridgeState.roomParticipants.set(roomId, {
      senderUserId: String(senderUserId),
      receiverUserId: String(receiverUserId)
    });
  }
}

async function setupWsBroker(server) {
  const wss = new WebSocketServer({ server, path: '/ws/node' });

  wss.on('connection', async (ws, req) => {
    try {
      const { token } = parseWsQuery(req.url || '');
      if (!token) {
        ws.close(4001, 'Missing token');
        return;
      }

      const payload = verifyToken(token);
      if (payload.kind !== 'node-bridge') {
        ws.close(4003, 'Invalid token kind');
        return;
      }

      const nodeId = payload.nodeId;
      const nodeType = payload.nodeType;

      ws.nodeMeta = { nodeId, nodeType };
      bridgeState.nodeSockets.set(nodeId, ws);

      await NodeRecord.findOneAndUpdate(
        { nodeId },
        {
          nodeId,
          nodeType,
          status: 'online',
          wsEndpoint: `${process.env.MAIN_NODE_URL || `https://localhost:${mainPort}`}/ws/node`
        },
        { upsert: true, new: true }
      );

      ws.send(
        JSON.stringify({
          type: 'bridge-ready',
          nodeId,
          nodeType,
          message: 'Connected to main broker'
        })
      );

      ws.on('message', async (raw) => {
        try {
          const incoming = JSON.parse(raw.toString());
          const sourceNodeId = ws.nodeMeta?.nodeId;

          if (incoming.type === 'user-online') {
            bridgeState.userNodeMap.set(String(incoming.userId), sourceNodeId);
            return;
          }

          if (incoming.type === 'user-offline') {
            bridgeState.userNodeMap.delete(String(incoming.userId));
            return;
          }

          if (incoming.type === 'activity') {
            const room = await SessionLog.findOne({ roomId: incoming.roomId });
            if (!room) return;

            room.status = 'active';
            room.lastActivityAt = new Date();
            room.endedAt = null;
            await room.save();
            return;
          }

          if (incoming.type === 'chat-message' || incoming.type === 'file-offer' || incoming.type === 'file-request' || incoming.type === 'file-transfer') {
            const room = await SessionLog.findOne({ roomId: incoming.roomId });
            if (!room) return;

            ensureRoomParticipants(room.roomId, room.senderUserId, room.receiverUserId);
            const participants = bridgeState.roomParticipants.get(room.roomId);

            const fromUserId = String(incoming.fromUserId);
            const toUserId = String(incoming.toUserId);

            const validPair =
              (fromUserId === participants.senderUserId && toUserId === participants.receiverUserId) ||
              (fromUserId === participants.receiverUserId && toUserId === participants.senderUserId);

            if (!validPair) {
              ws.send(JSON.stringify({ type: 'error', message: 'Invalid room participant pair' }));
              return;
            }

            room.status = 'active';
            room.lastActivityAt = new Date();
            room.endedAt = null;
            await room.save();

            const targetNodeId = bridgeState.userNodeMap.get(toUserId);
            const targetSocket = targetNodeId ? bridgeState.nodeSockets.get(targetNodeId) : null;
            if (!targetSocket || targetSocket.readyState !== 1) {
              ws.send(JSON.stringify({ type: 'delivery-status', roomId: room.roomId, ok: false, reason: 'Target offline' }));
              return;
            }

            targetSocket.send(
              JSON.stringify({
                ...incoming,
                relayedBy: 'main-node',
                at: new Date().toISOString()
              })
            );

            ws.send(JSON.stringify({ type: 'delivery-status', roomId: room.roomId, ok: true }));
            return;
          }
        } catch (err) {
          ws.send(JSON.stringify({ type: 'error', message: 'Malformed WS payload' }));
        }
      });

      ws.on('close', async () => {
        if (!ws.nodeMeta) return;

        const { nodeId } = ws.nodeMeta;
        bridgeState.nodeSockets.delete(nodeId);
        const affectedUserIds = [];

        for (const [userId, mappedNodeId] of bridgeState.userNodeMap.entries()) {
          if (mappedNodeId === nodeId) {
            bridgeState.userNodeMap.delete(userId);
            affectedUserIds.push(userId);
          }
        }

        await NodeRecord.findOneAndUpdate({ nodeId }, { status: 'offline' });

        if (affectedUserIds.length) {
          const now = new Date();
          await SessionLog.updateMany(
            {
              status: 'active',
              $or: [{ senderUserId: { $in: affectedUserIds } }, { receiverUserId: { $in: affectedUserIds } }]
            },
            { status: 'disconnected', endedAt: now }
          );
        }

        // TODO: Phase 2 threat detection hook on abnormal socket disconnects.
      });
    } catch (err) {
      ws.close(4003, 'Unauthorized');
    }
  });
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'main-node' });
});

app.get('/internal/sessions/:userId', authServiceMiddleware, async (req, res) => {
  const { userId } = req.params;
  const sessions = await SessionLog.find({
    $or: [{ senderUserId: userId }, { receiverUserId: userId }]
  }).sort({ startedAt: -1 });

  return res.json({ sessions });
});

app.get('/internal/presence/:userId', authServiceMiddleware, async (req, res) => {
  const { userId } = req.params;
  const nodeId = bridgeState.userNodeMap.get(String(userId)) || null;
  return res.json({ online: !!nodeId, nodeId });
});

app.use('/auth', require('./routes/auth'));
app.use('/admin', require('./routes/admin')(bridgeState));

app.get('/', (_req, res) => {
  res.redirect('/auth/login');
});

async function bootstrap() {
  await connectDB();

  await NodeRecord.findOneAndUpdate(
    { nodeId: 'MAIN-NODE-1' },
    {
      nodeId: 'MAIN-NODE-1',
      nodeType: 'main',
      status: 'online',
      wsEndpoint: `${process.env.MAIN_NODE_URL || `https://localhost:${mainPort}`}/ws/node`
    },
    { upsert: true }
  );

  const { server, protocol } = secureServerFactory();
  await setupWsBroker(server);

  server.listen(mainPort, () => {
    console.log(`[main-node] listening on ${protocol}://localhost:${mainPort}`);
  });
}

bootstrap().catch((err) => {
  console.error('[main-node] boot failure', err);
  process.exit(1);
});
