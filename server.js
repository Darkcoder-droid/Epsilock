const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');

require('dotenv').config({ path: path.join(__dirname, '.env') });

const { connectDB } = require('./config/db');
const { createTlsServer } = require('./config/tls');
const authRoutes = require('./routes/auth');
const dashboardRoutes = require('./routes/dashboard');
const adminRoutes = require('./routes/admin');
const recoveryRoutes = require('./routes/recovery');
const { buildFilesRouter } = require('./routes/files');
const { requireAuth } = require('./middleware/auth');
const { setupWsServer } = require('./websocket/wsServer');
const SessionLog = require('./models/SessionLog');
const Incident = require('./models/Incident');
const RecoveryRequest = require('./models/RecoveryRequest');
const RecoveryToken = require('./models/RecoveryToken');

function createTempFileStore() {
  const byToken = new Map();

  function cleanup() {
    const now = Date.now();
    for (const [token, file] of byToken.entries()) {
      if (file.expiresAt.getTime() <= now) byToken.delete(token);
    }
  }

  setInterval(cleanup, 15000).unref();

  return {
    createTemp({ ownerUserId, roomId, fileName, mimeType, dataBase64, size, ttlMs }) {
      const token = `TMP-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
      const expiresAt = new Date(Date.now() + ttlMs);
      byToken.set(token, {
        token,
        ownerUserId,
        roomId,
        fileName,
        mimeType,
        dataBase64,
        size,
        expiresAt
      });
      return { token, expiresAt };
    },
    get(token) {
      const record = byToken.get(token);
      if (!record) return null;
      if (record.expiresAt.getTime() <= Date.now()) {
        byToken.delete(token);
        return null;
      }
      return record;
    },
    consume(token) {
      const record = this.get(token);
      if (!record) return null;
      byToken.delete(token);
      return record;
    }
  };
}

async function ensureSessionLogIndexes() {
  const indexes = await SessionLog.collection.indexes();
  const legacyRoomIndex = indexes.find((idx) => idx.name === 'roomId_1' && idx.unique);

  if (legacyRoomIndex) {
    await SessionLog.collection.dropIndex('roomId_1');
    console.log('[db] Dropped legacy unique index sessionlogs.roomId_1');
  }

  await SessionLog.collection.createIndex({ sessionId: 1 }, { unique: true, name: 'sessionId_1' });
  await SessionLog.collection.createIndex({ roomId: 1, userId: 1, status: 1 }, { name: 'room_user_status_1' });
  await SessionLog.collection.createIndex({ suspicious: 1, status: 1, lastSecurityEventAt: -1 }, { name: 'suspicious_status_event_1' });
}

async function ensureIncidentIndexes() {
  await Incident.collection.createIndex({ incidentId: 1 }, { unique: true, name: 'incidentId_1' });
  await Incident.collection.createIndex({ status: 1, severity: 1, createdAt: -1 }, { name: 'status_severity_createdAt_1' });
}

async function ensureRecoveryIndexes() {
  await RecoveryRequest.collection.createIndex({ recoveryId: 1 }, { unique: true, name: 'recoveryId_1' });
  await RecoveryRequest.collection.createIndex({ incidentId: 1, status: 1, createdAt: -1 }, { name: 'incident_status_createdAt_1' });
  await RecoveryToken.collection.createIndex({ tokenId: 1 }, { unique: true, name: 'tokenId_1' });
  await RecoveryToken.collection.createIndex({ jti: 1 }, { unique: true, name: 'jti_1' });
  await RecoveryToken.collection.createIndex({ recoveryId: 1, userId: 1, used: 1 }, { name: 'recovery_user_used_1' });
}

async function bootstrap() {
  await connectDB();
  await ensureSessionLogIndexes();
  await ensureIncidentIndexes();
  await ensureRecoveryIndexes();

  const app = express();
  const fileStore = createTempFileStore();

  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));

  app.use(morgan('dev'));
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json({ limit: '4mb' }));
  app.use(cookieParser());
  app.use('/public', express.static(path.join(__dirname, 'public')));
  app.use('/css', express.static(path.join(__dirname, 'public/css')));
  app.use('/js', express.static(path.join(__dirname, 'public/js')));

  app.get('/', (req, res) => {
    if (!req.cookies?.epsi_access) return res.redirect('/login');
    return res.redirect('/dashboard');
  });

  app.use(authRoutes);
  app.use(dashboardRoutes);
  app.use(adminRoutes);
  app.use(recoveryRoutes);
  app.use(buildFilesRouter(fileStore));

  app.get('/register', requireAuth, (req, res) => {
    if (req.auth.role !== 'admin') return res.status(403).send('Forbidden');
    return res.render('register', { error: null });
  });

  const { server, protocol } = createTlsServer(app);
  const wsState = setupWsServer(server, fileStore);
  app.locals.wsState = wsState;

  const port = Number(process.env.PORT || 4000);
  server.listen(port, () => {
    console.log(`[server] EPSILOCK Phase 3 main node running on ${protocol}://localhost:${port}`);
  });
}

bootstrap().catch((err) => {
  console.error('[server] boot failure', err);
  process.exit(1);
});
