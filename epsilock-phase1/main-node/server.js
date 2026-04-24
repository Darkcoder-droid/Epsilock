const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
const { connectDB } = require('../config/db');
const { createTlsServer } = require('../config/tls');
const { setupMainWsServer } = require('./ws/server');
const { authRouter } = require('./routes/auth');
const { adminRouter } = require('./routes/admin');
const { demoRouter } = require('./routes/demo');
const {
  getSecuritySettings,
  setSecuritySettingsBroadcaster
} = require('../services/securitySettingsService');

async function bootstrap() {
  await connectDB();

  const app = express();
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));

  app.use(morgan('dev'));
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json({ limit: '1mb' }));
  app.use(cookieParser());
  app.use('/public', express.static(path.join(__dirname, 'public')));

  app.get('/', (_req, res) => res.redirect('/admin'));

  app.use(authRouter);
  app.use(adminRouter);
  app.use(demoRouter);

  const { server, protocol } = createTlsServer(app);
  const wsHub = setupMainWsServer(server);
  app.locals.wsHub = wsHub;
  const initialSettings = await getSecuritySettings();
  wsHub.applySecuritySettings(initialSettings, { emitAdminEvent: false });
  setSecuritySettingsBroadcaster((settings) => {
    wsHub.applySecuritySettings(settings);
  });

  const port = Number(process.env.MAIN_NODE_PORT || 8443);
  server.listen(port, () => {
    console.log(`[main-node] listening on ${protocol}://localhost:${port}`);
  });
}

bootstrap().catch((err) => {
  console.error('[main-node] boot failure', err);
  process.exit(1);
});
