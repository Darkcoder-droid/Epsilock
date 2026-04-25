const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
const { connectDB } = require('../config/db');
const { createTlsServer } = require('../config/tls');
const { buildChatRouter } = require('./routes/chat');

async function bootstrap() {
  await connectDB();

  const app = express();
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));
  app.locals.nodeRuntime = new Map();

  app.use(morgan('dev'));
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json({ limit: '1mb' }));
  app.use(cookieParser());
  app.use('/public', express.static(path.join(__dirname, 'public')));

  app.use(buildChatRouter());

  const { server, protocol } = createTlsServer(app);
  const port = Number(process.env.USER_NODE_PORT || 3001);
  server.listen(port, () => {
    console.log(`[user-node ${process.env.NODE_ID || 'node'}] listening on ${protocol}://localhost:${port}`);
  });
}

bootstrap().catch((err) => {
  console.error('[user-node] boot failure', err);
  process.exit(1);
});
