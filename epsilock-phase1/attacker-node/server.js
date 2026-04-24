const path = require('path');
const express = require('express');
const morgan = require('morgan');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
const { createTlsServer } = require('../config/tls');
const { AttackerDemoClient } = require('./ws/client');
const { buildDemoRouter } = require('./routes/demo');

function bootstrap() {
  const app = express();
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));

  app.use(morgan('dev'));
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json({ limit: '1mb' }));
  app.use('/public', express.static(path.join(__dirname, 'public')));

  const mainWsUrl = process.env.MAIN_NODE_WSS_URL || 'wss://localhost:8443/ws';
  const attackerClient = new AttackerDemoClient({
    mainWsUrl,
    attackerToken: process.env.ATTACKER_DEMO_TOKEN || '',
    nodeId: process.env.ATTACKER_NODE_ID || 'ATTACKER-NODE-1'
  });

  app.locals.attackerClient = attackerClient;
  app.use(buildDemoRouter(attackerClient));

  const { server, protocol } = createTlsServer(app);
  const port = Number(process.env.ATTACKER_NODE_PORT || 4001);

  attackerClient.connect();

  server.listen(port, () => {
    console.log(`[attacker-node] listening on ${protocol}://localhost:${port}`);
    console.log(`[attacker-node] dashboard ${protocol}://localhost:${port}/attacker`);
  });
}

bootstrap();
