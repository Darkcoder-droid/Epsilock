const path = require('path');
const express = require('express');
const morgan = require('morgan');
const { connectDB } = require('../config/db');
const { createTlsServer } = require('../config/tls');

require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const recoveryRoutes = require('./routes/recovery');
const recoveryService = require('./services/recoveryService');

async function bootstrapBackup() {
  await connectDB();

  const app = express();
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));

  app.use(morgan('dev'));
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: false }));
  app.use(recoveryRoutes);

  app.get('/backup/recovery/:recoveryId/view', async (req, res) => {
    try {
      const status = await recoveryService.getStatus(req.params.recoveryId);
      return res.render('recovery_status', { status });
    } catch (err) {
      return res.status(404).send(err.message);
    }
  });

  const { server, protocol } = createTlsServer(app);
  const port = Number(process.env.BACKUP_NODE_PORT || 5000);
  server.listen(port, () => {
    console.log(`[backup-node] running on ${protocol}://localhost:${port}`);
  });
}

bootstrapBackup().catch((err) => {
  console.error('[backup-node] boot failure', err);
  process.exit(1);
});
