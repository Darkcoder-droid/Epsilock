const express = require('express');

function buildDemoRouter(client) {
  const router = express.Router();

  router.get('/', (_req, res) => res.redirect('/attacker'));

  router.get('/attacker', (_req, res) => {
    res.render('layout', {
      title: 'Attacker Node Dashboard',
      bodyView: 'attacker_dashboard',
      data: {
        state: client.snapshot(),
        attackerNodeUrl: process.env.ATTACKER_NODE_URL || 'https://localhost:4001/attacker'
      }
    });
  });

  router.get('/api/state', (_req, res) => {
    res.json(client.snapshot());
  });

  router.post('/api/clear', (_req, res) => {
    client.clear();
    res.json({ ok: true });
  });

  router.get('/events', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const push = () => {
      res.write(`data: ${JSON.stringify(client.snapshot())}\n\n`);
    };

    push();
    const handler = () => push();
    client.on('update', handler);

    req.on('close', () => {
      client.off('update', handler);
    });
  });

  return router;
}

module.exports = { buildDemoRouter };
