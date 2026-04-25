const express = require('express');
const { verifyMainNodeSignature } = require('../services/signatureVerifier');
const recoveryService = require('../services/recoveryService');

const router = express.Router();

router.use((req, res, next) => {
  if (req.path.includes('/status')) return next();
  const verified = verifyMainNodeSignature(req);
  if (!verified.ok) return res.status(401).json({ error: verified.reason });
  return next();
});

router.post('/backup/recovery/request', async (req, res) => {
  try {
    const payload = await recoveryService.createRecoveryRequest(req.body);
    return res.json(payload);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

router.get('/backup/recovery/:recoveryId/status', async (req, res) => {
  try {
    const payload = await recoveryService.getStatus(req.params.recoveryId);
    return res.json(payload);
  } catch (err) {
    return res.status(404).json({ error: err.message });
  }
});

router.post('/backup/recovery/:recoveryId/verify-user', async (req, res) => {
  try {
    if (!req.body.verifiedByMain) {
      return res.status(400).json({ error: 'verifiedByMain required' });
    }

    const payload = await recoveryService.verifyUser({
      recoveryId: req.params.recoveryId,
      userId: req.body.userId
    });
    return res.json(payload);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

router.post('/backup/recovery/:recoveryId/complete', async (req, res) => {
  try {
    const payload = await recoveryService.completeRecovery(req.params.recoveryId);
    return res.json(payload);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

module.exports = router;
