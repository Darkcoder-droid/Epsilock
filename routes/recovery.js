const express = require('express');
const bcrypt = require('bcryptjs');
const { requireAuth } = require('../middleware/auth');
const { signAccessToken, setAuthCookie } = require('../middleware/auth');
const User = require('../models/User');
const Room = require('../models/Room');
const Incident = require('../models/Incident');
const RecoveryRequest = require('../models/RecoveryRequest');
const {
  startRecoveryFromIncident,
  registerUserRecoveryVerification,
  finalizeRecovery,
  consumeRecoveryTokenForUser,
  getRecoveryStatusMerged
} = require('../services/recoveryManager');

const router = express.Router();

router.post('/admin/incidents/:incidentId/start-recovery', requireAuth, async (req, res) => {
  if (req.auth.role !== 'admin') return res.status(403).send('Forbidden');

  const incident = await Incident.findOne({ incidentId: req.params.incidentId });
  if (!incident) return res.status(404).send('Incident not found');

  try {
    const recovery = await startRecoveryFromIncident(incident);

    req.app.locals.wsState?.broadcastAdminSecurityAlert?.({
      severity: 'medium',
      reason: `Recovery started for incident ${incident.incidentId}`,
      roomId: incident.roomId,
      incidentId: incident.incidentId,
      recoveryId: recovery.recoveryId
    });

    req.app.locals.wsState?.broadcastRecoveryStarted?.({
      roomId: incident.roomId,
      recoveryId: recovery.recoveryId
    });

    return res.redirect(`/admin/incidents/${incident._id}`);
  } catch (err) {
    return res.status(400).send(err.message);
  }
});

router.get('/recovery/:recoveryId', requireAuth, async (req, res) => {
  try {
    const merged = await getRecoveryStatusMerged(req.params.recoveryId);
    if (!merged.local) return res.status(404).send('Recovery not found');

    const inAffectedSet = merged.local.affectedUserIds.map(String).includes(String(req.auth.sub));
    if (!inAffectedSet && req.auth.role !== 'admin') {
      return res.status(403).send('Not part of this recovery request');
    }

    return res.render('recovery', {
      auth: req.auth,
      local: merged.local,
      remote: merged.remote,
      error: null,
      success: null
    });
  } catch (err) {
    return res.status(400).send(err.message);
  }
});

router.post('/recovery/:recoveryId/verify', requireAuth, async (req, res) => {
  const { password } = req.body;

  const local = await RecoveryRequest.findOne({ recoveryId: req.params.recoveryId });
  if (!local) return res.status(404).send('Recovery not found');

  const inAffectedSet = local.affectedUserIds.map(String).includes(String(req.auth.sub));
  if (!inAffectedSet) return res.status(403).send('Not part of affected recovery users');

  const user = await User.findById(req.auth.sub);
  if (!user) return res.status(404).send('User not found');

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.render('recovery', {
      auth: req.auth,
      local,
      remote: null,
      error: 'Identity verification failed',
      success: null
    });
  }

  try {
    const payload = await registerUserRecoveryVerification({
      recoveryId: req.params.recoveryId,
      userId: req.auth.sub,
      username: req.auth.username
    });

    const secureCookie = req.secure || req.get('x-forwarded-proto') === 'https';
    res.cookie('epsi_recovery', payload.recoveryToken, {
      httpOnly: true,
      sameSite: 'strict',
      secure: secureCookie,
      maxAge: Number(process.env.RECOVERY_TOKEN_EXPIRY_SECONDS || 300) * 1000
    });

    req.app.locals.wsState?.broadcastRecoveryVerified?.({
      recoveryId: req.params.recoveryId,
      userId: req.auth.sub,
      username: req.auth.username
    });

    return res.render('recovery', {
      auth: req.auth,
      local,
      remote: null,
      error: null,
      success: 'Recovery identity verification successful. Complete recovery to join new secure room.'
    });
  } catch (err) {
    return res.render('recovery', {
      auth: req.auth,
      local,
      remote: null,
      error: err.message,
      success: null
    });
  }
});

router.post('/recovery/:recoveryId/complete', requireAuth, async (req, res) => {
  if (req.auth.role !== 'admin') return res.status(403).send('Forbidden');

  try {
    const result = await finalizeRecovery(req.params.recoveryId);

    req.app.locals.wsState?.broadcastRecoveryCompleted?.({
      recoveryId: req.params.recoveryId,
      newRoomId: result.newRoomId,
      oldRoomId: result.oldRoomId
    });

    return res.redirect(`/admin/incidents`);
  } catch (err) {
    req.app.locals.wsState?.broadcastRecoveryFailed?.({
      recoveryId: req.params.recoveryId,
      reason: err.message
    });
    return res.status(400).send(err.message);
  }
});

router.post('/recovery/:recoveryId/join-new-room', requireAuth, async (req, res) => {
  const recoveryToken = req.cookies?.epsi_recovery;
  if (!recoveryToken) return res.status(401).send('Recovery token missing. Verify identity first.');

  try {
    const recovered = await consumeRecoveryTokenForUser({
      recoveryId: req.params.recoveryId,
      userId: req.auth.sub,
      token: recoveryToken
    });

    const room = await Room.findOne({ roomId: recovered.newRoomId, participantUserIds: req.auth.sub, status: 'active' });
    if (!room) return res.status(403).send('Recovered room access denied');

    const secureCookie = req.secure || req.get('x-forwarded-proto') === 'https';
    const freshUser = await User.findById(req.auth.sub);
    const token = signAccessToken(freshUser, { recoveryAccess: [recovered.newRoomId] });
    setAuthCookie(res, token, secureCookie);

    res.clearCookie('epsi_recovery', {
      httpOnly: true,
      sameSite: 'strict',
      secure: secureCookie
    });

    return res.redirect(`/chat/${recovered.newRoomId}?recovered=1`);
  } catch (err) {
    return res.status(400).send(err.message);
  }
});

router.get('/admin/recovery/:recoveryId/status', requireAuth, async (req, res) => {
  if (req.auth.role !== 'admin') return res.status(403).send('Forbidden');
  const merged = await getRecoveryStatusMerged(req.params.recoveryId);
  return res.render('recovery_status', {
    local: merged.local,
    remote: merged.remote
  });
});

module.exports = router;
