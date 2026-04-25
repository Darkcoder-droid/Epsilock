const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const { signAccessToken, setAuthCookie, clearAuthCookie } = require('../middleware/auth');
const { loginRateLimiter } = require('../middleware/rateLimitShared');
const { authFailureTracker } = require('../security/rateLimiter');
const { createIncident } = require('../security/incidentService');

const router = express.Router();

router.get('/login', (req, res) => {
  if (req.cookies?.epsi_access) return res.redirect('/dashboard');
  res.render('login', { error: null });
});

router.post('/login', loginRateLimiter, async (req, res) => {
  const { username, password } = req.body;
  const sourceIp = req.ip;

  if (authFailureTracker.isIpBlocked(sourceIp)) {
    return res.status(429).render('login', { error: 'Temporary block due to repeated authentication failures' });
  }

  const user = await User.findOne({ username });
  if (!user) {
    await createIncident({
      type: 'unregistered_login_attempt',
      severity: 'medium',
      reason: `Login rejected for unregistered username "${username}"`,
      actionTaken: 'login_rejected',
      sourceIp,
      userAgent: req.get('user-agent') || null,
      origin: req.get('origin') || null
    });

    const failState = authFailureTracker.registerFailure(sourceIp);
    if (failState.blocked) {
      await createIncident({
        type: 'repeated_authentication_failures',
        severity: 'high',
        reason: 'Repeated failed login attempts from same IP',
        actionTaken: 'temporary_ip_block',
        sourceIp,
        userAgent: req.get('user-agent') || null,
        origin: req.get('origin') || null
      });
    }
    return res.status(401).render('login', { error: 'Invalid credentials' });
  }

  const blockedUntil = user.blockedUntil ? new Date(user.blockedUntil).getTime() : null;
  const now = Date.now();
  if (user.blocked && blockedUntil && blockedUntil <= now && user.blockReason === 'Repeated authentication failures') {
    await User.updateOne({ _id: user._id }, { blocked: false, blockedUntil: null, blockReason: null });
    user.blocked = false;
    user.blockedUntil = null;
    user.blockReason = null;
  }

  if (user.blocked || (blockedUntil && blockedUntil > now)) {
    return res.status(403).render('login', { error: 'Account is temporarily blocked' });
  }

  if (user.requirePasswordReset) {
    return res.status(403).render('login', { error: 'Account locked after anomaly detection. Admin must set a new password.' });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    const failState = authFailureTracker.registerFailure(sourceIp);
    if (failState.blocked && user.role === 'user') {
      const blockedUntilDate = failState.until;
      await User.updateOne(
        { _id: user._id },
        {
          blocked: true,
          blockedUntil: blockedUntilDate,
          blockReason: 'Repeated authentication failures'
        }
      );

      await createIncident({
        userId: user._id,
        type: 'repeated_authentication_failures',
        severity: 'high',
        reason: 'Repeated failed login attempts caused temporary account and IP block',
        actionTaken: 'temporary_account_and_ip_block',
        sourceIp,
        userAgent: req.get('user-agent') || null,
        origin: req.get('origin') || null
      });
    }
    return res.status(401).render('login', { error: 'Invalid credentials' });
  }

  authFailureTracker.clearFailures(sourceIp);
  if (user.blocked && user.blockReason === 'Repeated authentication failures') {
    await User.updateOne({ _id: user._id }, { blocked: false, blockedUntil: null, blockReason: null });
  }

  const token = signAccessToken(user);
  const secureCookie = req.secure || req.get('x-forwarded-proto') === 'https';
  setAuthCookie(res, token, secureCookie);

  return res.redirect(user.role === 'admin' ? '/admin' : '/dashboard');
});

router.post('/logout', (req, res) => {
  const secureCookie = req.secure || req.get('x-forwarded-proto') === 'https';
  clearAuthCookie(res, secureCookie);
  return res.redirect('/login');
});

router.get('/logout', (req, res) => {
  const secureCookie = req.secure || req.get('x-forwarded-proto') === 'https';
  clearAuthCookie(res, secureCookie);
  return res.redirect('/login');
});

module.exports = router;
