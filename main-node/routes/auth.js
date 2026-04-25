const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const User = require('../../models/User');
const securityPolicy = require('../../config/securityPolicy');
const rateLimitStore = require('../../services/rateLimitStore');
const { recordAnomaly } = require('../../services/anomalyService');

const ACCESS_COOKIE_NAME = 'epsi_access';
const router = express.Router();

function signToken(user, extra = {}) {
  const jti = uuidv4();
  return jwt.sign(
    {
      sub: String(user._id),
      username: user.username,
      role: user.role,
      ver: Number(user.tokenVersion || 0),
      ...extra
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_TTL || '10m', jwtid: jti }
  );
}

function setCookie(res, token, secure) {
  res.cookie(ACCESS_COOKIE_NAME, token, {
    httpOnly: true,
    secure,
    sameSite: 'strict',
    maxAge: 10 * 60 * 1000
  });
}

function clearCookie(res, secure) {
  res.clearCookie(ACCESS_COOKIE_NAME, {
    httpOnly: true,
    secure,
    sameSite: 'strict'
  });
}

async function requireAdmin(req, res, next) {
  const token = req.cookies?.[ACCESS_COOKIE_NAME];
  if (!token) return res.redirect('/login');

  try {
    const claims = jwt.verify(token, process.env.JWT_SECRET);
    if (claims.role !== 'admin') return res.redirect('/login');
    const user = await User.findById(claims.sub).lean();
    if (!user || user.role !== 'admin') return res.redirect('/login');
    if (user.blocked || user.requirePasswordReset) return res.redirect('/login');
    if ((user.revokedJtis || []).includes(claims.jti)) return res.redirect('/login');
    if (Number(user.tokenVersion || 0) !== Number(claims.ver || 0)) return res.redirect('/login');
    req.auth = claims;
    return next();
  } catch (_e) {
    return res.redirect('/login');
  }
}

router.get('/login', (_req, res) => {
  res.render('layout', { title: 'Admin Login', bodyView: 'login', data: { error: null } });
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const sourceIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || null;
  const authKey = `authfail:${String(username || '').toLowerCase()}:${sourceIp || 'ip-unknown'}`;
  const user = await User.findOne({ username }).lean();
  if (!user || user.role !== 'admin') {
    const fail = rateLimitStore.tooMany(authKey, securityPolicy.authFailures.windowMs, securityPolicy.authFailures.maxFailures);
    if (fail.triggered) {
      await recordAnomaly({
        type: 'REPEATED_AUTH_FAILURES',
        severity: securityPolicy.authFailures.severity,
        reason: `Repeated failed login attempts for ${username || 'unknown'}`,
        username: username || null,
        sourceIp,
        metadata: { failures: fail.count }
      });
    }
    return res.status(401).render('layout', { title: 'Admin Login', bodyView: 'login', data: { error: 'Invalid credentials' } });
  }

  if (user.blocked || user.requirePasswordReset) {
    return res.status(403).render('layout', {
      title: 'Admin Login',
      bodyView: 'login',
      data: { error: user.requirePasswordReset ? 'Password reset required by admin.' : 'Account blocked.' }
    });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    const fail = rateLimitStore.tooMany(authKey, securityPolicy.authFailures.windowMs, securityPolicy.authFailures.maxFailures);
    if (fail.triggered) {
      await User.updateOne(
        { _id: user._id },
        {
          blocked: true,
          blockReason: 'Repeated authentication failures',
          blockedUntil: null,
          requirePasswordReset: true
        }
      );
      await recordAnomaly({
        type: 'REPEATED_AUTH_FAILURES',
        severity: securityPolicy.authFailures.severity,
        reason: `Repeated failed login attempts for ${user.username}`,
        userId: user._id,
        username: user.username,
        sourceIp,
        metadata: { failures: fail.count }
      });
    }
    return res.status(401).render('layout', { title: 'Admin Login', bodyView: 'login', data: { error: 'Invalid credentials' } });
  }

  rateLimitStore.reset(authKey);
  const token = signToken(user);
  setCookie(res, token, req.secure || req.protocol === 'https');
  return res.redirect('/admin');
});

router.post('/logout', (req, res) => {
  clearCookie(res, req.secure || req.protocol === 'https');
  return res.redirect('/login');
});

module.exports = {
  authRouter: router,
  requireAdmin,
  signToken,
  ACCESS_COOKIE_NAME
};
