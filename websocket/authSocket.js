const { verifyAccessToken } = require('../middleware/auth');
const { isOriginAllowed } = require('../security/originValidator');
const { isTokenRevoked } = require('../security/tokenRevocation');
const User = require('../models/User');

function parseCookies(cookieHeader = '') {
  const out = {};
  cookieHeader.split(';').map((v) => v.trim()).filter(Boolean).forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const key = pair.slice(0, idx);
    const value = decodeURIComponent(pair.slice(idx + 1));
    out[key] = value;
  });
  return out;
}

async function authSocketRequest(req) {
  const origin = req.headers.origin || null;
  if (!isOriginAllowed(origin)) {
    return { ok: false, reason: 'Origin not allowed', code: 'ORIGIN_REJECTED' };
  }

  const cookies = parseCookies(req.headers.cookie || '');
  const token = cookies.epsi_access;
  if (!token) return { ok: false, reason: 'Missing auth cookie', code: 'NO_COOKIE' };

  try {
    const claims = verifyAccessToken(token);
    if (isTokenRevoked(claims.jti)) {
      return { ok: false, reason: 'Token revoked', code: 'TOKEN_REVOKED' };
    }

    const user = await User.findById(claims.sub).lean();
    if (!user) return { ok: false, reason: 'User not found', code: 'NO_USER' };
    const claimVersion = Number.isFinite(claims.ver) ? Number(claims.ver) : 0;
    const userVersion = Number(user.tokenVersion || 0);
    if (claimVersion !== userVersion) {
      return { ok: false, reason: 'Session version mismatch', code: 'TOKEN_VERSION_MISMATCH' };
    }

    const blockedUntil = user.blockedUntil ? new Date(user.blockedUntil).getTime() : null;
    if (user.blocked && blockedUntil && blockedUntil <= Date.now() && user.blockReason === 'Repeated authentication failures') {
      await User.updateOne({ _id: user._id }, { blocked: false, blockedUntil: null, blockReason: null });
    } else if (user.blocked || (blockedUntil && blockedUntil > Date.now())) {
      return { ok: false, reason: 'User temporarily blocked', code: 'USER_BLOCKED' };
    }

    return {
      ok: true,
      claims,
      token,
      sourceIp: req.socket?.remoteAddress || null,
      userAgent: req.headers['user-agent'] || null,
      origin
    };
  } catch (_err) {
    return { ok: false, reason: 'Invalid token', code: 'INVALID_TOKEN' };
  }
}

module.exports = { authSocketRequest };
