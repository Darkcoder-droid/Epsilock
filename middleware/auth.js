const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const User = require('../models/User');
const { isTokenRevoked } = require('../security/tokenRevocation');

const ACCESS_COOKIE_NAME = 'epsi_access';

function getSecret() {
  if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET is required');
  return process.env.JWT_SECRET;
}

function signAccessToken(user, extraClaims = {}) {
  const ttl = process.env.ACCESS_TOKEN_TTL || '10m';
  return jwt.sign(
    {
      sub: user._id.toString(),
      username: user.username,
      role: user.role,
      ver: Number(user.tokenVersion || 0),
      jti: uuidv4(),
      ...extraClaims
    },
    getSecret(),
    { expiresIn: ttl }
  );
}

function verifyAccessToken(token) {
  return jwt.verify(token, getSecret());
}

function setAuthCookie(res, token, secureCookie = true) {
  res.cookie(ACCESS_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: secureCookie,
    maxAge: 10 * 60 * 1000
  });
}

function clearAuthCookie(res, secureCookie = true) {
  res.clearCookie(ACCESS_COOKIE_NAME, {
    httpOnly: true,
    sameSite: 'strict',
    secure: secureCookie
  });
}

function readTokenFromReq(req) {
  return req.cookies?.[ACCESS_COOKIE_NAME] || null;
}

async function requireAuth(req, res, next) {
  try {
    const token = readTokenFromReq(req);
    if (!token) return res.redirect('/login');
    const claims = verifyAccessToken(token);
    if (isTokenRevoked(claims.jti)) return res.redirect('/login');

    const user = await User.findById(claims.sub).lean();
    if (!user) return res.redirect('/login');
    const claimVersion = Number.isFinite(claims.ver) ? Number(claims.ver) : 0;
    const userVersion = Number(user.tokenVersion || 0);
    if (claimVersion !== userVersion) return res.redirect('/login');
    const blockedUntil = user.blockedUntil ? new Date(user.blockedUntil).getTime() : null;
    if (user.blocked && blockedUntil && blockedUntil <= Date.now() && user.blockReason === 'Repeated authentication failures') {
      await User.updateOne({ _id: user._id }, { blocked: false, blockedUntil: null, blockReason: null });
    } else if (user.blocked || (blockedUntil && blockedUntil > Date.now())) {
      return res.redirect('/login');
    }

    req.auth = claims;
    req.rawToken = token;
    return next();
  } catch (_err) {
    return res.redirect('/login');
  }
}

module.exports = {
  ACCESS_COOKIE_NAME,
  signAccessToken,
  verifyAccessToken,
  setAuthCookie,
  clearAuthCookie,
  readTokenFromReq,
  requireAuth
};
