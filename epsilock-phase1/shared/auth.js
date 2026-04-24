const jwt = require('jsonwebtoken');

const ACCESS_COOKIE_NAME = 'epsi_access';

function getJwtSecret() {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET is required');
  }
  return process.env.JWT_SECRET;
}

function getAccessTokenTTL() {
  return process.env.ACCESS_TOKEN_TTL || '10m';
}

function signAccessToken(user) {
  return jwt.sign(
    {
      sub: user._id.toString(),
      username: user.username,
      role: user.role,
      assignedNodeType: user.assignedNodeType || null,
      assignedNodeId: user.assignedNodeId || null
    },
    getJwtSecret(),
    { expiresIn: getAccessTokenTTL() }
  );
}

function signServiceNodeToken({ nodeType, nodeId }) {
  return jwt.sign(
    {
      nodeType,
      nodeId,
      kind: 'node-bridge'
    },
    getJwtSecret(),
    { expiresIn: '30m' }
  );
}

function verifyToken(token) {
  return jwt.verify(token, getJwtSecret());
}

function readTokenFromRequest(req) {
  const cookieToken = req.cookies?.[ACCESS_COOKIE_NAME];
  if (cookieToken) return cookieToken;

  const authHeader = req.get('authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }

  return null;
}

function setAuthCookie(res, token) {
  res.cookie(ACCESS_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: true,
    maxAge: 10 * 60 * 1000
  });
}

function clearAuthCookie(res) {
  res.clearCookie(ACCESS_COOKIE_NAME, {
    httpOnly: true,
    sameSite: 'strict',
    secure: true
  });
}

function requireAuth(req, res, next) {
  try {
    const token = readTokenFromRequest(req);
    if (!token) {
      return res.status(401).redirect('/auth/login');
    }

    req.auth = verifyToken(token);
    return next();
  } catch (err) {
    return res.status(401).redirect('/auth/login');
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.auth || req.auth.role !== role) {
      return res.status(403).send('Forbidden');
    }
    return next();
  };
}

module.exports = {
  ACCESS_COOKIE_NAME,
  signAccessToken,
  signServiceNodeToken,
  verifyToken,
  setAuthCookie,
  clearAuthCookie,
  requireAuth,
  requireRole,
  readTokenFromRequest
};
