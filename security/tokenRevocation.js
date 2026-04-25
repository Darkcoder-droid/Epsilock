const revokedTokenStore = new Map();
const revokedSessionStore = new Map();

function pruneExpired() {
  const now = Date.now();
  for (const [jti, entry] of revokedTokenStore.entries()) {
    if (entry.expiresAt <= now) revokedTokenStore.delete(jti);
  }
  for (const [sid, entry] of revokedSessionStore.entries()) {
    if (entry.expiresAt <= now) revokedSessionStore.delete(sid);
  }
}

setInterval(pruneExpired, 15000).unref();

function revokeToken({ jti, exp, reason = 'security_event' }) {
  if (!jti || !exp) return;
  revokedTokenStore.set(jti, {
    expiresAt: exp * 1000,
    reason
  });
}

function isTokenRevoked(jti) {
  if (!jti) return false;
  pruneExpired();
  return revokedTokenStore.has(jti);
}

function revokeSession({ sessionId, expiresAt = Date.now() + 10 * 60 * 1000, reason = 'security_event' }) {
  if (!sessionId) return;
  revokedSessionStore.set(sessionId, { expiresAt, reason });
}

function isSessionRevoked(sessionId) {
  if (!sessionId) return false;
  pruneExpired();
  return revokedSessionStore.has(sessionId);
}

module.exports = {
  revokeToken,
  isTokenRevoked,
  revokeSession,
  isSessionRevoked
};
