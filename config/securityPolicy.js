module.exports = {
  messageFlood: {
    windowMs: 10000,
    maxMessages: 8,
    severity: 'medium'
  },
  wsEventBurst: {
    windowMs: 5000,
    maxEvents: 25,
    severity: 'medium'
  },
  invalidRoomAttempts: {
    windowMs: 60000,
    maxAttempts: 3,
    severity: 'high'
  },
  oversizedPayload: {
    maxBytes: 8192,
    severity: 'high'
  },
  fileAbuse: {
    windowMs: 60000,
    maxFiles: 5,
    maxBytes: 2 * 1024 * 1024,
    allowedMimeTypes: ['image/png', 'image/jpeg', 'application/pdf'],
    severity: 'medium'
  },
  authFailures: {
    windowMs: 300000,
    maxFailures: 5,
    severity: 'high'
  },
  abnormalDisconnect: {
    windowMs: 60000,
    maxDisconnects: 5,
    severity: 'medium'
  },
  tokenMismatch: {
    severity: 'critical'
  },
  originFailure: {
    severity: 'critical'
  }
};
