const { createIpRateLimiter } = require('./rateLimit');

const loginRateLimiter = createIpRateLimiter({
  windowMs: Number(process.env.LOGIN_RATE_WINDOW_MS || 60000),
  max: Number(process.env.LOGIN_RATE_MAX || 10),
  keyFn: (req) => `${req.ip}:${(req.body?.username || '').toLowerCase()}`
});

module.exports = { loginRateLimiter };
