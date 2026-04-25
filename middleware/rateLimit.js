function createIpRateLimiter({ windowMs, max, keyFn }) {
  const buckets = new Map();

  setInterval(() => {
    const now = Date.now();
    for (const [key, state] of buckets.entries()) {
      if (state.resetAt <= now) buckets.delete(key);
    }
  }, Math.max(1000, Math.floor(windowMs / 2))).unref();

  return function rateLimit(req, res, next) {
    const key = keyFn ? keyFn(req) : req.ip;
    const now = Date.now();

    if (!buckets.has(key) || buckets.get(key).resetAt <= now) {
      buckets.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }

    const bucket = buckets.get(key);
    bucket.count += 1;

    if (bucket.count > max) {
      return res.status(429).send('Too many requests. Please try again later.');
    }

    return next();
  };
}

function createMessageRateLimiter({ windowMs, max }) {
  const buckets = new Map();

  return {
    check(key) {
      const now = Date.now();

      if (!buckets.has(key) || buckets.get(key).resetAt <= now) {
        buckets.set(key, { count: 1, resetAt: now + windowMs });
        return true;
      }

      const bucket = buckets.get(key);
      bucket.count += 1;
      return bucket.count <= max;
    }
  };
}

module.exports = {
  createIpRateLimiter,
  createMessageRateLimiter
};
