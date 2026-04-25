class SlidingWindowCounter {
  constructor() {
    this.map = new Map();
  }

  hit(key, limit, windowMs) {
    const now = Date.now();
    if (!this.map.has(key)) this.map.set(key, []);

    const queue = this.map.get(key);
    queue.push(now);

    while (queue.length && queue[0] <= now - windowMs) {
      queue.shift();
    }

    return {
      allowed: queue.length <= limit,
      count: queue.length,
      limit,
      windowMs
    };
  }
}

class AuthFailureTracker {
  constructor() {
    this.failedByIp = new Map();
    this.blockedIp = new Map();
  }

  isIpBlocked(ip) {
    const value = this.blockedIp.get(ip);
    if (!value) return false;
    if (value.until <= Date.now()) {
      this.blockedIp.delete(ip);
      return false;
    }
    return true;
  }

  registerFailure(ip) {
    const windowMs = Number(process.env.FAILED_LOGIN_WINDOW_SECONDS || 120) * 1000;
    const limit = Number(process.env.FAILED_LOGIN_LIMIT || 5);
    const blockMs = Number(process.env.TEMP_BLOCK_SECONDS || 180) * 1000;

    if (!this.failedByIp.has(ip)) this.failedByIp.set(ip, []);
    const arr = this.failedByIp.get(ip);

    const now = Date.now();
    arr.push(now);
    while (arr.length && arr[0] <= now - windowMs) arr.shift();

    if (arr.length >= limit) {
      this.blockedIp.set(ip, { until: now + blockMs });
      this.failedByIp.delete(ip);
      return { blocked: true, until: new Date(now + blockMs) };
    }

    return { blocked: false, remaining: Math.max(0, limit - arr.length) };
  }

  clearFailures(ip) {
    this.failedByIp.delete(ip);
  }
}

class ChannelBlocker {
  constructor() {
    this.blocked = new Map();
  }

  block(key, durationMs, reason = 'unauthenticated_channel_access') {
    if (!key) return;
    this.blocked.set(key, {
      until: Date.now() + durationMs,
      reason
    });
  }

  isBlocked(key) {
    if (!key) return false;
    const row = this.blocked.get(key);
    if (!row) return false;
    if (row.until <= Date.now()) {
      this.blocked.delete(key);
      return false;
    }
    return true;
  }

  getBlockInfo(key) {
    if (!this.isBlocked(key)) return null;
    return this.blocked.get(key) || null;
  }
}

const messageCounter = new SlidingWindowCounter();
const fileCounter = new SlidingWindowCounter();
const disconnectCounter = new SlidingWindowCounter();
const wsEventCounter = new SlidingWindowCounter();
const authFailureTracker = new AuthFailureTracker();
const wsChannelBlocker = new ChannelBlocker();

module.exports = {
  messageCounter,
  fileCounter,
  disconnectCounter,
  wsEventCounter,
  authFailureTracker,
  wsChannelBlocker
};
