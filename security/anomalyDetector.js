const { messageCounter, fileCounter, disconnectCounter, wsEventCounter } = require('./rateLimiter');

function detectMessageRateAnomaly({ userId }) {
  const result = messageCounter.hit(
    `msg:${userId}`,
    Number(process.env.MAX_MESSAGES_PER_10_SECONDS || 20),
    10000
  );

  if (result.allowed) return null;
  return {
    type: 'message_rate_anomaly',
    severity: 'high',
    reason: `Message flood detected (${result.count}/${result.limit} in ${result.windowMs / 1000}s)`
  };
}

function detectFileAbuse({ userId }) {
  const result = fileCounter.hit(
    `file:${userId}`,
    Number(process.env.MAX_FILE_UPLOADS_PER_MINUTE || 10),
    60000
  );

  if (result.allowed) return null;
  return {
    type: 'file_abuse_detection',
    severity: 'high',
    reason: `Excessive file sharing detected (${result.count}/${result.limit} in 60s)`
  };
}

function detectDisconnectAnomaly({ userId }) {
  const windowMs = Number(process.env.DISCONNECT_ANOMALY_WINDOW_SECONDS || 60) * 1000;
  const result = disconnectCounter.hit(
    `disc:${userId}`,
    Number(process.env.DISCONNECT_ANOMALY_LIMIT || 6),
    windowMs
  );

  if (result.allowed) return null;
  return {
    type: 'abnormal_disconnect_pattern',
    severity: 'medium',
    reason: `Rapid reconnect/disconnect behavior (${result.count}/${result.limit} in ${windowMs / 1000}s)`
  };
}

function detectRealtimeWsEventAnomaly({ userId }) {
  const windowMs = 5000;
  const result = wsEventCounter.hit(
    `ws-event:${userId}`,
    Number(process.env.MAX_WS_EVENTS_PER_5_SECONDS || 40),
    windowMs
  );

  if (result.allowed) return null;
  return {
    type: 'ws_event_rate_anomaly',
    severity: 'high',
    reason: `Excessive websocket event rate (${result.count}/${result.limit} in ${windowMs / 1000}s)`
  };
}

module.exports = {
  detectMessageRateAnomaly,
  detectFileAbuse,
  detectDisconnectAnomaly,
  detectRealtimeWsEventAnomaly
};
