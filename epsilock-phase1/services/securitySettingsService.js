const SecuritySettings = require('../models/SecuritySettings');

let broadcaster = null;

function clampNumber(value, min, max, fallback) {
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(num)));
}

function parseBoolean(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value === 'boolean') return value;
  const norm = String(value).trim().toLowerCase();
  if (norm === 'true' || norm === '1' || norm === 'on' || norm === 'yes') return true;
  if (norm === 'false' || norm === '0' || norm === 'off' || norm === 'no') return false;
  return fallback;
}

function normalizePatch(patch = {}) {
  return {
    attackerDemoEnabled: parseBoolean(patch.attackerDemoEnabled, true),
    coverTrafficEnabled: parseBoolean(patch.coverTrafficEnabled, false),
    coverTrafficIntervalMs: clampNumber(patch.coverTrafficIntervalMs, 100, 60000, 1500),
    coverTrafficJitterMs: clampNumber(patch.coverTrafficJitterMs, 0, 60000, 1000),
    coverTrafficRatio: clampNumber(patch.coverTrafficRatio, 1, 20, 3)
  };
}

async function getSecuritySettings() {
  let doc = await SecuritySettings.findOne({ key: 'global' }).lean();
  if (!doc) {
    doc = await SecuritySettings.create({ key: 'global' });
    return doc.toObject();
  }
  if (doc.attackerDemoEnabled === undefined) {
    await SecuritySettings.updateOne(
      { key: 'global' },
      { $set: { attackerDemoEnabled: true, updatedAt: new Date() } }
    );
    doc.attackerDemoEnabled = true;
  }
  return doc;
}

async function updateSecuritySettings(adminUserId, patch) {
  const normalized = normalizePatch(patch);
  await SecuritySettings.updateOne(
    { key: 'global' },
    {
      $set: {
        ...normalized,
        updatedBy: adminUserId || null,
        updatedAt: new Date()
      }
    },
    { upsert: true }
  );
  return getSecuritySettings();
}

function setSecuritySettingsBroadcaster(fn) {
  broadcaster = typeof fn === 'function' ? fn : null;
}

async function broadcastSecuritySettings(settings) {
  if (broadcaster) {
    broadcaster(settings);
  }
}

module.exports = {
  getSecuritySettings,
  updateSecuritySettings,
  broadcastSecuritySettings,
  setSecuritySettingsBroadcaster
};
