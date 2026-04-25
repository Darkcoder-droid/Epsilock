const PRIVATE_IPV4_PATTERNS = [
  /^10\./,
  /^127\./,
  /^169\.254\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[0-1])\./
];

function normalizeIp(rawIp) {
  if (!rawIp) return null;
  let ip = String(rawIp).trim();
  if (!ip) return null;

  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (ip === '::1') return '127.0.0.1';
  return ip;
}

function isPrivateOrLocalIp(ip) {
  if (!ip) return true;
  if (ip.includes(':')) {
    return ip === '::1' || ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80');
  }
  return PRIVATE_IPV4_PATTERNS.some((pattern) => pattern.test(ip));
}

async function fetchGeo(ip) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 2500);
  try {
    const response = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
      signal: controller.signal
    });
    if (!response.ok) return null;
    const body = await response.json();
    if (!body || body.success === false) return null;

    return {
      country: body.country || null,
      region: body.region || null,
      city: body.city || null,
      latitude: typeof body.latitude === 'number' ? body.latitude : null,
      longitude: typeof body.longitude === 'number' ? body.longitude : null,
      isp: body.connection?.isp || null,
      org: body.connection?.org || null
    };
  } catch (_err) {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

async function buildSourceGeo(rawIp) {
  const ip = normalizeIp(rawIp);
  if (!ip) return { normalizedIp: null, sourceGeo: null };

  if (isPrivateOrLocalIp(ip)) {
    return {
      normalizedIp: ip,
      sourceGeo: {
        country: 'Local/Private',
        region: null,
        city: null,
        latitude: null,
        longitude: null,
        isp: null,
        org: null
      }
    };
  }

  const sourceGeo = await fetchGeo(ip);
  return { normalizedIp: ip, sourceGeo };
}

module.exports = {
  buildSourceGeo,
  normalizeIp
};
