function getAllowedOrigins() {
  const configured = (process.env.ALLOWED_ORIGINS || 'https://localhost:4000,http://localhost:4000')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean);

  return new Set(configured);
}

function isOriginAllowed(origin) {
  const allowed = getAllowedOrigins();
  if (allowed.has('*')) return true;
  if (!origin) return false;
  return allowed.has(origin);
}

module.exports = {
  isOriginAllowed
};
