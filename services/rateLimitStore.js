const windows = new Map();

function prune(key, windowMs) {
  const now = Date.now();
  const arr = windows.get(key) || [];
  const filtered = arr.filter((ts) => ts > now - windowMs);
  windows.set(key, filtered);
  return filtered;
}

function hit(key, windowMs) {
  const arr = prune(key, windowMs);
  arr.push(Date.now());
  windows.set(key, arr);
  return arr.length;
}

function count(key, windowMs) {
  return prune(key, windowMs).length;
}

function tooMany(key, windowMs, max) {
  const current = hit(key, windowMs);
  return {
    triggered: current > max,
    count: current
  };
}

function reset(key) {
  windows.delete(key);
}

module.exports = {
  hit,
  count,
  tooMany,
  reset
};
