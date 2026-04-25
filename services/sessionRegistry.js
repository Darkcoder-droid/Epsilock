const sockets = new Map();
const userIndex = new Map();
const roomIndex = new Map();
const adminIndex = new Set();
const attackerIndex = new Set();

function addToIndex(map, key, socketId) {
  if (!key) return;
  if (!map.has(key)) map.set(key, new Set());
  map.get(key).add(socketId);
}

function removeFromIndex(map, key, socketId) {
  if (!key || !map.has(key)) return;
  const set = map.get(key);
  set.delete(socketId);
  if (set.size === 0) map.delete(key);
}

function registerSocket({ socketId, userId = null, username = null, nodeId = null, role = 'user', roomId = null, ws = null }) {
  sockets.set(socketId, { socketId, userId, username, nodeId, role, roomId, ws });
  if (userId) addToIndex(userIndex, String(userId), socketId);
  if (roomId) addToIndex(roomIndex, String(roomId), socketId);
  if (role === 'admin') adminIndex.add(socketId);
  if (role === 'attacker') attackerIndex.add(socketId);
}

function unregisterSocket(socketId) {
  const ref = sockets.get(socketId);
  if (!ref) return;
  sockets.delete(socketId);
  if (ref.userId) removeFromIndex(userIndex, String(ref.userId), socketId);
  if (ref.roomId) removeFromIndex(roomIndex, String(ref.roomId), socketId);
  adminIndex.delete(socketId);
  attackerIndex.delete(socketId);
}

function updateSocketRoom(socketId, roomId) {
  const ref = sockets.get(socketId);
  if (!ref) return;
  if (ref.roomId) removeFromIndex(roomIndex, String(ref.roomId), socketId);
  ref.roomId = roomId || null;
  sockets.set(socketId, ref);
  if (ref.roomId) addToIndex(roomIndex, String(ref.roomId), socketId);
}

function resolveSet(indexSet) {
  const list = [];
  for (const socketId of indexSet || []) {
    const ref = sockets.get(socketId);
    if (ref) list.push(ref);
  }
  return list;
}

function getUserSockets(userId) {
  return resolveSet(userIndex.get(String(userId)) || new Set());
}

function getRoomSockets(roomId) {
  return resolveSet(roomIndex.get(String(roomId)) || new Set());
}

function getAdminSockets() {
  return resolveSet(adminIndex);
}

function getAttackerSockets() {
  return resolveSet(attackerIndex);
}

function disconnectSocket(socketId, reason = 'Disconnected') {
  const ref = sockets.get(socketId);
  if (!ref || !ref.ws) return false;
  try {
    ref.ws.send(JSON.stringify({ type: 'FORCE_LOGOUT', reason }));
    ref.ws.send(JSON.stringify({ type: 'SESSION_REVOKED', reason }));
  } catch (_e) {}
  try {
    ref.ws.close(4403, reason);
  } catch (_e) {}
  return true;
}

function disconnectUserEverywhere(userId, reason = 'Security enforcement') {
  const refs = getUserSockets(userId);
  refs.forEach((ref) => disconnectSocket(ref.socketId, reason));
  return refs.length;
}

function safeSend(ref, payload) {
  if (!ref || !ref.ws || ref.ws.readyState !== 1) return;
  try {
    ref.ws.send(JSON.stringify(payload));
  } catch (_e) {}
}

function broadcastToAdmins(payload) {
  getAdminSockets().forEach((ref) => safeSend(ref, payload));
}

function broadcastToRoom(roomId, payload) {
  getRoomSockets(roomId).forEach((ref) => safeSend(ref, payload));
}

module.exports = {
  registerSocket,
  unregisterSocket,
  updateSocketRoom,
  getUserSockets,
  getRoomSockets,
  getAdminSockets,
  getAttackerSockets,
  disconnectSocket,
  disconnectUserEverywhere,
  broadcastToAdmins,
  broadcastToRoom
};
