class RoomManager {
  constructor() {
    this.roomToSockets = new Map();
    this.socketToRooms = new Map();
  }

  join(roomId, socket) {
    if (!this.roomToSockets.has(roomId)) this.roomToSockets.set(roomId, new Set());
    this.roomToSockets.get(roomId).add(socket);

    if (!this.socketToRooms.has(socket)) this.socketToRooms.set(socket, new Set());
    this.socketToRooms.get(socket).add(roomId);
  }

  leave(roomId, socket) {
    if (this.roomToSockets.has(roomId)) {
      this.roomToSockets.get(roomId).delete(socket);
      if (this.roomToSockets.get(roomId).size === 0) this.roomToSockets.delete(roomId);
    }

    if (this.socketToRooms.has(socket)) {
      this.socketToRooms.get(socket).delete(roomId);
      if (this.socketToRooms.get(socket).size === 0) this.socketToRooms.delete(socket);
    }
  }

  leaveAll(socket) {
    if (!this.socketToRooms.has(socket)) return [];
    const rooms = [...this.socketToRooms.get(socket)];
    for (const roomId of rooms) this.leave(roomId, socket);
    return rooms;
  }

  socketsInRoom(roomId) {
    return this.roomToSockets.get(roomId) || new Set();
  }

  roomUsers(roomId) {
    const users = [];
    for (const socket of this.socketsInRoom(roomId)) {
      if (socket.user) users.push({ userId: socket.user.userId, username: socket.user.username });
    }
    return users;
  }
}

module.exports = { RoomManager };
