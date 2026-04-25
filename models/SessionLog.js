const { Schema, model } = require('mongoose');

const sessionSchema = new Schema(
  {
    sessionId: { type: String, required: true, unique: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    username: { type: String, default: null },
    nodeId: { type: String, default: null, index: true },
    socketId: { type: String, required: true, index: true },
    sourceIp: { type: String, default: null },
    userAgent: { type: String, default: null },
    origin: { type: String, default: null },
    status: { type: String, enum: ['active', 'disconnected', 'revoked'], default: 'active', index: true },
    connectedAt: { type: Date, required: true },
    disconnectedAt: { type: Date, default: null },
    revokedAt: { type: Date, default: null },
    disconnectReason: { type: String, default: null },
    roomId: { type: String, default: null, index: true },
    lastActivityAt: { type: Date, default: Date.now }
  },
  { timestamps: false }
);

module.exports = model('SessionLog', sessionSchema);
