const { Schema, model } = require('mongoose');

const nodeSessionSchema = new Schema(
  {
    nodeId: { type: String, required: true, index: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    socketId: { type: String, required: true, index: true },
    status: { type: String, enum: ['online', 'offline'], default: 'online' },
    sourceIp: { type: String, default: null },
    userAgent: { type: String, default: null },
    connectedAt: { type: Date, default: Date.now },
    lastSeenAt: { type: Date, default: Date.now },
    disconnectedAt: { type: Date, default: null }
  },
  { timestamps: false }
);

module.exports = model('NodeSession', nodeSessionSchema);
