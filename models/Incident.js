const { Schema, model } = require('mongoose');

const incidentSchema = new Schema(
  {
    incidentId: { type: String, required: true, unique: true },
    type: { type: String, required: true, index: true },
    severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], required: true, index: true },
    reason: { type: String, required: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User', default: null, index: true },
    username: { type: String, default: null },
    roomId: { type: String, default: null, index: true },
    nodeId: { type: String, default: null, index: true },
    socketId: { type: String, default: null, index: true },
    sourceIp: { type: String, default: null },
    sourceGeo: { type: String, default: null },
    userAgent: { type: String, default: null },
    origin: { type: String, default: null },
    actionTaken: { type: String, required: true },
    status: { type: String, enum: ['open', 'resolved'], default: 'open', index: true },
    createdAt: { type: Date, default: Date.now, index: true }
    ,
    resolvedAt: { type: Date, default: null },
    metadata: { type: Schema.Types.Mixed, default: {} }
  },
  { timestamps: false }
);

module.exports = model('Incident', incidentSchema);
