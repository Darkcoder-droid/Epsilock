const { Schema, model } = require('mongoose');

const incidentSchema = new Schema(
  {
    incidentId: { type: String, required: true, unique: true },
    type: { type: String, required: true, index: true },
    severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], required: true, index: true },
    reason: { type: String, required: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User', default: null, index: true },
    nodeId: { type: String, default: null, index: true },
    sourceIp: { type: String, default: null },
    actionTaken: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, index: true }
  },
  { timestamps: false }
);

module.exports = model('Incident', incidentSchema);
