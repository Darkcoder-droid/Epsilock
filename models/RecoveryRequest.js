const { Schema, model } = require('mongoose');

const recoveryRequestSchema = new Schema(
  {
    recoveryId: { type: String, required: true, unique: true },
    incidentId: { type: String, required: true },
    oldRoomId: { type: String, required: true },
    newRoomId: { type: String, default: null },
    affectedUserIds: [{ type: Schema.Types.ObjectId, ref: 'User' }],
    status: {
      type: String,
      enum: ['pending', 'verified', 'completed', 'failed', 'expired'],
      default: 'pending'
    },
    challengeCodeHash: { type: String, required: true },
    expiresAt: { type: Date, required: true },
    createdAt: { type: Date, default: Date.now },
    completedAt: { type: Date, default: null }
  },
  { timestamps: false }
);

module.exports = model('RecoveryRequest', recoveryRequestSchema);
