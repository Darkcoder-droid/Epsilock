const { Schema, model } = require('mongoose');

const roomSchema = new Schema(
  {
    roomId: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    participantUserIds: [{ type: Schema.Types.ObjectId, ref: 'User' }],
    status: { type: String, enum: ['active', 'closed'], default: 'active' },
    frozen: { type: Boolean, default: false },
    frozenReason: { type: String, default: null },
    frozenAt: { type: Date, default: null },
    frozenBy: { type: String, enum: ['system', 'admin', null], default: null }
  },
  { timestamps: true }
);

module.exports = model('Room', roomSchema);
