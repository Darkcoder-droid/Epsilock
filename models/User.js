const { Schema, model } = require('mongoose');

const userSchema = new Schema(
  {
    username: { type: String, required: true, unique: true, trim: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ['admin', 'user'], default: 'user' },
    tokenVersion: { type: Number, default: 0 },
    blocked: { type: Boolean, default: false },
    blockedUntil: { type: Date, default: null },
    blockReason: { type: String, default: null },
    requirePasswordReset: { type: Boolean, default: false },
    revokedJtis: [{ type: String }]
  },
  { timestamps: { createdAt: true, updatedAt: true } }
);

module.exports = model('User', userSchema);
