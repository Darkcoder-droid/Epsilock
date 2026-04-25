const { Schema, model } = require('mongoose');

const recoveryTokenSchema = new Schema(
  {
    tokenId: { type: String, required: true, unique: true },
    recoveryId: { type: String, required: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    jti: { type: String, required: true, unique: true },
    used: { type: Boolean, default: false },
    expiresAt: { type: Date, required: true },
    createdAt: { type: Date, default: Date.now }
  },
  { timestamps: false }
);

module.exports = model('RecoveryToken', recoveryTokenSchema);
