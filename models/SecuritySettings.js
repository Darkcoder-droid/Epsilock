const { Schema, model } = require('mongoose');

const securitySettingsSchema = new Schema(
  {
    key: { type: String, unique: true, default: 'global' },
    attackerDemoEnabled: { type: Boolean, default: true },
    coverTrafficEnabled: { type: Boolean, default: false },
    coverTrafficIntervalMs: { type: Number, default: 1500 },
    coverTrafficJitterMs: { type: Number, default: 1000 },
    coverTrafficRatio: { type: Number, default: 3 },
    updatedBy: { type: Schema.Types.ObjectId, ref: 'User', default: null },
    updatedAt: { type: Date, default: Date.now }
  },
  { timestamps: false }
);

module.exports = model('SecuritySettings', securitySettingsSchema);
