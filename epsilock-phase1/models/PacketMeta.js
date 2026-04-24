const { Schema, model } = require('mongoose');

const packetMetaSchema = new Schema(
  {
    packetId: { type: String, required: true, unique: true },
    type: { type: String, required: true },
    roomId: { type: String, default: null, index: true },
    fromUserId: { type: Schema.Types.ObjectId, ref: 'User', default: null, index: true },
    toUserId: { type: Schema.Types.ObjectId, ref: 'User', default: null, index: true },
    nodeId: { type: String, required: true, index: true },
    sizeBytes: { type: Number, required: true },
    isCover: { type: Boolean, default: false, index: true },
    createdAt: { type: Date, default: Date.now, index: true },
    routeHint: { type: String, default: null },
    attackerDemoVisible: { type: Boolean, default: true }
  },
  { timestamps: false }
);

module.exports = model('PacketMeta', packetMetaSchema);
