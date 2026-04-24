const { Schema, model } = require('mongoose');

const sessionLogSchema = new Schema(
  {
    roomId: {
      type: String,
      required: true,
      unique: true
    },
    senderUserId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    receiverUserId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    senderNodeId: {
      type: String,
      required: true
    },
    receiverNodeId: {
      type: String,
      required: true
    },
    status: {
      type: String,
      enum: ['active', 'disconnected'],
      default: 'disconnected'
    },
    startedAt: {
      type: Date,
      required: true
    },
    lastActivityAt: {
      type: Date,
      required: true
    },
    endedAt: {
      type: Date,
      default: null
    }
  },
  {
    timestamps: false
  }
);

module.exports = model('SessionLog', sessionLogSchema);
