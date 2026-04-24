const { Schema, model } = require('mongoose');

const nodeRecordSchema = new Schema(
  {
    nodeId: {
      type: String,
      required: true,
      unique: true
    },
    nodeType: {
      type: String,
      enum: ['main', 'sender', 'receiver'],
      required: true
    },
    ownerUserId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      default: null
    },
    status: {
      type: String,
      enum: ['online', 'offline'],
      default: 'offline'
    },
    wsEndpoint: {
      type: String,
      required: true
    }
  },
  {
    timestamps: {
      createdAt: true,
      updatedAt: true
    }
  }
);

module.exports = model('NodeRecord', nodeRecordSchema);
