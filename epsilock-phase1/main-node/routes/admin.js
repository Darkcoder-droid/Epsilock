const express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { requireAuth, requireRole } = require('../../shared/auth');
const User = require('../../shared/models/User');
const NodeRecord = require('../../shared/models/NodeRecord');
const SessionLog = require('../../shared/models/SessionLog');

function buildAdminRouter(bridgeState) {
  const router = express.Router();

  router.use(requireAuth, requireRole('admin'));

  router.get('/dashboard', async (_req, res) => {
    const [users, nodes, sessions] = await Promise.all([
      User.find().sort({ createdAt: -1 }).lean(),
      NodeRecord.find().sort({ createdAt: -1 }).lean(),
      SessionLog.find().sort({ startedAt: -1 }).limit(50).lean()
    ]);

    const onlineUsers = new Set([...bridgeState.userNodeMap.keys()]);

    res.render('admin_dashboard', {
      users,
      nodes,
      sessions,
      onlineUsers,
      error: null,
      success: null
    });
  });

  router.get('/create-user', (_req, res) => {
    res.render('create_user', { error: null, success: null });
  });

  router.post('/create-user', async (req, res) => {
    const { username, password, assignedNodeType } = req.body;

    if (!['sender', 'receiver'].includes(assignedNodeType)) {
      return res.status(400).render('create_user', { error: 'Invalid node type', success: null });
    }

    const existing = await User.findOne({ username });
    if (existing) {
      return res.status(409).render('create_user', { error: 'Username already exists', success: null });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const generatedNodeId = `${assignedNodeType.toUpperCase()}-USR-${uuidv4().slice(0, 8)}`;

    const user = await User.create({
      username,
      passwordHash,
      role: 'user',
      assignedNodeType,
      assignedNodeId: generatedNodeId
    });

    await NodeRecord.create({
      nodeId: generatedNodeId,
      nodeType: assignedNodeType,
      ownerUserId: user._id,
      status: 'offline',
      wsEndpoint: `${process.env.MAIN_NODE_URL || 'https://localhost:4000'}/ws/node`
    });

    return res.render('create_user', {
      error: null,
      success: `User created. Node identity: ${generatedNodeId}`
    });
  });

  router.post('/pair-room', async (req, res) => {
    const { senderUserId, receiverUserId } = req.body;

    const [sender, receiver] = await Promise.all([
      User.findById(senderUserId),
      User.findById(receiverUserId)
    ]);

    if (!sender || !receiver) {
      return res.status(404).send('Sender/receiver not found');
    }

    if (sender.assignedNodeType !== 'sender' || receiver.assignedNodeType !== 'receiver') {
      return res.status(400).send('Users must be assigned sender and receiver roles correctly');
    }

    const roomId = `ROOM-${uuidv4().slice(0, 10)}`;
    const now = new Date();

    await SessionLog.create({
      roomId,
      senderUserId: sender._id,
      receiverUserId: receiver._id,
      senderNodeId: sender.assignedNodeId,
      receiverNodeId: receiver.assignedNodeId,
      status: 'disconnected',
      startedAt: now,
      lastActivityAt: now,
      endedAt: now
    });

    return res.redirect('/admin/dashboard');
  });

  router.get('/sessions', async (_req, res) => {
    const sessions = await SessionLog.find().sort({ startedAt: -1 }).lean();
    return res.render('sessions', { sessions });
  });

  return router;
}

module.exports = buildAdminRouter;
