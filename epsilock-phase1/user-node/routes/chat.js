const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../../models/User');
const Room = require('../../models/Room');
const { UserNodeClient } = require('../ws/client');
const { WS_EVENTS } = require('../../shared/constants');

const COOKIE = 'user_node_access';

function verifyCookie(req) {
  const token = req.cookies?.[COOKIE];
  if (!token) return null;
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (_e) {
    return null;
  }
}

function issueUserNodeCookie(res, claims, secure) {
  const token = jwt.sign(claims, process.env.JWT_SECRET, { expiresIn: process.env.ACCESS_TOKEN_TTL || '10m' });
  res.cookie(COOKIE, token, { httpOnly: true, secure, sameSite: 'strict', maxAge: 10 * 60 * 1000 });
}

function buildChatRouter() {
  const router = express.Router();

  function requireUser(req, res, next) {
    const claims = verifyCookie(req);
    if (!claims) return res.redirect('/login');
    req.userClaims = claims;
    next();
  }

  function getNodeRuntime(req) {
    const map = req.app.locals.nodeRuntime;
    if (!map) {
      req.app.locals.nodeRuntime = new Map();
      return req.app.locals.nodeRuntime;
    }
    return map;
  }

  async function ensureNodeClient(req, userDoc) {
    const runtime = getNodeRuntime(req);
    const key = String(userDoc._id);
    if (runtime.has(key)) return runtime.get(key);

    const nodeId = process.env.NODE_ID || `NODE-${process.env.USER_NODE_PORT || 3001}`;
    const mainToken = jwt.sign(
      {
        sub: String(userDoc._id),
        username: userDoc.username,
        role: 'user',
        ver: Number(userDoc.tokenVersion || 0)
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.ACCESS_TOKEN_TTL || '10m' }
    );

    const node = new UserNodeClient({
      mainWsUrl: process.env.MAIN_NODE_WSS_URL || 'wss://localhost:8443/ws',
      nodeId,
      user: { userId: String(userDoc._id), username: userDoc.username },
      token: mainToken
    });

    node.messages = [];
    node.sseClients = new Set();

    node.on('chatMessage', (msg) => {
      node.messages.push(msg);
      if (node.messages.length > 200) node.messages.shift();
      const payload = `data: ${JSON.stringify({ type: WS_EVENTS.CHAT_MESSAGE_RECEIVED, payload: msg })}\n\n`;
      for (const client of node.sseClients) client.write(payload);
    });

    node.on('status', (status) => {
      const payload = `data: ${JSON.stringify({ type: 'status', payload: status })}\n\n`;
      for (const client of node.sseClients) client.write(payload);
    });

    node.on('revoked', (reason) => {
      const payload = `data: ${JSON.stringify({ type: 'revoked', payload: { reason } })}\n\n`;
      for (const client of node.sseClients) client.write(payload);
    });

    node.on('joinDenied', (payload) => {
      const msg = `data: ${JSON.stringify({ type: 'joinDenied', payload })}\n\n`;
      for (const client of node.sseClients) client.write(msg);
    });

    node.on('sendDenied', (payload) => {
      const msg = `data: ${JSON.stringify({ type: 'sendDenied', payload })}\n\n`;
      for (const client of node.sseClients) client.write(msg);
    });

    node.connect();
    runtime.set(key, node);
    return node;
  }

  router.get('/login', (_req, res) => {
    res.render('layout', { title: 'User Node Login', bodyView: 'login', data: { error: null } });
  });

  router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username, role: 'user' });
    if (!user) {
      return res.status(401).render('layout', { title: 'User Node Login', bodyView: 'login', data: { error: 'Invalid credentials' } });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok || user.blocked) {
      return res.status(401).render('layout', { title: 'User Node Login', bodyView: 'login', data: { error: 'Invalid credentials or blocked user' } });
    }

    issueUserNodeCookie(
      res,
      {
        sub: String(user._id),
        username: user.username,
        role: 'user',
        ver: Number(user.tokenVersion || 0)
      },
      req.secure || req.protocol === 'https'
    );

    await ensureNodeClient(req, user);
    return res.redirect('/chat');
  });

  router.post('/logout', requireUser, (req, res) => {
    res.clearCookie(COOKIE, { httpOnly: true, secure: req.secure || req.protocol === 'https', sameSite: 'strict' });
    return res.redirect('/login');
  });

  router.get('/', (_req, res) => res.redirect('/chat'));

  router.get('/chat', requireUser, async (req, res) => {
    const userId = req.userClaims.sub;
    const [user, rooms] = await Promise.all([
      User.findById(userId).lean(),
      Room.find({ participantUserIds: userId, status: 'active' }).lean()
    ]);
    if (!user) return res.redirect('/login');

    const node = await ensureNodeClient(req, user);

    res.render('layout', {
      title: `User Node ${process.env.NODE_ID || ''}`,
      bodyView: 'chat',
      data: {
        user,
        nodeId: process.env.NODE_ID || `NODE-${process.env.USER_NODE_PORT || 3001}`,
        rooms,
        status: node.status()
      }
    });
  });

  router.post('/api/join-room', requireUser, async (req, res) => {
    const { roomId } = req.body;
    const room = await Room.findOne({ roomId, participantUserIds: req.userClaims.sub, status: 'active' }).lean();
    if (!room) return res.status(403).json({ ok: false, error: 'Room not assigned' });

    const user = await User.findById(req.userClaims.sub);
    const node = await ensureNodeClient(req, user);
    const result = await node.joinRoom(roomId);
    if (!result.ok) {
      return res.status(409).json({ ok: false, error: result.error || 'Room join denied', status: node.status() });
    }
    return res.json({ ok: true, status: node.status() });
  });

  router.post('/api/send', requireUser, async (req, res) => {
    const { roomId, toUserId, text } = req.body;
    if (!text || String(text).trim().length === 0) {
      return res.status(400).json({ ok: false, error: 'Message required' });
    }

    const room = await Room.findOne({ roomId, participantUserIds: req.userClaims.sub, status: 'active' }).lean();
    if (!room) return res.status(403).json({ ok: false, error: 'Invalid room' });

    const user = await User.findById(req.userClaims.sub);
    const node = await ensureNodeClient(req, user);
    if (!node.status().connected || !node.status().authenticated || !node.status().roomJoined || node.status().joinedRoomId !== roomId) {
      return res.status(409).json({ ok: false, error: 'Join room and connect first' });
    }

    node.sendRealMessage({ roomId, toUserId: toUserId || null, text: String(text) });
    return res.json({ ok: true });
  });

  router.get('/events', requireUser, async (req, res) => {
    const user = await User.findById(req.userClaims.sub);
    if (!user) return res.status(401).end();
    const node = await ensureNodeClient(req, user);

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.write(`data: ${JSON.stringify({ type: 'status', payload: node.status() })}\n\n`);

    node.sseClients.add(res);
    req.on('close', () => {
      node.sseClients.delete(res);
    });
  });

  return router;
}

module.exports = { buildChatRouter };
