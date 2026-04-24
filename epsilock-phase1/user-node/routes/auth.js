const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../../shared/models/User');
const { signAccessToken, setAuthCookie, clearAuthCookie } = require('../../shared/auth');

const router = express.Router();

router.get('/login', (_req, res) => {
  res.render('login', { error: null, nodeType: process.env.NODE_TYPE || 'sender' });
});

router.post('/login', async (req, res) => {
  const nodeType = process.env.NODE_TYPE || 'sender';
  const { username, password } = req.body;

  const user = await User.findOne({ username, role: 'user' });
  if (!user) {
    return res.status(401).render('login', { error: 'Invalid credentials', nodeType });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.status(401).render('login', { error: 'Invalid credentials', nodeType });
  }

  if (user.assignedNodeType !== nodeType) {
    return res.status(403).render('login', { error: `Access denied for ${nodeType} node`, nodeType });
  }

  const token = signAccessToken(user);
  setAuthCookie(res, token);
  return res.redirect('/dashboard');
});

router.post('/logout', (_req, res) => {
  clearAuthCookie(res);
  return res.redirect('/auth/login');
});

module.exports = router;
