const express = require('express');
const bcrypt = require('bcryptjs');
const path = require('path');
const { connectDB } = require('../../shared/db');
const User = require('../../shared/models/User');
const { signAccessToken, setAuthCookie, clearAuthCookie } = require('../../shared/auth');

require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env') });

const router = express.Router();

router.get('/login', (_req, res) => {
  res.render('login', { error: null });
});

router.post('/login', async (req, res) => {
  await connectDB();
  const { username, password } = req.body;

  const user = await User.findOne({ username, role: 'admin' });
  if (!user) {
    return res.status(401).render('login', { error: 'Invalid credentials' });
  }

  const isValid = await bcrypt.compare(password, user.passwordHash);
  if (!isValid) {
    return res.status(401).render('login', { error: 'Invalid credentials' });
  }

  const token = signAccessToken(user);
  setAuthCookie(res, token);
  return res.redirect('/admin/dashboard');
});

router.post('/logout', (_req, res) => {
  clearAuthCookie(res);
  return res.redirect('/auth/login');
});

module.exports = router;
