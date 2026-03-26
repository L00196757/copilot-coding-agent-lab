'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const { jwtSecret, jwtExpiresIn } = require('../config/config');
const { findByUsername } = require('../users/users');

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many login attempts, please try again later' },
});

/**
 * POST /api/auth/login
 * Body: { username, password }
 * Returns: { token }
 */
router.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  const user = findByUsername(username);
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const passwordMatch = await bcrypt.compare(password, user.passwordHash);
  if (!passwordMatch) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const payload = { id: user.id, username: user.username, role: user.role };
  const token = jwt.sign(payload, jwtSecret, { expiresIn: jwtExpiresIn });

  return res.status(200).json({ token });
});

module.exports = router;
