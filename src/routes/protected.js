'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

const protectedLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many requests, please try again later' },
});

// Apply rate limiting and JWT authentication middleware to all routes.
router.use(protectedLimiter);
router.use(authenticateToken);

/**
 * GET /api/protected/profile
 * Returns the authenticated user's profile derived from the JWT payload.
 */
router.get('/profile', (req, res) => {
  const { id, username, role } = req.user;
  res.status(200).json({
    message: 'Access granted',
    user: { id, username, role },
  });
});

/**
 * GET /api/protected/admin
 * Example of a role-restricted endpoint.
 */
router.get('/admin', (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Forbidden: admin role required' });
  }
  const { id, username, role } = req.user;
  return res.status(200).json({ message: 'Welcome, admin!', user: { id, username, role } });
});

module.exports = router;
