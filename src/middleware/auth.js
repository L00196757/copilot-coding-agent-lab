'use strict';

const jwt = require('jsonwebtoken');
const { jwtSecret } = require('../config/config');

/**
 * Express middleware that validates a Bearer JWT in the Authorization header.
 *
 * On success the decoded payload is attached to `req.user` and the next
 * handler is called. On failure a 401 response is returned.
 */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.user = decoded;
    return next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }
    return res.status(401).json({ message: 'Invalid token' });
  }
}

module.exports = { authenticateToken };
