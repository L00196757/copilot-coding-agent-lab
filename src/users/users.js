'use strict';

const bcrypt = require('bcryptjs');

// In-memory user store. Replace with a real database in production.
const SALT_ROUNDS = 10;

const users = [
  {
    id: 1,
    username: 'admin',
    // bcrypt hash of 'password123'
    passwordHash: bcrypt.hashSync('password123', SALT_ROUNDS),
    role: 'admin',
  },
  {
    id: 2,
    username: 'user',
    // bcrypt hash of 'secret456'
    passwordHash: bcrypt.hashSync('secret456', SALT_ROUNDS),
    role: 'user',
  },
];

/**
 * Find a user by username.
 * @param {string} username
 * @returns {object|undefined}
 */
function findByUsername(username) {
  return users.find((u) => u.username === username);
}

module.exports = { findByUsername };
