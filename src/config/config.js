'use strict';

require('dotenv').config();

module.exports = {
  jwtSecret: process.env.JWT_SECRET || 'changeme-use-a-strong-secret-in-production',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1h',
  port: parseInt(process.env.PORT, 10) || 3000,
};
