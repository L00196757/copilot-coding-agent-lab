'use strict';

const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../src/app');
const { jwtSecret } = require('../src/config/config');

// Helper to create a signed token
function makeToken(payload = { id: 1, username: 'admin', role: 'admin' }, options = {}) {
  return jwt.sign(payload, jwtSecret, { expiresIn: '1h', ...options });
}

describe('Protected routes', () => {
  describe('GET /api/protected/profile', () => {
    it('should return 200 and user data with a valid token', async () => {
      const token = makeToken();
      const res = await request(app)
        .get('/api/protected/profile')
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toBe(200);
      expect(res.body).toHaveProperty('message', 'Access granted');
      expect(res.body.user).toMatchObject({ id: 1, username: 'admin', role: 'admin' });
    });

    it('should return 401 when no token is provided', async () => {
      const res = await request(app).get('/api/protected/profile');

      expect(res.statusCode).toBe(401);
      expect(res.body).toHaveProperty('message', 'Access token required');
    });

    it('should return 401 for an invalid token', async () => {
      const res = await request(app)
        .get('/api/protected/profile')
        .set('Authorization', 'Bearer invalidtoken');

      expect(res.statusCode).toBe(401);
      expect(res.body).toHaveProperty('message', 'Invalid token');
    });

    it('should return 401 for an expired token', async () => {
      const token = makeToken({}, { expiresIn: '-10s' });
      const res = await request(app)
        .get('/api/protected/profile')
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toBe(401);
      expect(res.body).toHaveProperty('message', 'Token expired');
    });
  });

  describe('GET /api/protected/admin', () => {
    it('should return 200 for a user with admin role', async () => {
      const token = makeToken({ id: 1, username: 'admin', role: 'admin' });
      const res = await request(app)
        .get('/api/protected/admin')
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toBe(200);
      expect(res.body).toHaveProperty('message', 'Welcome, admin!');
    });

    it('should return 403 for a user with non-admin role', async () => {
      const token = makeToken({ id: 2, username: 'user', role: 'user' });
      const res = await request(app)
        .get('/api/protected/admin')
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toBe(403);
      expect(res.body).toHaveProperty('message', 'Forbidden: admin role required');
    });

    it('should return 401 when no token is provided', async () => {
      const res = await request(app).get('/api/protected/admin');

      expect(res.statusCode).toBe(401);
      expect(res.body).toHaveProperty('message', 'Access token required');
    });
  });
});
