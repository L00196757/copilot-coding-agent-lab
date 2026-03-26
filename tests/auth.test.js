'use strict';

const request = require('supertest');
const app = require('../src/app');

describe('POST /api/auth/login', () => {
  it('should return 200 and a JWT token for valid credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'password123' });

    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('token');
    expect(typeof res.body.token).toBe('string');
  });

  it('should return 401 for a wrong password', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'wrongpassword' });

    expect(res.statusCode).toBe(401);
    expect(res.body).toHaveProperty('message', 'Invalid credentials');
  });

  it('should return 401 for an unknown username', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'nobody', password: 'password123' });

    expect(res.statusCode).toBe(401);
    expect(res.body).toHaveProperty('message', 'Invalid credentials');
  });

  it('should return 400 when username is missing', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ password: 'password123' });

    expect(res.statusCode).toBe(400);
    expect(res.body).toHaveProperty('message', 'Username and password are required');
  });

  it('should return 400 when password is missing', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin' });

    expect(res.statusCode).toBe(400);
    expect(res.body).toHaveProperty('message', 'Username and password are required');
  });

  it('should return 400 when both fields are missing', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({});

    expect(res.statusCode).toBe(400);
    expect(res.body).toHaveProperty('message', 'Username and password are required');
  });

  it('should return a JWT with the correct payload fields', async () => {
    const jwt = require('jsonwebtoken');
    const { jwtSecret } = require('../src/config/config');

    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'password123' });

    const decoded = jwt.verify(res.body.token, jwtSecret);
    expect(decoded).toHaveProperty('id', 1);
    expect(decoded).toHaveProperty('username', 'admin');
    expect(decoded).toHaveProperty('role', 'admin');
  });
});
