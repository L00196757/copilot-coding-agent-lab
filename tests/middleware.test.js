'use strict';

const jwt = require('jsonwebtoken');
const httpMocks = require('node-mocks-http');
const { authenticateToken } = require('../src/middleware/auth');
const { jwtSecret } = require('../src/config/config');

// Helper to create a signed token with default settings
function makeToken(payload = { id: 1, username: 'test', role: 'user' }, options = {}) {
  return jwt.sign(payload, jwtSecret, { expiresIn: '1h', ...options });
}

describe('authenticateToken middleware', () => {
  let next;

  beforeEach(() => {
    next = jest.fn();
  });

  it('should call next() and set req.user for a valid Bearer token', () => {
    const token = makeToken();
    const req = httpMocks.createRequest({
      headers: { authorization: `Bearer ${token}` },
    });
    const res = httpMocks.createResponse();

    authenticateToken(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(req.user).toMatchObject({ id: 1, username: 'test', role: 'user' });
  });

  it('should return 401 when Authorization header is missing', () => {
    const req = httpMocks.createRequest();
    const res = httpMocks.createResponse();

    authenticateToken(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res._getJSONData()).toEqual({ message: 'Access token required' });
  });

  it('should return 401 when Authorization header has no Bearer prefix', () => {
    const token = makeToken();
    const req = httpMocks.createRequest({
      headers: { authorization: token },
    });
    const res = httpMocks.createResponse();

    authenticateToken(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res._getJSONData()).toEqual({ message: 'Access token required' });
  });

  it('should return 401 for a tampered / invalid token', () => {
    const req = httpMocks.createRequest({
      headers: { authorization: 'Bearer this.is.not.valid' },
    });
    const res = httpMocks.createResponse();

    authenticateToken(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res._getJSONData()).toEqual({ message: 'Invalid token' });
  });

  it('should return 401 with "Token expired" for an expired token', () => {
    // Create a token that expired 10 seconds ago
    const token = makeToken({}, { expiresIn: '-10s' });
    const req = httpMocks.createRequest({
      headers: { authorization: `Bearer ${token}` },
    });
    const res = httpMocks.createResponse();

    authenticateToken(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res._getJSONData()).toEqual({ message: 'Token expired' });
  });

  it('should return 401 for a token signed with a different secret', () => {
    const badToken = jwt.sign({ id: 99 }, 'wrong-secret', { expiresIn: '1h' });
    const req = httpMocks.createRequest({
      headers: { authorization: `Bearer ${badToken}` },
    });
    const res = httpMocks.createResponse();

    authenticateToken(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res._getJSONData()).toEqual({ message: 'Invalid token' });
  });
});
