'use strict';

const express = require('express');

const authRoutes = require('./routes/auth');
const protectedRoutes = require('./routes/protected');

const app = express();

app.use(express.json());

// Health check
app.get('/health', (_req, res) => res.status(200).json({ status: 'ok' }));

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/protected', protectedRoutes);

// 404 handler
app.use((_req, res) => res.status(404).json({ message: 'Not found' }));

module.exports = app;
