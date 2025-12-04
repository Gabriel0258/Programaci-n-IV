const express = require('express');
const router = express.Router();
const vulnerabilityController = require('../controllers/vulnerabilityController');
const { uploadMiddleware, uploadFile } = require('../controllers/uploadController');

// Command Injection
router.post('/ping', vulnerabilityController.ping);

// CSRF - obtener token
router.get('/csrf-token', vulnerabilityController.getCsrfToken);

// CSRF - transferencia protegida
router.post('/transfer', vulnerabilityController.transfer);

// Local File Inclusion
router.get('/file', vulnerabilityController.readFile);

// File Upload
router.post('/upload', uploadMiddleware, uploadFile);

module.exports = router;
