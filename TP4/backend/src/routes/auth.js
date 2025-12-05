const express = require('express');
const rateLimit = require('express-rate-limit');
const { body } = require('express-validator');
const router = express.Router();
const authController = require('../controllers/authController');

// Rate limit para chequear el nombre de usuario
const userLimit = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: { error: "Too many attempts" }
});

// Valida que el nombre del usuario sea válido
const validarUserName = [
    body('username').trim().matches(/^[a-zA-Z0-9_]{3,20}$/).withMessage("Usuario inválido")
];
// Rutas de autenticación
router.post('/login', authController.login);
router.post('/register', authController.register);
router.post('/auth/verify', authController.verifyToken);
router.post('/check-username', authController.checkUsername);

// ruta para chequear el nombre del usuario
router.post('/check-username', userLimit, validarUserName, authController.checkUsername);
module.exports = router;
