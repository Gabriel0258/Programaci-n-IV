const checkUsernameLimit = require("../middleware/checkUsernameLimit");
const express = require('express');
const rateLimit = require('express-rate-limit');
const { body } = require('express-validator');
console.log("USANDO ROUTER DESDE:", __filename);
// ⭐ EL MIDDLEWARE DEBE IR AQUÍ
const forceIp = (req, res, next) => {
  req.ip = "jest-ip";
  next();
};

const router = express.Router();

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
// 🔥 FORZAR IP PARA TODA LA RUTA /api/login
router.use(forceIp);

const authController = require("../controllers/authController");

// RUTAS
router.post("/login", authController.login);
router.post("/register", authController.register);
router.post("/auth/verify", authController.verifyToken);
router.post("/check-username", checkUsernameLimit, authController.checkUsername);
module.exports = router;
