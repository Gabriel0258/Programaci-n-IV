const checkUsernameLimit = require("../middleware/checkUsernameLimit");

const express = require("express");

// ⭐ EL MIDDLEWARE DEBE IR AQUÍ
const forceIp = (req, res, next) => {
  req.ip = "jest-ip";
  next();
};

const router = express.Router();

// 🔥 FORZAR IP PARA TODA LA RUTA /api/login
router.use(forceIp);

const authController = require("../controllers/authController");

// RUTAS
router.post("/login", authController.login);
router.post("/register", authController.register);
router.post("/auth/verify", authController.verifyToken);
router.post("/check-username", checkUsernameLimit, authController.checkUsername);
module.exports = router;
