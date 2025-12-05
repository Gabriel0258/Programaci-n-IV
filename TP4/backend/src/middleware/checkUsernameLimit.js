const rateLimit = require("express-rate-limit");

const checkUsernameLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: "Too many attempts" },

  // ❗ NO LIMITAR peticiones inválidas
  skip: (req) => {
    const username = req.body?.username;
    if (!username) return true;

    // si el username NO pasa la validación → NO aplicar rate limit
    return !/^[a-zA-Z0-9_]{3,20}$/.test(username);
  },
});

module.exports = checkUsernameLimit;
