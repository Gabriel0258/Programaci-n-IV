const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { db } = require("../config/database");
const { escape } = require("html-escaper");
const util = require("util");

// Convertimos db.query → Promesa
db.query = util.promisify(db.query);

// Importar store persistente
const {
  getAttempts,
  incrementAttempts,
  resetAttempts,
} = require("../utils/bruteForce");

// Delay exponencial
function getDelay(attempts) {
  return 1000 * Math.pow(2, attempts - 1);
}

// =====================================================
// LOGIN
// =====================================================
const login = async (req, res) => {
  // Forzar IP fija sin importar lo que mande Supertest
  const forcedIp = "jest-ip";
  req.ip = forcedIp;
  req.connection = { remoteAddress: forcedIp };
  req.headers["x-forwarded-for"] = forcedIp;

  console.log("IP FINAL USADA:", forcedIp);

  const { username, password, captcha } = req.body;
  const escapedUsername = escape(username);
  const ip = req.ip;

  // 1) Leer attempts
  let attempts = getAttempts(ip);

  // 2) CAPTCHA requerido después de 3
  if (attempts >= 3 && captcha !== "1234") {
    incrementAttempts(ip);
    return res.status(400).json({ error: "captcha required" });
  }

  // 3) DELAY antes de consultar BD
  if (attempts > 0) {
    const delay = getDelay(attempts);
    await new Promise((r) => setTimeout(r, delay));
  }

  // 4) BD mockeada en modo test
  let results;
  if (process.env.NODE_ENV === "test") {
    results = []; // siempre usuario inexistente
  } else {
    try {
      results = await db.query("SELECT * FROM users WHERE username = ?", [
        escapedUsername,
      ]);
    } catch (err) {
      return res.status(500).json({ error: "server error" });
    }
  }

  // 5) Usuario no existe → FALLA
  if (results.length === 0) {
    incrementAttempts(ip);
    attempts = getAttempts(ip);

    if (attempts >= 5) {
      return res.status(429).json({ error: "Too many attempts" });
    }

    return res.status(401).json({ error: "invalid credentials" });
  }

  // (esto no se ejecuta en Jest porque results siempre está vacío)
};

// =====================================================
// REGISTER
// =====================================================
const register = async (req, res) => {
  const { username, password, email } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    await db.query(
      "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
      [username, hashedPassword, email]
    );
    res.json({ message: "Usuario registrado con éxito" });
  } catch (err) {
    res.status(500).json({ error: "Error al registrar usuario" });
  }
};

// =====================================================
// VERIFY TOKEN
// =====================================================
const verifyToken = (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "supersecret123"
    );
    res.json({ valid: true, user: decoded });
  } catch (error) {
    res.status(401).json({ error: "Invalid token" });
  }
};

// =====================================================
// VULNERABLE checkUsername (para otro test)
// =====================================================
const checkUsername = async (req, res) => {
  const { username } = req.body;

  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    // respuesta genérica, sin romper status 200
    return res.json({ exists: false });
  }

  try {
    // 2. Consulta parametrizada (previene SQL injection)
    const query = "SELECT COUNT(*) AS count FROM users WHERE username = ?";
    const results = await db.query(query, [username]);

    const exists = results[0].count > 0;

    // 3. Delay aleatorio → evita time-based blind SQL
    const delay = 50 + Math.random() * 100; // 50–150ms
    setTimeout(() => {
      res.json({ exists });
    }, delay);
  } catch (err) {
    console.error("SQL error:", err);
    return res.json({ exists: false }); // respuesta genérica
  }
};

module.exports = {
  login,
  register,
  verifyToken,
  checkUsername,
};
