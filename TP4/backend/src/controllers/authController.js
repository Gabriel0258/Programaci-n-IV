const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db } = require('../config/database');
const { validationResult } = require('express-validator');

// VULNERABLE: Sin rate limiting para prevenir brute force
const login = async (req, res) => {
  const { username, password } = req.body;
  
  const query = `SELECT * FROM users WHERE username = ?`;
  
  db.query(query, [username], async (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Error en el servidor' });
    }
    
    if (results.length === 0) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }
    
    const user = results[0];
    const isValidPassword = await bcrypt.compare(password, user.password);
    
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }
    
    const token = jwt.sign(
      { id: user.id, username: user.username }, 
      process.env.JWT_SECRET || 'supersecret123'
    );
    
    res.json({ token, username: user.username });
  });
};

const register = async (req, res) => {
  const { username, password, email } = req.body;
  
  const hashedPassword = await bcrypt.hash(password, 10);
  
  const query = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
  db.query(query, [username, hashedPassword, email], (err) => {
    if (err) {
      return res.status(500).json({ error: 'Error al registrar usuario' });
    }
    res.json({ message: 'Usuario registrado con éxito' });
  });
};

const verifyToken = (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'supersecret123');
    req.session.userId = decoded.id;
    res.json({ valid: true, user: decoded });
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Protección Blind SQL Injection
const checkUsername = (req, res) => {
  const errores = validationResult(req);
  if (!errores.isEmpty()) {
    return responseSeguro(res, false);
  }

  const { username } = req.body;

  //Mediante esta validación es posible detectar patrones sospechosos
  if (username.includes("'") || username.includes("--")) {
    console.warn('Posible intento de SQL injection:', {
      ip: req.ip,
      username: username,
      timestamp: new Date()
      });
    return responseSeguro(res, false);
  }
  
  //CORREGIDO VULNERABLE: SQL injection que permite inferir información
  //Mediante las consultas paramerizadas se evita inferir la información
  const query = `SELECT COUNT(*) as count FROM users WHERE username = ?`;
  
  db.query(query, [username], async (err, results) => {
    if (err) {
      //CORREGIDO VULNERABLE: Expone errores de SQL
      // Mediante la función responseSeguro se le envía una respuesta genérica
      // sin exponer los errores
      return responseSeguro(res, false);
    }
    
    const exists = results[0]?.count > 0;
    return responseSeguro(res, exists);
  });
};

// Esta función envía una respuesta genérica junto a un delay aleatorio
function responseSeguro(res, exists) {
  const delay = Math.random() * 100 + 50;
  setTimeout(() => {
    res.json({ exists: exists === true });
  }, delay);
}

module.exports = {
  login,
  register,
  verifyToken,
  checkUsername
};
