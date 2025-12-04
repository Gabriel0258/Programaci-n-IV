const express = require('express');
const { query, validationResult } = require('express-validator');
const router = express.Router();
const productController = require('../controllers/productController');

const sqlRegex = /['"=;()#\-*\/]|--|union|select|drop|delete|insert|update|information_schema/i;

const sanitizarQuery = [ 
    query('category').isAlphanumeric().trim().optional().escape().custom(cat => {
        if (sqlRegex.test(cat)) {
            throw new Error('Carácter inválido.');
        }
        return true
    }),
    query('search').optional().escape().trim().custom(s => {
        if (sqlRegex.test(s)) {
            throw new Error('Carácter inválido.');
        }
        return true
    }),
    (req, res, next) => {
        const errores = validationResult(req);
        if (!errores.isEmpty()) {
            return res.status(200).json([]);
        }
        next();
    }
];
// Ruta de productos (vulnerable a SQL injection)
router.get('/products', sanitizarQuery, productController.getProducts);

module.exports = router;
