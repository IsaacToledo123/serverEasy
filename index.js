const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const mysql = require('mysql2/promise');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'aplicacion_secreta';

// Configuración de la base de datos MySQL
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_DATABASE || 'auth_db',
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

// Pool de conexiones
const pool = mysql.createPool(dbConfig);

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// CORS configuración mejorada
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000', '*'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Origin', 'X-Requested-With', 'Accept'],
  credentials: true
}));

// Función para crear la tabla de usuarios si no existe
async function createUsersTable() {
  try {
    const connection = await pool.getConnection();
    
    const createTableQuery = `
      CREATE TABLE IF NOT EXISTS usuarios (
        id INT PRIMARY KEY AUTO_INCREMENT,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `;
    
    await connection.execute(createTableQuery);
    connection.release();
    console.log('✅ Tabla usuarios verificada/creada exitosamente');
  } catch (error) {
    console.error('❌ Error creando tabla usuarios:', error);
  }
}

// Validaciones
const registerValidation = [
  body('username')
    .isLength({ min: 3, max: 20 })
    .withMessage('El username debe tener entre 3 y 20 caracteres')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('El username solo puede contener letras, números y guiones bajos'),
  body('email')
    .isEmail()
    .withMessage('Debe ser un email válido')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 6 })
    .withMessage('La contraseña debe tener al menos 6 caracteres')
];

const loginValidation = [
  body('username')
    .notEmpty()
    .withMessage('El username es requerido'),
  body('password')
    .notEmpty()
    .withMessage('La contraseña es requerida')
];

// Función para buscar usuario por username
async function findUserByUsername(username) {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT * FROM usuarios WHERE username = ?',
      [username]
    );
    connection.release();
    return rows[0] || null;
  } catch (error) {
    console.error('Error buscando usuario:', error);
    throw error;
  }
}

// Función para buscar usuario por email
async function findUserByEmail(email) {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT * FROM usuarios WHERE email = ?',
      [email]
    );
    connection.release();
    return rows[0] || null;
  } catch (error) {
    console.error('Error buscando usuario por email:', error);
    throw error;
  }
}

// Función para buscar usuario por ID
async function findUserById(id) {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT * FROM usuarios WHERE id = ?',
      [id]
    );
    connection.release();
    return rows[0] || null;
  } catch (error) {
    console.error('Error buscando usuario por ID:', error);
    throw error;
  }
}

// Función para crear usuario
async function createUser(userData) {
  try {
    const connection = await pool.getConnection();
    const { username, email, password } = userData;

    const [result] = await connection.execute(
      'INSERT INTO usuarios (username, email, password) VALUES (?, ?, ?)',
      [username, email, password]
    );

    const insertedId = result.insertId;
    connection.release();
    
    return { id: insertedId, username, email, password };
  } catch (error) {
    console.error('Error creando usuario:', error);
    throw error;
  }
}

// RUTAS

// Ruta de prueba
app.get('/', (req, res) => {
  res.json({ 
    message: 'API de Autenticación funcionando',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    endpoints: {
      register: 'POST /api/register',
      login: 'POST /api/login',
      profile: 'GET /api/profile',
      testDb: 'GET /api/test-db'
    }
  });
});

// Test de conexión a la base de datos
app.get('/api/test-db', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.execute('SELECT 1 as test');
    connection.release();
    res.json({
      success: true,
      message: 'Conexión a la base de datos exitosa',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error en test de DB:', error);
    res.status(500).json({
      success: false,
      message: 'Error conectando a la base de datos',
      error: error.message
    });
  }
});

// REGISTRO
app.post('/api/register', registerValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Errores de validación',
        errors: errors.array()
      });
    }

    const { username, email, password } = req.body;

    // Verificar si el usuario ya existe
    const existingUserByUsername = await findUserByUsername(username);
    if (existingUserByUsername) {
      return res.status(400).json({
        success: false,
        message: 'El username ya está en uso'
      });
    }

    const existingUserByEmail = await findUserByEmail(email);
    if (existingUserByEmail) {
      return res.status(400).json({
        success: false,
        message: 'El email ya está registrado'
      });
    }

    // Encriptar contraseña
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Crear nuevo usuario
    const newUser = {
      username: username.toLowerCase(),
      email: email.toLowerCase(),
      password: hashedPassword
    };

    const createdUser = await createUser(newUser);

    // Generar JWT
    const token = jwt.sign(
      { 
        userId: createdUser.id, 
        username: createdUser.username 
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Obtener usuario creado (sin contraseña)
    const userForResponse = await findUserById(createdUser.id);
    const { password: _, ...userResponse } = userForResponse;

    res.status(201).json({
      success: true,
      message: 'Usuario registrado exitosamente',
      data: {
        user: userResponse,
        token
      }
    });

  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// LOGIN
app.post('/api/login', loginValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Errores de validación',
        errors: errors.array()
      });
    }

    const { username, password } = req.body;

    // Buscar usuario
    const user = await findUserByUsername(username.toLowerCase());
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Credenciales inválidas'
      });
    }

    // Verificar contraseña
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Credenciales inválidas'
      });
    }

    // Generar JWT
    const token = jwt.sign(
      { 
        userId: user.id, 
        username: user.username 
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Respuesta sin contraseña
    const { password: _, ...userResponse } = user;

    res.json({
      success: true,
      message: 'Login exitoso',
      data: {
        user: userResponse,
        token
      }
    });

  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// Middleware para verificar JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Token de acceso requerido'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        message: 'Token inválido'
      });
    }
    req.user = user;
    next();
  });
};

// Ruta protegida - Obtener perfil del usuario
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await findUserById(req.user.userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    const { password: _, ...userResponse } = user;

    res.json({
      success: true,
      data: { user: userResponse }
    });

  } catch (error) {
    console.error('Error obteniendo perfil:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// Manejo de errores 404
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint no encontrado'
  });
});

// Manejo de errores globales
app.use((error, req, res, next) => {
  console.error('Error no manejado:', error);
  res.status(500).json({
    success: false,
    message: 'Error interno del servidor'
  });
});

// Inicializar servidor
async function startServer() {
  try {
    // Crear tabla si no existe
    await createUsersTable();
    
    app.listen(PORT, () => {
      console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
      console.log(`🌐 URL: http://localhost:${PORT}`);
      console.log(`📋 Endpoints disponibles:`);
      console.log(`   GET  / - Información de la API`);
      console.log(`   GET  /api/test-db - Test de conexión DB`);
      console.log(`   POST /api/register - Registro de usuarios`);
      console.log(`   POST /api/login - Login de usuarios`);
      console.log(`   GET  /api/profile - Perfil del usuario (requiere token)`);
    });
  } catch (error) {
    console.error('❌ Error iniciando servidor:', error);
    process.exit(1);
  }
}

startServer();

module.exports = app;