/* server.js */
'use strict';

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

// Node 18+ trae fetch global. Si estás en 16/14, cae a import dinámico de node-fetch v3 (ESM).
const fetch =
  global.fetch ||
  ((...args) => import('node-fetch').then(({ default: f }) => f(...args)));

dotenv.config();

const app = express();
app.disable('x-powered-by');
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

if ((process.env.JWT_SECRET || 'changeme') === 'changeme') {
  console.warn('[WARN] Estás usando el JWT_SECRET por defecto. Cámbialo en producción.');
}

/* ---------------------------- Swagger (OpenAPI) ---------------------------- */
const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: '3.0.3',
    info: {
      title: 'API Envío de Correos (Node.js)',
      version: '1.0.0',
      description: 'Express + JWT + Swagger + Nodemailer (sin BD)',
    },
    servers: [{ url: APP_URL }],
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      },
      schemas: {
        SendEmailRequest: {
          type: 'object',
          required: ['to', 'empresa', 'nombre', 'cargo', 'asunto', 'contenido', 'telefono'],
          properties: {
            to: { type: 'string', format: 'email', example: 'cliente@dominio.com' },
            empresa: { type: 'string', example: 'ACME S.A.C.' },
            nombre: { type: 'string', example: 'Juan Pérez' },
            cargo: { type: 'string', example: 'Jefe de TI' },
            asunto: { type: 'string', example: 'Solicitud de cotización' },
            telefono: { type: 'string', example: '+51 999 999 999' },
            contenido: { type: 'string', example: 'Mensaje del formulario...' },
          },
        },
        LoginRequest: {
          type: 'object',
          required: ['username', 'password'],
          properties: {
            username: { type: 'string', example: 'admin' },
            password: { type: 'string', example: 'suert3' },
          },
        },
        LoginResponse: {
          type: 'object',
          properties: {
            token: { type: 'string' },
            token_type: { type: 'string', example: 'bearer' },
            expires_in: { type: 'integer', example: 3600 },
          },
        },
      },
    },
  },
  // Toma las anotaciones OpenAPI de ESTE archivo
  apis: [__filename],
});

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

/* --------------------------------- Auth/JWT -------------------------------- */
function generateToken(sub) {
  const secret = process.env.JWT_SECRET || 'changeme';
  const expires = parseInt(process.env.JWT_EXPIRES_MIN || '60', 10) * 60; // segundos
  return jwt.sign({ sub }, secret, { expiresIn: expires });
}

function verifyToken(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const prefix = 'Bearer ';
  if (!auth.startsWith(prefix)) {
    return res.status(401).json({ error: 'Token ausente' });
  }
  const token = auth.substring(prefix.length);
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'changeme');
    req.user = decoded;
    return next();
  } catch {
    return res.status(401).json({ error: 'Token inválido' });
  }
}

/* --------------------------------- Mailer ---------------------------------- */
function createTransporter() {
  const secure = String(process.env.SMTP_SECURE || 'false').toLowerCase() === 'true';
  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host || !user || !pass) {
    throw new Error('Faltan variables SMTP_HOST/SMTP_USER/SMTP_PASS en el entorno.');
  }

  return nodemailer.createTransport({
    host,
    port: parseInt(process.env.SMTP_PORT || (secure ? '465' : '587'), 10),
    secure,
    auth: { user, pass },
  });
}

/* -------------------------------- Endpoints -------------------------------- */
/**
 * @openapi
 * /health:
 *   get:
 *     tags: [Misc]
 *     summary: Healthcheck
 *     responses:
 *       200:
 *         description: OK
 */
app.get('/health', (req, res) => res.json({ ok: true }));

/**
 * @openapi
 * /auth/login:
 *   post:
 *     tags: [Auth]
 *     summary: Login
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: Token emitido
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/LoginResponse'
 *       401:
 *         description: Credenciales inválidas
 */
app.post('/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  const demoUser = process.env.DEMO_USER || 'admin';
  const demoPass = process.env.DEMO_PASS || 'suert3';

  if (username !== demoUser || password !== demoPass) {
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }
  const token = generateToken(username);
  const expires = parseInt(process.env.JWT_EXPIRES_MIN || '60', 10) * 60;
  return res.json({ token, token_type: 'bearer', expires_in: expires });
});

/**
 * @openapi
 * /api/v1/email/send:
 *   post:
 *     tags: [Email]
 *     summary: Envía un correo
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/SendEmailRequest'
 *     responses:
 *       200:
 *         description: Correo enviado
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 id:
 *                   type: string
 *                   example: '<message id>'
 *       400:
 *         description: Datos inválidos
 *       500:
 *         description: Error enviando correo
 */
app.post('/api/v1/email/send', verifyToken, async (req, res) => {
  const { to, empresa, nombre, cargo, asunto, contenido, telefono } = req.body || {};
  if (!to || !empresa || !nombre || !cargo || !asunto || !contenido || !telefono) {
    return res.status(400).json({ error: 'Parámetros inválidos: todos los campos son obligatorios' });
  }

  // Texto plano para correo
  const text = [
    'Se recibió una solicitud desde el formulario de contacto.',
    '',
    `Empresa: ${empresa}`,
    `Nombre: ${nombre}`,
    `Cargo: ${cargo}`,
    `Correo: ${to}`,
    `Asunto: ${asunto}`,
    `Teléfono: ${telefono}`,
    '',
    'Mensaje:',
    contenido,
  ].join('\n');

  try {
    const transporter = createTransporter();
    const info = await transporter.sendMail({
      from: {
        name: process.env.FROM_NAME || 'API',
        address: process.env.FROM_EMAIL || process.env.SMTP_USER, // asegúrate que tu SMTP permita este remitente
      },
      // El destinatario real suele ser tu buzón (contacto de tu web)
      to: process.env.SMTP_USER,
      subject: 'Hexagon - Consulta de formulario contacto',
      text,
      html: `
        <p><strong>Empresa:</strong> ${empresa}</p>
        <p><strong>Nombre:</strong> ${nombre}</p>
        <p><strong>Cargo:</strong> ${cargo}</p>
        <p><strong>Email:</strong> ${to}</p>
        <p><strong>Asunto:</strong> ${asunto}</p>
        <p><strong>Teléfono:</strong> ${telefono}</p>
        <p><strong>Mensaje:</strong><br>${String(contenido).replace(/\n/g, '<br>')}</p>
      `,
    });

    return res.json({ success: true, id: info.messageId || null });
  } catch (err) {
    console.error('Mailer error:', err?.message || err);
    return res.status(500).json({ error: 'Mailer error' });
  }
});

/**
 * @openapi
 * /api/verify-captcha:
 *   post:
 *     tags: [Misc]
 *     summary: Verifica token de Google reCAPTCHA
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [token]
 *             properties:
 *               token:
 *                 type: string
 *                 description: Token retornado por reCAPTCHA en el cliente
 *     responses:
 *       200:
 *         description: verificación OK
 *       400:
 *         description: token inválido o ausente
 */
app.post('/api/verify-captcha', async (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ ok: false, error: 'Token CAPTCHA requerido' });
    if (!process.env.RECAPTCHA_SECRET) {
      return res.status(500).json({ ok: false, error: 'Falta RECAPTCHA_SECRET en el entorno' });
    }

    const params = new URLSearchParams({
      secret: process.env.RECAPTCHA_SECRET,
      response: token,
      // remoteip: req.ip, // opcional
    });

    const r = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });

    const data = await r.json(); // { success: boolean, ... }

    if (data.success) return res.status(200).json({ ok: true, score: data.score, action: data.action });
    return res.status(400).json({ ok: false, details: data['error-codes'] });
  } catch (e) {
    console.error('Captcha error:', e?.message || e);
    return res.status(500).json({ ok: false, error: 'Error verificando CAPTCHA' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on ${APP_URL}`);
  console.log(`Swagger UI: ${APP_URL}/api-docs`);
});
