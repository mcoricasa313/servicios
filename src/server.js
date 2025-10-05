const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
import fetch from 'node-fetch';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

// Swagger
const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: '3.0.3',
    info: {
      title: 'API Envío de Correos (Node.js)',
      version: '1.0.0',
      description: 'Express + JWT + Swagger + Nodemailer (sin BD)',
    },
    servers: [{ url: '/' }],
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      },
      schemas: {
        SendEmailRequest: {
          type: 'object',
          required: ['to', 'empresa', 'nombre', 'cargo', 'asunto', 'contenido','telefono'],
          properties: {
            email: { type: 'string', format: 'email', example: 'destino@empresa.com' },
            empresa: { type: 'string', example: 'Consulta de servicio' },
            nombre: { type: 'string', example: 'Consulta de servicio' },
            cargo: { type: 'string', example: 'Consulta de servicio' },
            asunto: { type: 'string', example: 'Consulta de servicio' },
            telefono: { type: 'string', example: '+51 999 999 999' },
            contenido: { type: 'string', example: 'Mensaje opcional' },
          },
        },
        LoginRequest: {
          type: 'object',
          required: ['username', 'password'],
          properties: {
            username: { type: 'string', example: 'admin@example.com' },
            password: { type: 'string', example: 'admin' },
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
  apis: ['./src/server.js'],
});

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

function generateToken(sub) {
  const secret = process.env.JWT_SECRET || 'changeme';
  const expires = parseInt(process.env.JWT_EXPIRES_MIN || '60', 10) * 60;
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
function createTransporter() {
  const secure = String(process.env.SMTP_SECURE || 'false').toLowerCase() === 'true';
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || (secure ? '465' : '587'), 10),
    secure,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
}

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
  const { to, empresa, nombre, cargo, asunto,contenido,telefono} = req.body || {};
  if (!to || !empresa || !nombre|| !cargo|| !asunto|| !contenido|| !telefono) {
    return res.status(400).json({ error: 'Parámetros inválidos: Todos los campos son obligatorios' });
  }

  const text = [
    'Se recibió una solicitud desde el formulario de contacto.',
    '',
    `Empresa: ${empresa}`,
    `Nombre: ${nombre}`,
    `Cargo: ${cargo}`,
    `Correo: ${to}`,
    `Asunto: ${asunto}`,
    `Teléfono: ${telefono}`,
    contenido ? ['', 'Mensaje:', contenido].join('\\n') : ''
  ].join('\\n');

  try {
    const transporter = createTransporter();
    const info = await transporter.sendMail({
      from: {
        name: process.env.FROM_NAME || 'API',
        address: process.env.FROM_EMAIL || 'no-reply@example.com',
      },
      to : process.env.SMTP_USER,
      //cc:process.env.SMTP_USER,
      subject : 'Hexagon - Consulta de formulario contacto',
      text,
      html: `<p><strong>Empresa:</strong> ${empresa}</p>
      <p><strong>Nombres:</strong> ${nombre}</p>
      <p><strong>Cargo:</strong> ${cargo}</p>
      <p><strong>Email:</strong> ${to}</p>
             <p><strong>Asunto:</strong> ${asunto}</p>
             ${contenido ? `<p><strong>Mensaje:</strong><br>${String(contenido).replace(/\\n/g,'<br>')}</p>` : ''}`
    });
    return res.json({ success: true, id: info.messageId || null });
  } catch (err) {
    console.error('Mailer error:', err?.message || err);
    return res.status(500).json({ error: 'Mailer error' });
  }
});

app.post('/api/verify-captcha', async (req, res) => {
  const { token } = req.body;
  const params = new URLSearchParams({
    secret: process.env.RECAPTCHA_SECRET, // tu SECRET del servidor
    response: token,
    // optional: remoteip: req.ip
  });
  const r = await fetch('https://www.google.com/recaptcha/api/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString()
  });
  const data = await r.json(); // { success: boolean, ... }
  if (data.success) res.status(200).send({ ok: true });
  else res.status(400).send({ ok: false, details: data['error-codes'] });
});

app.listen(PORT, () => {
  console.log(`Server running on ${APP_URL}`);
  console.log(`Swagger UI: ${APP_URL}/api-docs`);
});
