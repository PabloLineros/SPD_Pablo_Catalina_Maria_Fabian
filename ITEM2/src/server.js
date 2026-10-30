import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CONFIG } from './config/env.js';
import { API } from './api.js';
import { resolverSesion } from './services/authService.js';
import { UserService } from './services/userService.js';
import { bandejaDe } from './infra/correo.js';
import { respuestaDeError } from './security/errors.js';
import { logger } from './security/logger.js';

/**
 * Servidor HTTP de NortiShop (sin dependencias externas).
 *
 *  POST /api/<grupo>/<operacion>   cuerpo JSON { "args": [...] }, token en "Authorization: Bearer".
 *  GET  /                          Centro de privacidad (public/).
 *  GET  /api/dev/bandeja           Bandeja de correo SIMULADA del usuario con sesión (no existe en producción).
 *
 * No hay atajos: cada ruta llama a la misma API que valida sesión, rol, propiedad del recurso y
 * campos permitidos. Las operaciones internas (p. ej. suprimirCliente, otorgarConsentimiento
 * interno) no están en la API y por lo tanto no tienen ruta.
 */

const PUBLICAS = new Set([
  'auth.registrar', 'auth.iniciarSesion', 'auth.cerrarSesion', 'catalogo.listar', 'catalogo.resenas',
  'invitado.crearPedido', 'invitado.consultarPedido', 'consentimiento.desuscribir'
]);
const MAX_CUERPO = 100 * 1024;
const PUBLICO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../public');
const ESTATICOS = { '/': 'index.html', '/app.js': 'app.js', '/estilos.css': 'estilos.css' };
const TIPOS = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };

const CABECERAS_SEGURIDAD = {
  'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY'
};

function responder(res, estado, cuerpo) {
  res.writeHead(estado, { ...CABECERAS_SEGURIDAD, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(cuerpo));
}

function leerCuerpo(req) {
  return new Promise((resolve, reject) => {
    let total = 0;
    let excedido = false;
    const partes = [];
    req.on('data', (c) => {
      total += c.length;
      if (total > MAX_CUERPO) excedido = true; // se sigue leyendo (y descartando) para poder responder 413
      else partes.push(c);
    });
    req.on('end', () => (excedido
      ? reject(Object.assign(new Error('cuerpo demasiado grande'), { estado: 413 }))
      : resolve(Buffer.concat(partes).toString('utf8'))));
    req.on('error', reject);
  });
}

const tokenDe = (req) => /^Bearer (\S+)$/.exec(req.headers.authorization ?? '')?.[1];

async function manejarApi(req, res, grupo, operacion) {
  const fn = Object.hasOwn(API, grupo) && Object.hasOwn(API[grupo], operacion) ? API[grupo][operacion] : null;
  if (!fn) return responder(res, 404, { ok: false, error: { codigo: 'NO_ENCONTRADO', estado: 404, mensaje: 'Operación inexistente.' } });
  if (req.method !== 'POST') return responder(res, 405, { ok: false, error: { codigo: 'METODO_NO_PERMITIDO', estado: 405, mensaje: 'Use POST.' } });
  if (!String(req.headers['content-type'] ?? '').startsWith('application/json')) {
    return responder(res, 415, { ok: false, error: { codigo: 'DATO_INVALIDO', estado: 415, mensaje: 'Content-Type debe ser application/json.' } });
  }

  let args;
  try {
    const cuerpo = await leerCuerpo(req);
    args = cuerpo ? JSON.parse(cuerpo).args ?? [] : [];
    if (!Array.isArray(args)) throw new Error('args debe ser una lista');
  } catch (e) {
    const estado = e.estado ?? 400;
    return responder(res, estado, { ok: false, error: { codigo: 'DATO_INVALIDO', estado, mensaje: 'Cuerpo de la solicitud inválido.' } });
  }

  const resultado = PUBLICAS.has(`${grupo}.${operacion}`) ? await fn(...args) : await fn(tokenDe(req), ...args);
  return responder(res, resultado.ok ? 200 : resultado.error.estado, resultado);
}

function manejarBandejaDev(req, res) {
  if (CONFIG.NODE_ENV === 'production') return responder(res, 404, { ok: false });
  try {
    const sesion = resolverSesion(tokenDe(req));
    const { email } = UserService.verPerfilPropio(sesion, sesion.usuarioId);
    return responder(res, 200, { ok: true, data: bandejaDe(email).reverse() });
  } catch (e) {
    const r = respuestaDeError(e);
    return responder(res, r.estado, { ok: false, error: r });
  }
}

export function crearServidor() {
  return http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://localhost');
      const api = /^\/api\/([a-zA-Z]+)\/([a-zA-Z]+)$/.exec(url.pathname);
      if (url.pathname === '/api/dev/bandeja' && req.method === 'GET') return manejarBandejaDev(req, res);
      if (api) return await manejarApi(req, res, api[1], api[2]);
      const archivo = ESTATICOS[url.pathname];
      if (archivo && req.method === 'GET') {
        res.writeHead(200, { ...CABECERAS_SEGURIDAD, 'Content-Type': TIPOS[path.extname(archivo)] });
        return res.end(fs.readFileSync(path.join(PUBLICO, archivo)));
      }
      return responder(res, 404, { ok: false, error: { codigo: 'NO_ENCONTRADO', estado: 404, mensaje: 'Recurso no encontrado.' } });
    } catch (error) {
      logger.error('error_http', { error });
      return responder(res, 500, { ok: false, error: { codigo: 'ERROR_INTERNO', estado: 500, mensaje: 'Ocurrió un error interno. Intente nuevamente.' } });
    }
  });
}

// Ejecución directa: `npm run servidor` levanta el servidor con datos sintéticos de demostración.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { prepararEscenario, PASSWORD_PRUEBA } = await import('./dev/escenario.js');
  await prepararEscenario();
  crearServidor().listen(CONFIG.PUERTO, '127.0.0.1', () => {
    console.log(`Centro de privacidad: http://127.0.0.1:${CONFIG.PUERTO}/`);
    console.log(`Cuenta de prueba (sintética): ana.prueba@ejemplo.test / ${PASSWORD_PRUEBA}`);
  });
}
