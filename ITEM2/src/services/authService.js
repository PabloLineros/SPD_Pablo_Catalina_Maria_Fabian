import crypto from 'node:crypto';
import { CONFIG } from '../config/env.js';
import { DB, ROLES_BD } from '../db/repository.js';
import { verifyPassword } from '../crypto/hashing.js';
import { indiceCiegoEmail } from '../crypto/pseudonymization.js';
import { ROLES } from '../security/rbac.js';
import { errores } from '../security/errors.js';
import { logger } from '../security/logger.js';

/**
 * Autenticación y sesiones.
 * - Búsqueda por índice ciego (email_hmac): no se descifra ningún correo para hacer login.
 * - Respuesta única 'Credenciales inválidas' + bcrypt señuelo: no permite enumerar usuarios.
 * - Bloqueo temporal tras CONFIG.MAX_INTENTOS_LOGIN fallos (fuerza bruta en línea).
 * - Token de sesión aleatorio de 256 bits; en BD solo se guarda su SHA-256.
 * - El rol del personal se relee en cada solicitud: revocar o cambiar un rol es inmediato.
 */

const bd = DB.conectar(ROLES_BD.SVC_APP);
const intentos = new Map(); // email_hmac -> { fallos, bloqueadoHasta }
const BLOQUEO_MS = 15 * 60 * 1000;

const hashToken = (token) => crypto.createHash('sha256').update(String(token)).digest('hex');

export async function iniciarSesion({ email, password } = {}) {
  const emailHmac = indiceCiegoEmail(email ?? '');
  const estado = intentos.get(emailHmac);
  if (estado?.bloqueadoHasta > Date.now()) {
    logger.warn('login_bloqueado', { cuenta: emailHmac.slice(0, 12) });
    throw errores.cuentaBloqueada();
  }

  const cliente = bd.buscarUno('users', u => u.email_hmac === emailHmac);
  const personal = cliente ? null : bd.buscarUno('personal', p => p.email_hmac === emailHmac && p.activo);
  const cuenta = cliente ?? personal;

  const valida = await verifyPassword(password, cuenta?.password_hash ?? null);
  if (!valida) {
    const fallos = (estado?.fallos ?? 0) + 1;
    intentos.set(emailHmac, {
      fallos,
      bloqueadoHasta: fallos >= CONFIG.MAX_INTENTOS_LOGIN ? Date.now() + BLOQUEO_MS : 0
    });
    logger.warn('login_fallido', { cuenta: emailHmac.slice(0, 12), fallos });
    throw errores.credencialesInvalidas();
  }
  intentos.delete(emailHmac);

  const token = crypto.randomBytes(32).toString('base64url');
  const ahora = new Date();
  bd.insertar('sesiones', {
    id: hashToken(token),
    usuario_id: cuenta.id,
    tipo: cliente ? 'CLIENTE' : 'PERSONAL',
    rol: cliente ? ROLES.CLIENTE : personal.rol,
    expira_el: new Date(ahora.getTime() + CONFIG.SESSION_TTL_MINUTOS * 60_000).toISOString(),
    created_at: ahora.toISOString()
  });
  logger.info('login_exitoso', { usuarioId: cuenta.id, rol: cliente ? ROLES.CLIENTE : personal.rol });

  return { token, rol: cliente ? ROLES.CLIENTE : personal.rol, usuarioId: cuenta.id, expiraEnMinutos: CONFIG.SESSION_TTL_MINUTOS };
}

/** Valida el token y devuelve la sesión vigente con el rol ACTUAL del usuario. */
export function resolverSesion(token) {
  if (typeof token !== 'string' || token.length < 40) throw errores.noAutenticado();
  const registro = bd.obtener('sesiones', hashToken(token));
  if (!registro || Date.parse(registro.expira_el) <= Date.now()) {
    if (registro) bd.eliminar('sesiones', registro.id);
    throw errores.noAutenticado();
  }

  if (registro.tipo === 'PERSONAL') {
    const p = bd.obtener('personal', registro.usuario_id);
    if (!p || !p.activo) {
      bd.eliminar('sesiones', registro.id);
      throw errores.noAutenticado();
    }
    return { usuarioId: p.id, rol: p.rol, tipo: 'PERSONAL' };
  }
  if (!bd.obtener('users', registro.usuario_id)) {
    bd.eliminar('sesiones', registro.id);
    throw errores.noAutenticado();
  }
  return { usuarioId: registro.usuario_id, rol: ROLES.CLIENTE, tipo: 'CLIENTE' };
}

export function cerrarSesion(token) {
  bd.eliminar('sesiones', hashToken(token));
}

/** Invalida todas las sesiones de un usuario (supresión de cuenta, desactivación). */
export function cerrarTodasLasSesiones(usuarioId) {
  for (const s of bd.seleccionar('sesiones', s => s.usuario_id === usuarioId)) {
    bd.eliminar('sesiones', s.id);
  }
}

/** Solo para pruebas: reinicia contadores de intentos. */
export function reiniciarIntentos() {
  intentos.clear();
}
