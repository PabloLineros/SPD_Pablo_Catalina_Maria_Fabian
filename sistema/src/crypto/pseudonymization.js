import crypto from 'node:crypto';
import { FINALIDADES } from './keyring.js';
import { hmacHex } from './integrity.js';

/**
 * Módulo Criptográfico: Seudonimización
 *
 * - Índice ciego (blind index): HMAC(K_indice, email normalizado). Permite buscar al usuario
 *   en el login sin descifrar todos los correos. No es reversible sin la llave.
 * - Seudónimos por finalidad: HMAC(K_<finalidad>, user_id). Una llave distinta por finalidad
 *   evita que se crucen datasets (el seudónimo de reseñas no coincide con el de analítica).
 * - Referencias aleatorias: UUID v4 sin relación con ningún dato (seguimiento, courier, baja).
 *
 * La tabla que permite REVERTIR un seudónimo (pseudo.pseudonimos) solo es accesible por el
 * rol de BD svc_privacidad (ver src/db/repository.js y 03_rbac.sql).
 */

const FINALIDADES_SEUDONIMO = new Set([
  FINALIDADES.RESENAS,
  FINALIDADES.ANALITICA,
  FINALIDADES.MARKETING
]);

export function normalizarEmail(email) {
  return String(email).trim().toLowerCase();
}

/** Índice ciego para búsquedas exactas del email sin descifrar. */
export function indiceCiegoEmail(email) {
  return hmacHex(FINALIDADES.INDICE, normalizarEmail(email));
}

/**
 * Seudónimo determinista de un usuario para una finalidad concreta.
 * @param {'resenas'|'analitica'|'marketing'} finalidad
 * @param {string} userId
 */
export function seudonimo(finalidad, userId) {
  if (!FINALIDADES_SEUDONIMO.has(finalidad)) {
    throw new Error('Finalidad de seudonimización no permitida.');
  }
  return hmacHex(finalidad, userId);
}

/**
 * Huella de supresión de un titular: HMAC(K_indice, 'supresion:' + user_id). Permite reconocer
 * a un titular suprimido (p. ej. al restaurar un respaldo) sin conservar ningún dato suyo.
 */
export function huellaSupresion(userId) {
  return hmacHex(FINALIDADES.INDICE, `supresion:${userId}`);
}

/**
 * Seudónimo del origen de red para la auditoría: HMAC(K_origen, ip) truncado a 16 hex (64 bits).
 * Permite agrupar los eventos que vienen de un mismo origen (p. ej. un atacante que prueba muchas
 * cuentas) sin guardar la dirección IP. Sin la llave no se puede volver a la IP.
 */
export function referenciaOrigen(ip) {
  if (!ip) return null;
  const normalizada = String(ip).trim().toLowerCase().replace(/^::ffff:/, '');
  return `org:${hmacHex(FINALIDADES.ORIGEN, normalizada).slice(0, 16)}`;
}

/** Referencia opaca aleatoria (UUID v4, 122 bits de entropía). */
export function referenciaAleatoria() {
  return crypto.randomUUID();
}
