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

/** Referencia opaca aleatoria (UUID v4, 122 bits de entropía). */
export function referenciaAleatoria() {
  return crypto.randomUUID();
}
