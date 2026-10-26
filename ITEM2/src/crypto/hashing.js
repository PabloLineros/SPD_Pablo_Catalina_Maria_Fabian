import bcrypt from 'bcryptjs';
import { CONFIG } from '../config/env.js';

/**
 * Módulo Criptográfico: Hashing de Contraseñas (Irreversible)
 * Principio: Una contraseña NUNCA debe ser descifrable. Se utiliza una función
 * hash lenta con salting criptográfico por iteración (bcrypt) para resistir
 * ataques de diccionario, tablas arcoíris (Rainbow Tables) y fuerza bruta con GPUs.
 */

// bcrypt ignora silenciosamente todo lo que exceda 72 bytes: se rechaza explícitamente.
const BCRYPT_MAX_BYTES = 72;
const LARGO_MINIMO = 12;

let hashSenuelo = null;

/**
 * Política mínima de contraseñas (OWASP ASVS 2.1): largo >= 12 y <= 72 bytes.
 * @returns {string|null} Motivo del rechazo, o null si es aceptable.
 */
export function validarPoliticaPassword(password) {
  if (typeof password !== 'string' || password.length < LARGO_MINIMO) {
    return `La contraseña debe tener al menos ${LARGO_MINIMO} caracteres.`;
  }
  if (Buffer.byteLength(password, 'utf8') > BCRYPT_MAX_BYTES) {
    return `La contraseña no puede superar ${BCRYPT_MAX_BYTES} bytes.`;
  }
  return null;
}

/**
 * Genera un hash irreversible a partir de una contraseña en texto plano.
 * @param {string} plainPassword Contraseña ingresada por el usuario.
 * @returns {Promise<string>} Hash bcrypt completo ($2a$ o $2b$ + coste + salt + hash).
 */
export async function hashPassword(plainPassword) {
  if (!plainPassword || typeof plainPassword !== 'string') {
    throw new Error('La contraseña debe ser una cadena de texto no vacía.');
  }
  if (Buffer.byteLength(plainPassword, 'utf8') > BCRYPT_MAX_BYTES) {
    throw new Error(`La contraseña no puede superar ${BCRYPT_MAX_BYTES} bytes.`);
  }

  const salt = await bcrypt.genSalt(CONFIG.BCRYPT_ROUNDS);
  return bcrypt.hash(plainPassword, salt);
}

/**
 * Verifica si una contraseña candidata coincide con el hash almacenado.
 * Si no existe usuario (storedHash vacío) se compara contra un hash señuelo, para que
 * el tiempo de respuesta no revele si el correo está registrado (enumeración de usuarios).
 * @param {string} candidatePassword Contraseña ingresada en el formulario de inicio de sesión.
 * @param {string|null} storedHash Hash recuperado de la base de datos (o null).
 * @returns {Promise<boolean>}
 */
export async function verifyPassword(candidatePassword, storedHash) {
  if (typeof candidatePassword !== 'string') {
    candidatePassword = '';
  }
  if (!storedHash) {
    hashSenuelo ??= bcrypt.hashSync('senuelo-no-es-una-cuenta', CONFIG.BCRYPT_ROUNDS);
    await bcrypt.compare(candidatePassword, hashSenuelo);
    return false;
  }
  return bcrypt.compare(candidatePassword, storedHash);
}

/**
 * Desglosa la estructura del hash generado por bcrypt para propósitos de auditoría y evidencia técnica.
 * Formato estándar: $[algoritmo]$[costo]$[salt (22 chars)][hash (31 chars)]
 * @param {string} hash
 */
export function inspectBcryptHash(hash) {
  const parts = hash.split('$');
  if (parts.length < 4) {
    return { valid: false };
  }
  const algorithm = parts[1];
  const cost = parts[2];
  const saltAndHash = parts[3];

  return {
    valid: true,
    algorithm: `bcrypt (${algorithm})`,
    costFactorRounds: parseInt(cost, 10),
    iterations: 2 ** parseInt(cost, 10),
    saltBase64: saltAndHash.substring(0, 22),
    hashDigest: saltAndHash.substring(22)
  };
}
