import bcrypt from 'bcryptjs';
import { CONFIG } from '../config/env.js';

/**
 * Módulo Criptográfico: Hashing de Contraseñas (Irreversible)
 * Principio: Una contraseña NUNCA debe ser descifrable. Se utiliza una función
 * hash lenta con salting criptográfico por iteración (bcrypt) para resistir
 * ataques de diccionario, tablas arcoíris (Rainbow Tables) y fuerza bruta con GPUs.
 */

/**
 * Genera un hash irreversible a partir de una contraseña en texto plano.
 * @param {string} plainPassword Contraseña ingresada por el usuario.
 * @returns {Promise<string>} Hash bcrypt completo ($2a$ o $2b$ + coste + salt + hash).
 */
export async function hashPassword(plainPassword) {
  if (!plainPassword || typeof plainPassword !== 'string') {
    throw new Error('La contraseña debe ser una cadena de texto no vacía.');
  }

  // Generación de Salt criptográficamente seguro con el factor de costo configurado
  const salt = await bcrypt.genSalt(CONFIG.BCRYPT_ROUNDS);
  const hash = await bcrypt.hash(plainPassword, salt);
  return hash;
}

/**
 * Verifica si una contraseña candidata coincide con el hash almacenado en la base de datos.
 * La operación bcrypt.compare es constante en tiempo para mitigar Timing Attacks.
 * @param {string} candidatePassword Contraseña ingresada en el formulario de inicio de sesión.
 * @param {string} storedHash Hash recuperado de la base de datos.
 * @returns {Promise<boolean>} True si la contraseña es correcta, False de lo contrario.
 */
export async function verifyPassword(candidatePassword, storedHash) {
  if (!candidatePassword || !storedHash) {
    return false;
  }
  return await bcrypt.compare(candidatePassword, storedHash);
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
  const salt = saltAndHash.substring(0, 22);
  const rawHash = saltAndHash.substring(22);

  return {
    valid: true,
    algorithm: `bcrypt (${algorithm})`,
    costFactorRounds: parseInt(cost, 10),
    iterations: 2 ** parseInt(cost, 10),
    saltBase64: salt,
    hashDigest: rawHash
  };
}
