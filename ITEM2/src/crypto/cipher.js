import crypto from 'node:crypto';
import { CONFIG } from '../config/env.js';

/**
 * Módulo Criptográfico: Cifrado Simétrico Autenticado (AES-256-GCM)
 * Principio: Se utiliza cuando el sistema necesita recuperar el dato original en texto plano
 * (Reversible), como información PII de clientes (email, direcciones, datos tributarios).
 * 
 * Estándar implementado:
 * - Algoritmo: AES-256 en modo GCM (Galois/Counter Mode).
 * - Tamaño de Llave: 256 bits (32 bytes).
 * - IV (Vector de Inicialización): 96 bits (12 bytes), generado con CSPRNG aleatorio y único por registro.
 * - Tag de Autenticación: 128 bits (16 bytes), asegura Confidencialidad E Integridad (AEAD).
 */

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH_BYTES = 12; // 96 bits recomendado por NIST SP 800-38D
const AUTH_TAG_LENGTH_BYTES = 16; // 128 bits

/**
 * Cifra un texto plano utilizando AES-256-GCM con un IV único por operación.
 * @param {string} plaintext Texto a cifrar (ej. email, dirección).
 * @param {string} [associatedData] Datos asociados adicionales (AAD) opcionales para autenticación de contexto.
 * @returns {string} Cadena compacta serializada: 'ivHex:authTagHex:ciphertextHex'.
 */
export function encryptField(plaintext, associatedData = '') {
  if (plaintext === null || plaintext === undefined || typeof plaintext !== 'string') {
    throw new Error('El dato a cifrar debe ser una cadena de texto.');
  }

  // 1. Generación de IV único por registro usando CSPRNG nativo
  const iv = crypto.randomBytes(IV_LENGTH_BYTES);

  // 2. Creación del objeto Cipher
  const cipher = crypto.createCipheriv(ALGORITHM, CONFIG.AES_KEY, iv, {
    authTagLength: AUTH_TAG_LENGTH_BYTES
  });

  if (associatedData) {
    cipher.setAAD(Buffer.from(associatedData, 'utf8'));
  }

  // 3. Cifrado de los datos
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final()
  ]);

  // 4. Obtención del tag de autenticación generado por GCM
  const authTag = cipher.getAuthTag();

  // 5. Serialización segura para almacenamiento en base de datos
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

/**
 * Descifra un dato cifrado con AES-256-GCM y valida su etiqueta de autenticación (auth tag).
 * @param {string} encryptedPayload Cadena serializada 'ivHex:authTagHex:ciphertextHex'.
 * @param {string} [associatedData] Mismo AAD utilizado durante el cifrado.
 * @returns {string} Texto plano original recuperado.
 * @throws {Error} Si el dato fue manipulado, la llave es incorrecta o el auth tag no coincide.
 */
export function decryptField(encryptedPayload, associatedData = '') {
  if (!encryptedPayload || typeof encryptedPayload !== 'string') {
    throw new Error('El payload cifrado es inválido.');
  }

  const parts = encryptedPayload.split(':');
  if (parts.length !== 3) {
    throw new Error('Formato de payload cifrado no reconocido (se esperaba iv:tag:data).');
  }

  const [ivHex, authTagHex, ciphertextHex] = parts;
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const ciphertext = Buffer.from(ciphertextHex, 'hex');

  // Creación del objeto Decipher
  const decipher = crypto.createDecipheriv(ALGORITHM, CONFIG.AES_KEY, iv, {
    authTagLength: AUTH_TAG_LENGTH_BYTES
  });

  if (associatedData) {
    decipher.setAAD(Buffer.from(associatedData, 'utf8'));
  }

  // Establecer el tag de autenticación esperado
  decipher.setAuthTag(authTag);

  // Descifrado y verificación matemática del tag
  try {
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]);
    return decrypted.toString('utf8');
  } catch (err) {
    throw new Error(`Fallo de Autenticidad en Descifrado AES-256-GCM: Los datos han sido alterados o la llave es inválida. Detalle: ${err.message}`);
  }
}

/**
 * Inspecciona un payload cifrado para mostrar visualmente sus componentes criptográficos.
 * @param {string} encryptedPayload
 */
export function inspectCipherPayload(encryptedPayload) {
  const parts = encryptedPayload.split(':');
  if (parts.length !== 3) return { valid: false };

  return {
    algorithm: ALGORITHM,
    ivHex: parts[0],
    ivBytes: Buffer.from(parts[0], 'hex').length,
    authTagHex: parts[1],
    authTagBytes: Buffer.from(parts[1], 'hex').length,
    ciphertextHex: parts[2],
    cipherSizeBytes: Buffer.from(parts[2], 'hex').length
  };
}
