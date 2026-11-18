import crypto from 'node:crypto';
import { usarLlave, FINALIDADES } from './keyring.js';

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
 * - AAD OBLIGATORIO: '<tabla>.<campo>:<id>'. Amarra el criptograma a su registro y campo:
 *   copiar el email cifrado de un usuario a otro (o a otra columna) hace fallar el descifrado.
 */

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH_BYTES = 12; // 96 bits recomendado por NIST SP 800-38D
const AUTH_TAG_LENGTH_BYTES = 16; // 128 bits
const FORMATO_PAYLOAD = /^[0-9a-f]{24}:[0-9a-f]{32}:([0-9a-f]{2})*$/;

/**
 * Construye el AAD canónico de un campo cifrado.
 * @param {string} tabla Nombre de la tabla (ej. 'users').
 * @param {string} campo Nombre de la columna (ej. 'email_cifrado').
 * @param {string} id Identificador del registro.
 */
export function contexto(tabla, campo, id) {
  if (!tabla || !campo || !id) {
    throw new Error('El contexto de cifrado requiere tabla, campo e id.');
  }
  return `${tabla}.${campo}:${id}`;
}

/** Indica si un valor tiene el formato serializado iv:tag:ciphertext. */
export function esPayloadCifrado(valor) {
  return typeof valor === 'string' && FORMATO_PAYLOAD.test(valor);
}

/**
 * Cifra un texto plano utilizando AES-256-GCM con un IV único por operación.
 * @param {string} plaintext Texto a cifrar (ej. email, dirección).
 * @param {string} associatedData AAD obligatorio (usar contexto()).
 * @returns {string} Cadena compacta serializada: 'ivHex:authTagHex:ciphertextHex'.
 */
export function encryptField(plaintext, associatedData) {
  if (typeof plaintext !== 'string') {
    throw new Error('El dato a cifrar debe ser una cadena de texto.');
  }
  if (!associatedData || typeof associatedData !== 'string') {
    throw new Error('El cifrado requiere un contexto (AAD) explícito.');
  }

  const iv = crypto.randomBytes(IV_LENGTH_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, usarLlave(FINALIDADES.CIFRADO), iv, {
    authTagLength: AUTH_TAG_LENGTH_BYTES
  });
  cipher.setAAD(Buffer.from(associatedData, 'utf8'));

  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

/**
 * Descifra un dato cifrado con AES-256-GCM y valida su etiqueta de autenticación.
 * El mensaje de error es genérico a propósito: no revela si falló la llave, el tag o el AAD.
 * @param {string} encryptedPayload Cadena serializada 'ivHex:authTagHex:ciphertextHex'.
 * @param {string} associatedData Mismo AAD utilizado durante el cifrado.
 * @returns {string} Texto plano original recuperado.
 */
export function decryptField(encryptedPayload, associatedData) {
  if (!esPayloadCifrado(encryptedPayload)) {
    throw errorDescifrado();
  }
  if (!associatedData || typeof associatedData !== 'string') {
    throw new Error('El descifrado requiere un contexto (AAD) explícito.');
  }

  const [ivHex, authTagHex, ciphertextHex] = encryptedPayload.split(':');
  const decipher = crypto.createDecipheriv(ALGORITHM, usarLlave(FINALIDADES.CIFRADO), Buffer.from(ivHex, 'hex'), {
    authTagLength: AUTH_TAG_LENGTH_BYTES
  });
  decipher.setAAD(Buffer.from(associatedData, 'utf8'));
  decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));

  try {
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(ciphertextHex, 'hex')),
      decipher.final()
    ]);
    return decrypted.toString('utf8');
  } catch {
    throw errorDescifrado();
  }
}

function errorDescifrado() {
  const error = new Error('Fallo de Autenticidad en Descifrado AES-256-GCM: dato alterado, contexto incorrecto o llave inválida.');
  error.code = 'CIFRADO_INVALIDO';
  return error;
}

/**
 * Inspecciona un payload cifrado para mostrar visualmente sus componentes criptográficos.
 * @param {string} encryptedPayload
 */
export function inspectCipherPayload(encryptedPayload) {
  if (!esPayloadCifrado(encryptedPayload)) return { valid: false };
  const parts = encryptedPayload.split(':');

  return {
    valid: true,
    algorithm: ALGORITHM,
    ivHex: parts[0],
    ivBytes: parts[0].length / 2,
    authTagHex: parts[1],
    authTagBytes: parts[1].length / 2,
    ciphertextHex: parts[2],
    cipherSizeBytes: parts[2].length / 2
  };
}
