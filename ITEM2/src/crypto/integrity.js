import crypto from 'node:crypto';
import { CONFIG } from '../config/env.js';

/**
 * Módulo Criptográfico: Integridad y Autenticidad mediante HMAC-SHA256
 * Principio: Se utiliza cuando el dato no necesariamente debe ser secreto en sí mismo
 * (ej. el saldo de NortiPuntos del cliente es un número visible en pantalla), pero
 * DEBE evitarse cualquier manipulación o fraude por parte de actores maliciosos o
 * inyecciones directas en la base de datos.
 */

/**
 * Genera un código HMAC-SHA256 sobre una carga de datos y un identificador de contexto.
 * @param {string|number|object} data Información a proteger (ej. saldo de puntos o payload).
 * @param {string} context Identificador contextual (ej. userId o id_transaccion).
 * @returns {string} Firma HMAC en formato hexadecimal (64 caracteres hex).
 */
export function generateHMAC(data, context = '') {
  const serialized = typeof data === 'object' ? JSON.stringify(data) : String(data);
  const message = `${context}:${serialized}`;

  const hmac = crypto.createHmac('sha256', CONFIG.HMAC_SECRET);
  hmac.update(message, 'utf8');
  return hmac.digest('hex');
}

/**
 * Verifica la autenticidad e integridad de un dato contra un código HMAC provisto.
 * Utiliza comparación de tiempo constante (timingSafeEqual) para mitigar Timing Attacks.
 * @param {string|number|object} data Información actual.
 * @param {string} context Identificador de contexto.
 * @param {string} providedHmac Firma HMAC almacenada o recibida.
 * @returns {boolean} True si la firma es matemáticamente válida, False si fue alterado.
 */
export function verifyHMAC(data, context, providedHmac) {
  if (!providedHmac || typeof providedHmac !== 'string') {
    return false;
  }

  const expectedHmac = generateHMAC(data, context);
  const expectedBuffer = Buffer.from(expectedHmac, 'hex');
  const providedBuffer = Buffer.from(providedHmac, 'hex');

  // Si las longitudes difieren, se descarta de inmediato
  if (expectedBuffer.length !== providedBuffer.length) {
    return false;
  }

  // Comparación segura en tiempo constante
  return crypto.timingSafeEqual(expectedBuffer, providedBuffer);
}
