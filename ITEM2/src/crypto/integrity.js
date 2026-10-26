import crypto from 'node:crypto';
import { usarLlave, FINALIDADES } from './keyring.js';

/**
 * Módulo Criptográfico: Integridad y Autenticidad mediante HMAC-SHA256
 * Principio: Se utiliza cuando el dato no necesariamente debe ser secreto en sí mismo
 * (ej. el saldo de NortiPuntos del cliente es un número visible en pantalla), pero
 * DEBE evitarse cualquier manipulación o fraude por parte de actores maliciosos o
 * inyecciones directas en la base de datos.
 */

/**
 * Calcula HMAC-SHA256 de un mensaje con la llave de la finalidad indicada.
 * @param {string} finalidad Una de FINALIDADES (cada uso tiene su propia llave).
 * @param {string} mensaje
 * @returns {string} 64 caracteres hexadecimales.
 */
export function hmacHex(finalidad, mensaje) {
  return crypto.createHmac('sha256', usarLlave(finalidad)).update(String(mensaje), 'utf8').digest('hex');
}

/**
 * Comparación en tiempo constante de dos HMAC hexadecimales.
 */
export function compararHmac(esperado, provisto) {
  if (typeof provisto !== 'string' || !/^[0-9a-f]{64}$/.test(provisto)) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(esperado, 'hex'), Buffer.from(provisto, 'hex'));
}

/**
 * Firma el estado de una cuenta de puntos. La VERSIÓN forma parte del mensaje: cada
 * movimiento incrementa la versión, y el servicio exige que coincida con el número de
 * movimientos del historial. Así, restaurar una fila antigua (saldo + firma válidos de
 * una versión anterior) queda en evidencia.
 */
export function firmarSaldo(userId, version, saldo) {
  return hmacHex(FINALIDADES.INTEGRIDAD, `${userId}:${version}:${saldo}`);
}

export function verificarFirmaSaldo(userId, version, saldo, firma) {
  return compararHmac(firmarSaldo(userId, version, saldo), firma);
}
