import crypto from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { referenciaOrigen } from '../crypto/pseudonymization.js';

/**
 * Contexto de la solicitud en curso, para la trazabilidad.
 *
 * Cada evento de auditoría se asocia, sin que cada servicio tenga que pasarlo a mano, a:
 *  - origen_ref:     seudónimo HMAC del origen de red (la IP NO se guarda).
 *  - correlacion_id: identificador aleatorio de la solicitud; agrupa todos los eventos que produjo.
 *  - sesion_ref:     prefijo del SHA-256 del token de sesión (el token no se guarda).
 *
 * El servidor HTTP abre el contexto con la IP del socket (conOrigen); la API agrega la
 * correlación y la sesión. La demo, el simulacro y las pruebas usan conOrigen con IPs de
 * documentación (RFC 5737), nunca IPs reales.
 */

const almacen = new AsyncLocalStorage();

/** Ejecuta fn asociando los eventos que produzca al origen de red indicado. */
export function conOrigen(ip, fn) {
  return almacen.run({ ...(almacen.getStore() ?? {}), origenRef: referenciaOrigen(ip) }, fn);
}

/** Abre el contexto de una operación de la API (hereda el origen si existe). */
export function enSolicitud(operacion, fn) {
  return almacen.run({ ...(almacen.getStore() ?? {}), operacion, correlacionId: crypto.randomUUID(), sesionRef: null }, fn);
}

/** Asocia la sesión ya validada a la solicitud en curso. */
export function fijarSesion(sesionRef) {
  const store = almacen.getStore();
  if (store) store.sesionRef = sesionRef ?? null;
}

export function contextoActual() {
  return almacen.getStore() ?? {};
}
