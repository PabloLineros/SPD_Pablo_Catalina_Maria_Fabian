import crypto from 'node:crypto';
import { DB, ROLES_BD } from '../db/repository.js';
import { firmarSaldo, verificarFirmaSaldo } from '../crypto/integrity.js';
import { autorizar, PERMISOS } from '../security/rbac.js';
import { errores } from '../security/errors.js';
import { validar } from '../security/validation.js';
import { logger } from '../security/logger.js';
import { registrarAuditoria } from '../security/audit.js';

/**
 * Servicio de Fidelización: NortiPuntos
 * Principio: Control de Integridad y Detección de Fraude mediante HMAC-SHA256.
 * El saldo de puntos no es un secreto (el cliente lo visualiza en su cuenta), pero nadie
 * (ni administradores ni atacantes con acceso a la BD) debe poder alterarlo sin invalidar
 * la firma del servidor.
 *
 * Una cuenta es íntegra solo si se cumplen TRES condiciones:
 *  1. HMAC(K_integridad, user_id:version:saldo) coincide con hmac_firma.
 *  2. version == cantidad de movimientos en historial_puntos.
 *  3. saldo == suma de los deltas del historial.
 * La 2 y la 3 detectan la restauración de una fila antigua con su firma (ataque de repetición).
 */

const bd = DB.conectar(ROLES_BD.SVC_APP);
const PUNTOS_POR_CLP = 100; // 1 punto por cada $100

/** Verificación de todas las cuentas (uso interno: comprobaciones antes de recuperar el servicio). */
export function cuentasConIntegridadRota() {
  return bd.seleccionar('loyalty_accounts').filter(c => {
    try {
      cargarCuentaVerificada(c.user_id);
      return false;
    } catch {
      return true;
    }
  }).map(c => c.user_id);
}

function cargarCuentaVerificada(userId) {
  const cuenta = bd.obtener('loyalty_accounts', userId);
  if (!cuenta) throw errores.noEncontrado('Cuenta de puntos');
  const historial = bd.seleccionar('historial_puntos', h => h.user_id === userId);
  const suma = historial.reduce((acc, h) => acc + h.delta, 0);

  const integra =
    verificarFirmaSaldo(userId, cuenta.version, cuenta.saldo_puntos, cuenta.hmac_firma) &&
    cuenta.version === historial.length &&
    cuenta.saldo_puntos === suma;

  if (!integra) {
    logger.error('integridad_puntos_comprometida', { usuarioId: userId });
    registrarAuditoria({ actorId: 'sistema', actorRol: 'SISTEMA', accion: 'seguridad:integridad_puntos', recurso: `loyalty:${userId}`, resultado: 'FALLIDO', motivo: 'FIRMA_O_HISTORIAL_INCONSISTENTE' });
    throw errores.integridad();
  }
  return cuenta;
}

function registrarMovimiento(userId, delta, motivo, cuentaActual) {
  const version = (cuentaActual?.version ?? 0) + 1;
  const saldo = (cuentaActual?.saldo_puntos ?? 0) + delta;
  if (saldo < 0) throw errores.datoInvalido('Saldo de puntos insuficiente.');
  const ahora = new Date().toISOString();

  bd.insertar('historial_puntos', { id: crypto.randomUUID(), user_id: userId, delta, motivo, created_at: ahora });
  const fila = { user_id: userId, saldo_puntos: saldo, version, hmac_firma: firmarSaldo(userId, version, saldo), updated_at: ahora };
  if (cuentaActual) bd.actualizar('loyalty_accounts', userId, fila);
  else bd.insertar('loyalty_accounts', fila);
  return fila;
}

export class LoyaltyService {
  /** Crea la cuenta con puntos de bienvenida (uso interno del registro). */
  static inicializarCuenta(userId, puntosBienvenida = 500) {
    return registrarMovimiento(userId, puntosBienvenida, 'BIENVENIDA', null);
  }

  /** Acredita puntos por una compra (uso interno de OrderService). Falla cerrado si hay manipulación. */
  static acreditarCompra(userId, totalClp) {
    const puntos = Math.floor(totalClp / PUNTOS_POR_CLP);
    if (puntos <= 0) return 0;
    registrarMovimiento(userId, puntos, 'COMPRA', cargarCuentaVerificada(userId));
    return puntos;
  }

  /** Consulta del saldo propio, previa verificación de integridad. */
  static saldoPropio(sesion, userId) {
    autorizar(sesion, PERMISOS.PUNTOS_PROPIOS, { propietarioId: userId, recurso: `loyalty:${userId}` });
    const cuenta = cargarCuentaVerificada(userId);
    return { saldo: cuenta.saldo_puntos, version: cuenta.version, integridad: 'VERIFICADA' };
  }

  /** Canje de puntos propios. */
  static canjear(sesion, userId, puntos) {
    autorizar(sesion, PERMISOS.PUNTOS_PROPIOS, { propietarioId: userId, recurso: `loyalty:${userId}` });
    validar.enteroPositivo(puntos, 'puntos');
    const cuenta = cargarCuentaVerificada(userId);
    if (cuenta.saldo_puntos < puntos) throw errores.datoInvalido('Saldo de puntos insuficiente.');
    const nueva = registrarMovimiento(userId, -puntos, 'CANJE', cuenta);
    return { puntosCanjeados: puntos, nuevoSaldo: nueva.saldo_puntos };
  }
}
