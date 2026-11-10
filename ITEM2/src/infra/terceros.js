import crypto from 'node:crypto';
import { DB, ROLES_BD } from '../db/repository.js';

/**
 * Comunicación a terceros que recibieron datos del titular (SIMULADA).
 * En producción cada llamada iría a la API del proveedor (o a un aviso formal por correo):
 *  - PASARELA_PAGO: revocar el token de la tarjeta.
 *  - PLATAFORMA_CORREO: dar de baja o actualizar al suscriptor (identificado por su seudónimo).
 *  - OPERADOR_LOGISTICO: actualizar la dirección de un envío aún no despachado (por ref_envio).
 * Aquí se deja constancia en `comunicaciones_terceros` usando solo referencias internas.
 */

const bd = DB.conectar(ROLES_BD.SVC_APP);

export function comunicarATercero({ tercero, tipo, referencia, solicitudId = null }) {
  return bd.insertar('comunicaciones_terceros', {
    id: crypto.randomUUID(), tercero, tipo, referencia: String(referencia).slice(0, 200),
    solicitud_id: solicitudId, enviado_el: new Date().toISOString()
  });
}
