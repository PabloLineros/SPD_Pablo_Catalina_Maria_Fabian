import crypto from 'node:crypto';
import { DB, ROLES_BD } from '../db/repository.js';
import { decryptField, contexto } from '../crypto/cipher.js';
import { enviarCorreo } from '../infra/correo.js';
import { registrarAuditoria } from '../security/audit.js';
import { errores } from '../security/errors.js';

/**
 * Oposición y bloqueo.
 *
 * OPOSICIÓN: el titular se niega a un tratamiento concreto aunque su base NO sea el consentimiento.
 *   Se guarda como marca de exclusión por tratamiento; el proceso la consulta antes de ejecutarse.
 *   Tratamiento oponible implementado: ENCUESTAS_SATISFACCION (correo de encuesta tras la entrega,
 *   base: interés legítimo).
 *
 * BLOQUEO: los datos se conservan pero no se usan para ningún fin, salvo lo estrictamente necesario
 *   (cumplir pedidos en curso, obligaciones legales y atender al propio titular), mientras se aclara
 *   la exactitud o vigencia. Mientras está ACTIVO, el titular queda fuera de: exportación de
 *   marketing, ETL de analítica y encuestas. Se levanta cuando desaparece la causa.
 */

const bd = DB.conectar(ROLES_BD.SVC_APP);

export const TRATAMIENTOS_OPONIBLES = Object.freeze({
  ENCUESTAS_SATISFACCION: 'Encuesta de satisfacción por correo tras la entrega (interés legítimo)'
});
export const MOTIVOS_BLOQUEO = Object.freeze({
  EXACTITUD_EN_DISPUTA: 'El titular discute la exactitud de sus datos',
  VIGENCIA_DUDOSA: 'La vigencia de los datos es dudosa'
});

export function tieneOposicion(userId, tratamiento) {
  return bd.obtener('oposiciones', `${userId}:${tratamiento}`)?.estado === 'ACTIVA';
}

export function bloqueoActivo(userId) {
  return bd.buscarUno('bloqueos', b => b.user_id === userId && b.estado === 'ACTIVO');
}

export function registrarOposicion(userId, tratamiento, solicitudId) {
  if (!(tratamiento in TRATAMIENTOS_OPONIBLES)) {
    throw errores.datoInvalido(`Tratamiento no oponible. Válidos: ${Object.keys(TRATAMIENTOS_OPONIBLES).join(', ')}.`);
  }
  const id = `${userId}:${tratamiento}`;
  const fila = { estado: 'ACTIVA', desde: new Date().toISOString(), retirada_el: null, solicitud_id: solicitudId };
  if (bd.obtener('oposiciones', id)) bd.actualizar('oposiciones', id, fila);
  else bd.insertar('oposiciones', { id, user_id: userId, tratamiento, ...fila });
  return fila;
}

export function registrarBloqueo(userId, motivo, solicitudId) {
  if (!(motivo in MOTIVOS_BLOQUEO)) throw errores.datoInvalido(`Motivo inválido. Válidos: ${Object.keys(MOTIVOS_BLOQUEO).join(', ')}.`);
  if (bloqueoActivo(userId)) throw errores.conflicto('Sus datos ya están bloqueados.');
  return bd.insertar('bloqueos', {
    id: crypto.randomUUID(), user_id: userId, motivo, estado: 'ACTIVO',
    desde: new Date().toISOString(), levantado_el: null, causa_levantamiento: null, solicitud_id: solicitudId
  });
}

/** Levanta el bloqueo cuando desaparece su causa (rectificación, decisión del titular o del DPO). */
export function levantarBloqueo(userId, causa, sesion = null) {
  const b = bloqueoActivo(userId);
  if (!b) return null;
  const fila = bd.actualizar('bloqueos', b.id, { estado: 'LEVANTADO', levantado_el: new Date().toISOString(), causa_levantamiento: causa });
  registrarAuditoria({ sesion, actorId: sesion ? undefined : 'sistema', actorRol: sesion ? undefined : 'SISTEMA', accion: 'derechos:bloqueo:levantado', recurso: `bloqueo:${b.id}`, resultado: 'EXITO', motivo: causa });
  return fila;
}

/**
 * Tratamiento oponible: encuesta de satisfacción tras la entrega. Antes de ejecutarse consulta la
 * oposición y el bloqueo; si alguno aplica, no se envía y queda constancia del motivo.
 */
export function enviarEncuestaSatisfaccion(userId, orderId) {
  let motivo = null;
  if (tieneOposicion(userId, 'ENCUESTAS_SATISFACCION')) motivo = 'OPOSICION_ACTIVA';
  else if (bloqueoActivo(userId)) motivo = 'DATOS_BLOQUEADOS';
  if (!motivo) {
    const u = bd.obtener('users', userId);
    if (!u) return { enviada: false, motivo: 'SIN_CUENTA' };
    enviarCorreo({
      para: decryptField(u.email_cifrado, contexto('users', 'email_cifrado', userId)),
      asunto: 'NortiShop: ¿cómo fue tu compra?',
      cuerpo: 'Tu pedido fue entregado. Cuéntanos cómo te fue en una encuesta de 1 minuto. Si no quieres recibir encuestas, puedes oponerte desde el Centro de privacidad.'
    });
  }
  registrarAuditoria({ actorId: 'sistema', actorRol: 'SISTEMA', accion: 'tratamiento:encuesta_satisfaccion', recurso: `orders:${orderId}`, resultado: motivo ? 'DENEGADO' : 'EXITO', motivo });
  return { enviada: !motivo, motivo };
}
