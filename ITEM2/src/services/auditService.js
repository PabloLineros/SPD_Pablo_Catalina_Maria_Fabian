import crypto from 'node:crypto';
import { CONFIG } from '../config/env.js';
import { DB, ROLES_BD } from '../db/repository.js';
import { registrarAuditoria, sellar, HASH_GENESIS } from '../security/audit.js';
import { autorizar, PERMISOS } from '../security/rbac.js';
import { errores } from '../security/errors.js';

/**
 * Consulta, verificación, anclaje y retención de la auditoría.
 *  - Lectura: solo con el rol de BD rol_auditor y el permiso auditoria:leer
 *    (ADMINISTRADOR, OFICIAL_PRIVACIDAD, SEGURIDAD). Cada consulta queda, a su vez, auditada.
 *  - Verificación: recalcula la cadena de sellos; detecta registros modificados, eliminados,
 *    reordenados o truncados (contra las anclas).
 *  - Retención: 24 meses. La purga solo borra el tramo inicial vencido, con svc_retencion, y deja
 *    constancia (hasta qué secuencia y con qué hash) para que la cadena siga siendo verificable.
 */

const bdAuditor = DB.conectar(ROLES_BD.ROL_AUDITOR);
const bdRetencion = DB.conectar(ROLES_BD.SVC_RETENCION);
const bdSeguridad = DB.conectar(ROLES_BD.SVC_SEGURIDAD);

const ordenadas = () => bdAuditor.seleccionar('audit_log').sort((a, b) => a.secuencia - b.secuencia);

/** Verificación de integridad de toda la auditoría (uso interno: recuperación y evidencias). */
export function verificarCadena() {
  const filas = ordenadas();
  const purgas = bdAuditor.seleccionar('auditoria_purgas');
  const anclas = bdAuditor.seleccionar('auditoria_anclas');
  const problemas = [];

  let previo = HASH_GENESIS;
  let esperada = 1;
  if (filas.length && filas[0].secuencia !== 1) {
    const purga = purgas.find(p => p.hasta_secuencia === filas[0].secuencia - 1);
    if (purga) {
      previo = purga.hash_ultimo;
      esperada = filas[0].secuencia;
    } else {
      problemas.push({ secuencia: 1, problema: 'Faltan registros iniciales sin constancia de purga.' });
      previo = filas[0].hash_previo;
      esperada = filas[0].secuencia;
    }
  }
  for (const f of filas) {
    if (f.secuencia !== esperada) problemas.push({ secuencia: esperada, problema: `Falta el registro ${esperada} (eliminado).` });
    if (f.hash_previo !== previo) problemas.push({ secuencia: f.secuencia, problema: 'El encadenamiento con el registro anterior está roto.' });
    if (sellar(f) !== f.hash) problemas.push({ secuencia: f.secuencia, problema: 'El contenido del registro fue modificado.' });
    previo = f.hash;
    esperada = f.secuencia + 1;
  }
  const ultima = filas[filas.length - 1]?.secuencia ?? 0;
  for (const a of anclas) {
    const fila = filas.find(f => f.secuencia === a.secuencia);
    if (a.secuencia > ultima) problemas.push({ secuencia: a.secuencia, problema: 'Faltan registros finales (truncamiento detectado por ancla).' });
    else if (fila && fila.hash !== a.hash) problemas.push({ secuencia: a.secuencia, problema: 'El registro no coincide con el ancla.' });
  }
  return { integra: problemas.length === 0, registros: filas.length, ultimaSecuencia: ultima, problemas };
}

/** Guarda la cabeza de la cadena en una tabla de solo inserción (simula un almacenamiento WORM). */
export function anclarAuditoria() {
  const filas = ordenadas();
  const ultima = filas[filas.length - 1];
  if (!ultima) return null;
  return bdSeguridad.insertar('auditoria_anclas', { id: crypto.randomUUID(), secuencia: ultima.secuencia, hash: ultima.hash, created_at: new Date().toISOString() });
}

/** Eventos de un rango de tiempo (uso interno: preservación de evidencias). */
export function eventosEntre(desde, hasta) {
  return ordenadas().filter(f => (!desde || f.created_at >= desde) && (!hasta || f.created_at <= hasta));
}

export class AuditService {
  static consultar(sesion, filtros = {}) {
    autorizar(sesion, PERMISOS.AUDITORIA_LEER, { recurso: 'audit_log' });
    const { categoria, actorId, accion, resultado, desde, hasta, limite = 50 } = filtros ?? {};
    const filas = ordenadas().filter(f =>
      (!categoria || f.categoria === categoria) && (!actorId || f.actor_id === actorId) &&
      (!accion || f.accion.startsWith(accion)) && (!resultado || f.resultado === resultado) &&
      (!desde || f.created_at >= desde) && (!hasta || f.created_at <= hasta));
    registrarAuditoria({ sesion, accion: 'auditoria:consulta', recurso: 'audit_log', resultado: 'EXITO', motivo: `filtros=${Object.keys(filtros ?? {}).join(',') || 'ninguno'}; filas=${filas.length}` });
    return filas.slice(-Math.min(Math.max(1, limite), 500));
  }

  static verificar(sesion) {
    autorizar(sesion, PERMISOS.AUDITORIA_LEER, { recurso: 'audit_log' });
    const r = verificarCadena();
    registrarAuditoria({ sesion, accion: 'auditoria:verificacion', recurso: 'audit_log', resultado: r.integra ? 'EXITO' : 'FALLIDO', motivo: `registros=${r.registros}; problemas=${r.problemas.length}` });
    return r;
  }

  /**
   * Purga segura por retención: borra solo registros con más de RETENCION_AUDITORIA_DIAS desde el
   * inicio de la cadena (tramo contiguo), deja constancia y audita la propia purga.
   */
  static purgarVencidos(sesion, ahora = new Date()) {
    autorizar(sesion, PERMISOS.AUDITORIA_RETENCION, { recurso: 'audit_log' });
    const verificacion = verificarCadena();
    if (!verificacion.integra) throw errores.conflicto('La auditoría no está íntegra; no se purga hasta investigar.');

    const limite = new Date(ahora.getTime() - CONFIG.RETENCION_AUDITORIA_DIAS * 86_400_000).toISOString();
    const filas = ordenadas();
    const vencidas = [];
    for (const f of filas.slice(0, -1)) { // nunca se borra el último registro (cabeza de la cadena)
      if (f.created_at >= limite) break;
      vencidas.push(f);
    }
    if (vencidas.length === 0) return { purgados: 0 };

    const ultimaPurgada = vencidas[vencidas.length - 1];
    for (const f of vencidas) bdRetencion.eliminar('audit_log', f.secuencia);
    bdRetencion.insertar('auditoria_purgas', {
      id: crypto.randomUUID(), hasta_secuencia: ultimaPurgada.secuencia, hash_ultimo: ultimaPurgada.hash,
      filas: vencidas.length, ejecutada_el: new Date().toISOString(), actor_id: sesion.usuarioId
    });
    registrarAuditoria({ sesion, accion: 'auditoria:purga', recurso: 'audit_log', resultado: 'EXITO', motivo: `hasta_secuencia=${ultimaPurgada.secuencia}; filas=${vencidas.length}` });
    return { purgados: vencidas.length, hastaSecuencia: ultimaPurgada.secuencia };
  }
}
