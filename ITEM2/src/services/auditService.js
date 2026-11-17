import crypto from 'node:crypto';
import { CONFIG } from '../config/env.js';
import { DB, ROLES_BD } from '../db/repository.js';
import { registrarAuditoria, sellar, HASH_GENESIS } from '../security/audit.js';
import { autorizar, PERMISOS } from '../security/rbac.js';
import { errores } from '../security/errors.js';
import { logger, redactarTexto } from '../security/logger.js';
import { soloCampos } from '../security/validation.js';
import { CAMPOS_DATOS, tiposDeDatos } from '../security/catalogoAuditoria.js';

/**
 * Consulta, verificación, anclaje y retención de la auditoría.
 *  - Lectura: solo con el rol de BD rol_auditor y el permiso auditoria:leer
 *    (ADMINISTRADOR, OFICIAL_PRIVACIDAD, SEGURIDAD). Cada consulta queda, a su vez, auditada.
 *  - Verificación: recalcula la cadena de sellos; detecta registros modificados, eliminados,
 *    reordenados o truncados (contra las anclas).
 *  - Retención: ver POLITICA_CONSERVACION. La purga solo borra el tramo inicial vencido, con
 *    svc_retencion, y deja constancia (hasta qué secuencia y con qué hash) para que la cadena siga
 *    siendo verificable. Mientras haya un incidente abierto, no se purga nada posterior a su inicio
 *    (retención extendida o "legal hold").
 *  - Reconstrucción: SEGURIDAD y OFICIAL_PRIVACIDAD, con motivo obligatorio, rearman la línea de tiempo
 *    de un origen, sesión, actor o titular, y obtienen qué titulares y qué datos fueron afectados.
 */

/** Plazos de conservación de los registros de trazabilidad (los aplica purgarVencidos). */
export const POLITICA_CONSERVACION = Object.freeze([
  { registro: 'audit_log', plazo: `${CONFIG.RETENCION_AUDITORIA_DIAS} días (24 meses)`, fundamento: 'Permite investigar incidentes detectados tarde y responder reclamos de titulares sobre accesos pasados.', borra: 'svc_retencion (tramo inicial vencido, con constancia en auditoria_purgas)' },
  { registro: 'alertas', plazo: `${CONFIG.RETENCION_ALERTAS_DIAS} días (24 meses)`, fundamento: 'Mismo plazo que la auditoría de la que derivan; las abiertas no se borran.', borra: 'svc_retencion (solo descartadas o escaladas a un incidente ya cerrado)' },
  { registro: 'evidencias de incidentes', plazo: `${CONFIG.RETENCION_EVIDENCIAS_DIAS} días (5 años) desde el cierre`, fundamento: 'Rendición de cuentas ante la Agencia y eventuales procesos sancionatorios o judiciales.', borra: 'svc_retencion; el incidente y su bitácora (sin datos personales) se conservan' },
  { registro: 'auditoria_anclas y auditoria_purgas', plazo: 'Indefinido', fundamento: 'No contienen datos personales (solo secuencias y hashes) y permiten verificar la cadena tras cada purga.', borra: 'Nadie' },
  { registro: 'logs de aplicación', plazo: `${CONFIG.RETENCION_LOGS_APLICACION_DIAS} días`, fundamento: 'Solo sirven para diagnóstico técnico y ya vienen redactados.', borra: 'Proceso de retención' }
]);

const bdAuditor = DB.conectar(ROLES_BD.ROL_AUDITOR);
const bdRetencion = DB.conectar(ROLES_BD.SVC_RETENCION);
const bdSeguridad = DB.conectar(ROLES_BD.SVC_SEGURIDAD);
const DIA = 86_400_000;
const ESTADOS_CERRADOS = ['CERRADO', 'DESCARTADO'];

/**
 * Retención extendida: si hay incidentes abiertos, no se purga nada desde 24 h antes del inicio del
 * más antiguo (los registros son evidencia). Devuelve la fecha ISO desde la que se retiene, o null.
 */
function retencionPorIncidentes() {
  const abiertos = bdRetencion.seleccionar('incidentes', i => !ESTADOS_CERRADOS.includes(i.estado));
  if (!abiertos.length) return null;
  const inicio = Math.min(...abiertos.map(i => Date.parse(i.ocurrido_desde ?? i.detectado_el)));
  return new Date(inicio - DIA).toISOString();
}

const CAMPOS_LINEA = ['secuencia', 'created_at', 'actor_id', 'actor_rol', 'accion', 'categoria', 'recurso', 'titular_ref', 'datos', 'resultado', 'motivo', 'sesion_ref', 'origen_ref', 'correlacion_id'];
const EXITO = new Set(['EXITO', 'PERMITIDO']);
const CATEGORIAS_CAMBIO = new Set(['MODIFICACION', 'TRANSACCION', 'EXPORTACION', 'SUPRESION', 'CONSENTIMIENTO']);
const unicos = (xs) => [...new Set(xs.filter(Boolean))];

/**
 * Reconstruye lo ocurrido a partir de la auditoría (función pura sobre las filas).
 * 1. Semilla: eventos que coinciden con el origen, la sesión, el actor o el titular indicados.
 * 2. Expansión: todos los eventos de las sesiones que aparecen en la semilla (si el atacante logró
 *    entrar, lo que hizo dentro de la cuenta queda ligado a esa sesión).
 * 3. Resumen: cuentas probadas, cuentas comprometidas, titulares afectados y, por titular, qué
 *    campos personales se expusieron o cambiaron; además, los intentos que los controles frenaron.
 */
export function reconstruirLineaDeTiempo(filas, { origenRef, sesionRef, actorId, titularRef }) {
  const semilla = filas.filter(f => (origenRef && f.origen_ref === origenRef) || (sesionRef && f.sesion_ref === sesionRef) ||
    (actorId && f.actor_id === actorId) || (titularRef && f.titular_ref === titularRef));
  const sesiones = new Set(semilla.map(f => f.sesion_ref).filter(Boolean));
  const ids = new Set(semilla.map(f => f.secuencia));
  const linea = filas.filter(f => ids.has(f.secuencia) || (f.sesion_ref && sesiones.has(f.sesion_ref)))
    .map(f => Object.fromEntries(CAMPOS_LINEA.map(c => [c, f[c] ?? null])));

  const logins = linea.filter(f => f.accion === 'auth:login');
  const fallidos = logins.filter(f => f.resultado === 'FALLIDO');
  const exitosos = logins.filter(f => f.resultado === 'EXITO');
  const conEfecto = linea.filter(f => EXITO.has(f.resultado) && f.titular_ref && f.accion !== 'auth:login');

  const porTitular = {};
  const nuevo = () => ({ campos: new Set(), acciones: new Set() });
  for (const f of conEfecto) {
    const t = (porTitular[f.titular_ref] ??= nuevo());
    for (const c of (f.datos ?? '').split(',').filter(c => c in CAMPOS_DATOS)) t.campos.add(c);
    t.acciones.add(f.accion);
  }
  for (const f of exitosos) (porTitular[f.titular_ref] ??= nuevo()).campos.add('credenciales');
  const titulares = Object.fromEntries(Object.entries(porTitular).map(([t, v]) => [t, {
    campos: [...v.campos].sort(), tipos: tiposDeDatos([...v.campos]).sort(), acciones: [...v.acciones]
  }]));

  return {
    linea_tiempo: linea,
    resumen: {
      eventos: linea.length,
      desde: linea[0]?.created_at ?? null,
      hasta: linea[linea.length - 1]?.created_at ?? null,
      origenes: unicos(linea.map(f => f.origen_ref)),
      sesiones: unicos(linea.map(f => f.sesion_ref)),
      cuentas_probadas: unicos(fallidos.map(f => f.actor_id)).length,
      cuentas_reales_probadas: unicos(fallidos.map(f => f.titular_ref)),
      cuentas_comprometidas: unicos(exitosos.map(f => f.titular_ref)),
      titulares_afectados: Object.keys(titulares),
      titulares,
      tipos_datos: tiposDeDatos(Object.values(titulares).flatMap(t => t.campos)).sort(),
      cambios: linea.filter(f => EXITO.has(f.resultado) && CATEGORIAS_CAMBIO.has(f.categoria))
        .map(({ secuencia, created_at, accion, recurso, titular_ref, datos, motivo }) => ({ secuencia, created_at, accion, recurso, titular_ref, datos, motivo })),
      frenados: linea.filter(f => ['FALLIDO', 'DENEGADO'].includes(f.resultado) && f.accion !== 'auth:login')
        .map(({ secuencia, accion, resultado, motivo }) => ({ secuencia, accion, resultado, motivo }))
    }
  };
}

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
   * Reconstrucción de un incidente a partir de la auditoría. Exige un motivo (p. ej. el incidente)
   * y al menos un pivote; el propio acceso queda auditado.
   */
  static reconstruir(sesion, entrada) {
    autorizar(sesion, PERMISOS.AUDITORIA_RECONSTRUIR, { recurso: 'audit_log' });
    soloCampos(entrada, { obligatorios: ['motivo'], opcionales: ['origenRef', 'sesionRef', 'actorId', 'titularRef', 'desde', 'hasta'] });
    const motivo = String(entrada.motivo).trim();
    if (motivo.length < 10) throw errores.datoInvalido('Indique el motivo de la reconstrucción (mín. 10 caracteres), p. ej. el incidente.');
    const pivotes = ['origenRef', 'sesionRef', 'actorId', 'titularRef'].filter(k => entrada[k]);
    if (!pivotes.length) throw errores.datoInvalido('Indique al menos un pivote: origenRef, sesionRef, actorId o titularRef.');

    const filas = ordenadas().filter(f => (!entrada.desde || f.created_at >= entrada.desde) && (!entrada.hasta || f.created_at <= entrada.hasta));
    const verificacion = verificarCadena();
    const r = reconstruirLineaDeTiempo(filas, entrada);
    registrarAuditoria({ sesion, accion: 'auditoria:reconstruccion', recurso: 'audit_log', resultado: 'EXITO',
      motivo: `${redactarTexto(motivo).slice(0, 120)}; pivotes=${pivotes.join(',')}; eventos=${r.resumen.eventos}` });
    return { integridad: { integra: verificacion.integra, registros: verificacion.registros, problemas: verificacion.problemas.length }, ...r };
  }

  /**
   * Purga por retención (POLITICA_CONSERVACION). Auditoría: solo el tramo inicial vencido, con
   * constancia; nunca si la cadena no está íntegra ni lo posterior al inicio de un incidente abierto.
   * También purga alertas resueltas vencidas, evidencias de incidentes cerrados hace más de 5 años y
   * logs de aplicación de más de 90 días.
   */
  static purgarVencidos(sesion, ahora = new Date()) {
    autorizar(sesion, PERMISOS.AUDITORIA_RETENCION, { recurso: 'audit_log' });
    const verificacion = verificarCadena();
    if (!verificacion.integra) throw errores.conflicto('La auditoría no está íntegra; no se purga hasta investigar.');

    const retenidoDesde = retencionPorIncidentes();
    const vencimiento = new Date(ahora.getTime() - CONFIG.RETENCION_AUDITORIA_DIAS * DIA).toISOString();
    const limite = retenidoDesde && retenidoDesde < vencimiento ? retenidoDesde : vencimiento;
    const filas = ordenadas();
    const vencidas = [];
    for (const f of filas.slice(0, -1)) { // nunca se borra el último registro (cabeza de la cadena)
      if (f.created_at >= limite) break;
      vencidas.push(f);
    }
    const resultado = { purgados: 0, retencionExtendidaDesde: retenidoDesde };
    if (vencidas.length) {
      const ultimaPurgada = vencidas[vencidas.length - 1];
      for (const f of vencidas) bdRetencion.eliminar('audit_log', f.secuencia);
      bdRetencion.insertar('auditoria_purgas', {
        id: crypto.randomUUID(), hasta_secuencia: ultimaPurgada.secuencia, hash_ultimo: ultimaPurgada.hash,
        filas: vencidas.length, ejecutada_el: new Date().toISOString(), actor_id: sesion.usuarioId
      });
      Object.assign(resultado, { purgados: vencidas.length, hastaSecuencia: ultimaPurgada.secuencia });
    }

    // Alertas: solo las ya resueltas (descartadas, o escaladas a un incidente cerrado).
    const cerrados = new Set(bdRetencion.seleccionar('incidentes', i => ESTADOS_CERRADOS.includes(i.estado)).map(i => i.id));
    const limiteAlertas = new Date(ahora.getTime() - CONFIG.RETENCION_ALERTAS_DIAS * DIA).toISOString();
    const alertas = bdRetencion.seleccionar('alertas', a => a.created_at < limiteAlertas && (a.estado === 'DESCARTADA' || (a.estado === 'ESCALADA' && cerrados.has(a.incidente_id))));
    for (const a of alertas) bdRetencion.eliminar('alertas', a.id);

    // Evidencias: 5 años desde el cierre del incidente.
    const limiteEvidencias = new Date(ahora.getTime() - CONFIG.RETENCION_EVIDENCIAS_DIAS * DIA).toISOString();
    const vencidosInc = new Set(bdRetencion.seleccionar('incidentes', i => ESTADOS_CERRADOS.includes(i.estado) && i.cerrado_el && i.cerrado_el < limiteEvidencias).map(i => i.id));
    const evidencias = bdRetencion.seleccionar('evidencias', e => vencidosInc.has(e.incidente_id));
    for (const e of evidencias) bdRetencion.eliminar('evidencias', e.id);

    const vencenLogs = new Date(ahora.getTime() - CONFIG.RETENCION_LOGS_APLICACION_DIAS * DIA).toISOString();
    const logsAplicacion = logger.purgar(retenidoDesde && retenidoDesde < vencenLogs ? retenidoDesde : vencenLogs);
    Object.assign(resultado, { alertas: alertas.length, evidencias: evidencias.length, logsAplicacion });

    const detalle = [`auditoria=${resultado.purgados}`, `alertas=${alertas.length}`, `evidencias=${evidencias.length}`, `logs=${logsAplicacion}`];
    if (retenidoDesde) detalle.push(`retencion_extendida_desde=${retenidoDesde}`);
    registrarAuditoria({ sesion, accion: 'auditoria:purga', recurso: 'audit_log', resultado: 'EXITO', motivo: detalle.join('; ') });
    return resultado;
  }
}
