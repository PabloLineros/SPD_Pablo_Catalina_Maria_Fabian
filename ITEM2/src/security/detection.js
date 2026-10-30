import crypto from 'node:crypto';
import { DB, ROLES_BD } from '../db/repository.js';
import { registrarAuditoria, suscribirEventos } from './audit.js';
import { logger } from './logger.js';

/**
 * Detección de eventos sospechosos sobre el flujo de auditoría.
 *
 * Niveles (ver plan de respuesta a incidentes):
 *  - ALERTA: señal aislada que se revisa en el turno (p. ej. fuerza bruta contra una cuenta).
 *  - EVENTO_SOSPECHOSO: patrón que exige análisis del responsable de seguridad.
 *  - INCIDENTE: solo lo declara una persona con rol SEGURIDAD (incidentService.abrir).
 *
 * Las reglas trabajan con ventanas deslizantes en memoria y guardan en `alertas` solo
 * referencias internas (id de actor o prefijo de cuenta), nunca datos personales.
 */

const MINUTO = 60_000;
export const REGLAS = Object.freeze({
  FUERZA_BRUTA: { nivel: 'ALERTA', severidad: 'MEDIA', umbral: 5, ventana: 15 * MINUTO,
    descripcion: '5 o más inicios de sesión fallidos contra una misma cuenta en 15 minutos' },
  RELLENO_CREDENCIALES: { nivel: 'EVENTO_SOSPECHOSO', severidad: 'ALTA', umbral: 10, ventana: 10 * MINUTO,
    descripcion: '10 o más cuentas distintas con inicio de sesión fallido en 10 minutos' },
  DENEGACIONES_REPETIDAS: { nivel: 'EVENTO_SOSPECHOSO', severidad: 'MEDIA', umbral: 5, ventana: 10 * MINUTO,
    descripcion: '5 o más accesos denegados de un mismo usuario en 10 minutos (posible escalamiento)' },
  REVELACIONES_PII_ANOMALAS: { nivel: 'EVENTO_SOSPECHOSO', severidad: 'ALTA', umbral: 5, ventana: 60 * MINUTO,
    descripcion: '5 o más revelaciones de datos personales completos por un mismo agente en 1 hora' },
  EXPORTACION_ANOMALA: { nivel: 'EVENTO_SOSPECHOSO', severidad: 'MEDIA', umbral: 3, ventana: 24 * 60 * MINUTO,
    descripcion: '3 o más exportaciones masivas o de derechos por un mismo actor en 24 horas' },
  INTEGRIDAD_COMPROMETIDA: { nivel: 'EVENTO_SOSPECHOSO', severidad: 'CRITICA', umbral: 1, ventana: 60 * MINUTO,
    descripcion: 'Se detectó una firma de puntos o un registro de auditoría alterado' }
});

const bd = DB.conectar(ROLES_BD.SVC_APP);
const ventanas = new Map();   // `${regla}|${clave}` -> timestamps (o claves distintas)
const enfriamiento = new Map(); // evita repetir la misma alerta dentro de la ventana

function contar(regla, clave, ts, valor = null) {
  const k = `${regla}|${clave}`;
  const lista = (ventanas.get(k) ?? []).filter(e => ts - e.ts <= REGLAS[regla].ventana);
  lista.push({ ts, valor });
  ventanas.set(k, lista);
  return valor === null ? lista.length : new Set(lista.map(e => e.valor)).size;
}

function emitir(regla, sujeto, detalle, ts) {
  const k = `${regla}|${sujeto}`;
  if (ts - (enfriamiento.get(k) ?? -Infinity) < REGLAS[regla].ventana) return;
  enfriamiento.set(k, ts);
  const def = REGLAS[regla];
  const alerta = bd.insertar('alertas', {
    id: crypto.randomUUID(), regla, nivel: def.nivel, severidad: def.severidad, sujeto,
    detalle, estado: 'ABIERTA', incidente_id: null, created_at: new Date(ts).toISOString()
  });
  logger.warn('alerta_seguridad', { regla, nivel: def.nivel, severidad: def.severidad });
  registrarAuditoria({ actorId: 'sistema', actorRol: 'SISTEMA', accion: 'seguridad:alerta', recurso: `alerta:${alerta.id}`, resultado: 'EXITO', motivo: `${regla} (${def.nivel}, ${def.severidad})` });
}

export function procesarEvento(ev) {
  if (ev.accion.startsWith('seguridad:alerta')) return; // las alertas no se evalúan a sí mismas
  const ts = Date.parse(ev.created_at);

  if (ev.accion === 'auth:login' && ev.resultado === 'FALLIDO') {
    if (contar('FUERZA_BRUTA', ev.actor_id, ts) >= REGLAS.FUERZA_BRUTA.umbral) {
      emitir('FUERZA_BRUTA', ev.actor_id, REGLAS.FUERZA_BRUTA.descripcion, ts);
    }
    if (contar('RELLENO_CREDENCIALES', 'global', ts, ev.actor_id) >= REGLAS.RELLENO_CREDENCIALES.umbral) {
      emitir('RELLENO_CREDENCIALES', 'global', REGLAS.RELLENO_CREDENCIALES.descripcion, ts);
    }
  }
  if (ev.resultado === 'DENEGADO' && ev.actor_id !== 'anonimo') {
    if (contar('DENEGACIONES_REPETIDAS', ev.actor_id, ts) >= REGLAS.DENEGACIONES_REPETIDAS.umbral) {
      emitir('DENEGACIONES_REPETIDAS', ev.actor_id, `${REGLAS.DENEGACIONES_REPETIDAS.descripcion}; rol=${ev.actor_rol}`, ts);
    }
  }
  if (ev.accion === 'clientes:pii:revelar' && ev.resultado === 'PERMITIDO') {
    if (contar('REVELACIONES_PII_ANOMALAS', ev.actor_id, ts) >= REGLAS.REVELACIONES_PII_ANOMALAS.umbral) {
      emitir('REVELACIONES_PII_ANOMALAS', ev.actor_id, REGLAS.REVELACIONES_PII_ANOMALAS.descripcion, ts);
    }
  }
  if (['marketing:exportar', 'copia_desarrollo'].includes(ev.accion) && ev.resultado === 'PERMITIDO' ||
      /^derechos:(acceso|portabilidad):ejecutada$/.test(ev.accion)) {
    if (contar('EXPORTACION_ANOMALA', ev.actor_id, ts) >= REGLAS.EXPORTACION_ANOMALA.umbral) {
      emitir('EXPORTACION_ANOMALA', ev.actor_id, REGLAS.EXPORTACION_ANOMALA.descripcion, ts);
    }
  }
  if ((ev.accion === 'seguridad:integridad_puntos' || ev.accion === 'auditoria:verificacion') && ev.resultado === 'FALLIDO') {
    emitir('INTEGRIDAD_COMPROMETIDA', ev.recurso ?? 'sistema', `${REGLAS.INTEGRIDAD_COMPROMETIDA.descripcion}: ${ev.accion}`, ts);
  }
}

suscribirEventos(procesarEvento);

/** Solo para pruebas y demo: reinicia ventanas y enfriamientos. */
export function reiniciarDeteccion() {
  ventanas.clear();
  enfriamiento.clear();
}
