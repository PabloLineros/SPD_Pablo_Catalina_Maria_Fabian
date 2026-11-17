import crypto from 'node:crypto';
import { CONFIG } from '../config/env.js';
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
 * Reglas GENÉRICAS (etapa anterior) y reglas PROPIAS de NortiShop (`propia: true`), que usan los
 * campos de trazabilidad de cada registro (sesión, origen seudonimizado, titular, datos tocados).
 * Las ventanas viven en memoria y en `alertas` se guardan solo referencias internas, nunca datos personales.
 */

const MINUTO = 60_000;
const HORA = 60 * MINUTO;
export const REGLAS = Object.freeze({
  FUERZA_BRUTA: { nivel: 'ALERTA', severidad: 'MEDIA', umbral: 5, ventana: 15 * MINUTO,
    descripcion: '5 o más inicios de sesión fallidos contra una misma cuenta en 15 minutos' },
  RELLENO_CREDENCIALES: { nivel: 'EVENTO_SOSPECHOSO', severidad: 'ALTA', umbral: 10, ventana: 10 * MINUTO,
    descripcion: '10 o más cuentas distintas con inicio de sesión fallido en 10 minutos (por origen, si se conoce)' },
  DENEGACIONES_REPETIDAS: { nivel: 'EVENTO_SOSPECHOSO', severidad: 'MEDIA', umbral: 5, ventana: 10 * MINUTO,
    descripcion: '5 o más accesos denegados de un mismo usuario en 10 minutos (posible escalamiento)' },
  REVELACIONES_PII_ANOMALAS: { nivel: 'EVENTO_SOSPECHOSO', severidad: 'ALTA', umbral: 5, ventana: HORA,
    descripcion: '5 o más revelaciones de datos personales completos por un mismo agente en 1 hora' },
  EXPORTACION_ANOMALA: { nivel: 'EVENTO_SOSPECHOSO', severidad: 'MEDIA', umbral: 3, ventana: 24 * HORA,
    descripcion: '3 o más exportaciones masivas o de derechos por un mismo actor en 24 horas' },
  INTEGRIDAD_COMPROMETIDA: { nivel: 'EVENTO_SOSPECHOSO', severidad: 'CRITICA', umbral: 1, ventana: HORA,
    descripcion: 'Se detectó una firma de puntos o un registro de auditoría alterado' },

  // ---- Alertas propias de NortiShop (actividad de trazabilidad) ----
  TOMA_DE_CUENTA: { propia: true, nivel: 'EVENTO_SOSPECHOSO', severidad: 'ALTA', umbral: 1, ventana: HORA,
    descripcion: 'Inicio de sesión de un cliente desde un origen nunca visto para su cuenta y, en esa misma sesión y dentro de 1 hora, cambio de dirección o teléfono, compra con la tarjeta guardada o pedido de copia de sus datos' },
  ETIQUETAS_ANOMALAS: { propia: true, nivel: 'EVENTO_SOSPECHOSO', severidad: 'MEDIA', umbral: 15, ventana: HORA,
    descripcion: 'Logística genera 15 o más etiquetas (nombre y dirección en claro) en 1 hora, o la etiqueta de un envío ya entregado o cancelado' },
  TICKET_REUTILIZADO: { propia: true, nivel: 'EVENTO_SOSPECHOSO', severidad: 'ALTA', umbral: 3, ventana: 24 * HORA,
    descripcion: 'Un mismo ticket de soporte se usa para revelar los datos completos de 3 o más clientes distintos en 24 horas' },
  ACCESO_FUERA_DE_HORARIO: { propia: true, nivel: 'ALERTA', severidad: 'MEDIA', umbral: 1, ventana: HORA,
    descripcion: 'Personal accede a datos personales completos (revelar, etiqueta, revertir seudónimo, exportar) fuera del horario laboral (lun-sáb 08:00-21:00, hora de Chile)' }
});

/** Acciones del personal que exponen datos personales completos (para ACCESO_FUERA_DE_HORARIO). */
const ACCIONES_DATOS_COMPLETOS = new Set(['clientes:pii:revelar', 'envios:etiqueta', 'seudonimos:revertir', 'marketing:exportar', 'copia_desarrollo', 'derechos:localizar']);
const ROLES_NO_PERSONAL = new Set(['CLIENTE', 'ANONIMO', 'SISTEMA']);

const bd = DB.conectar(ROLES_BD.SVC_APP);
const ventanas = new Map();          // `${regla}|${clave}` -> [{ts, valor}]
const enfriamiento = new Map();      // evita repetir la misma alerta dentro de la ventana
const origenesConocidos = new Map(); // titular -> Set(origen_ref) desde donde ya operó
const sesionesNuevoOrigen = new Map(); // sesion_ref -> { ts, titular, origen }

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
  registrarAuditoria({ actorId: 'sistema', actorRol: 'SISTEMA', accion: 'seguridad:alerta', recurso: `alerta:${alerta.id}`, resultado: 'EXITO', motivo: `${regla} (${def.nivel}, ${def.severidad}); sujeto=${sujeto}` });
}

/** ¿El instante cae fuera del horario laboral (en la zona horaria de Chile)? */
export function fueraDeHorario(ts, horario = CONFIG.HORARIO_LABORAL) {
  const partes = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone: horario.zona, weekday: 'short', hour: 'numeric', hourCycle: 'h23' })
    .formatToParts(new Date(ts)).map(p => [p.type, p.value]));
  const dia = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(partes.weekday);
  const hora = Number(partes.hour);
  return !horario.dias.includes(dia) || hora < horario.desde || hora >= horario.hasta;
}

/** Acciones de una sesión que, tras entrar desde un origen nuevo, indican una toma de cuenta. */
function accionDeTomaDeCuenta(ev) {
  if (ev.resultado === 'DENEGADO' || ev.resultado === 'FALLIDO') return false;
  if (ev.accion === 'perfil:propio:editar') return /(^|,)(direccion|telefono|comuna)(,|$)/.test(ev.datos ?? '');
  if (ev.accion === 'pedido:crear') return /medio=TOKEN_GUARDADO/.test(ev.motivo ?? '');
  return /^derechos:(acceso|portabilidad):recibida$/.test(ev.accion);
}

function reglasTomaDeCuenta(ev, ts) {
  if (ev.accion === 'auth:registro' && ev.origen_ref) {
    origenesConocidos.set(ev.titular_ref, new Set([ev.origen_ref]));
    return;
  }
  if (ev.accion === 'auth:login' && ev.resultado === 'EXITO' && ev.actor_rol === 'CLIENTE' && ev.origen_ref) {
    const conocidos = origenesConocidos.get(ev.actor_id);
    if (conocidos?.size && !conocidos.has(ev.origen_ref) && ev.sesion_ref) {
      sesionesNuevoOrigen.set(ev.sesion_ref, { ts, titular: ev.actor_id, origen: ev.origen_ref });
    }
    origenesConocidos.set(ev.actor_id, new Set([...(conocidos ?? []), ev.origen_ref]));
    return;
  }
  const marca = ev.sesion_ref ? sesionesNuevoOrigen.get(ev.sesion_ref) : null;
  if (marca && ts - marca.ts <= REGLAS.TOMA_DE_CUENTA.ventana && accionDeTomaDeCuenta(ev)) {
    emitir('TOMA_DE_CUENTA', marca.titular, `${REGLAS.TOMA_DE_CUENTA.descripcion}; sesion=${ev.sesion_ref}; origen=${marca.origen}; accion=${ev.accion}`, ts);
  }
}

export function procesarEvento(ev) {
  if (ev.accion.startsWith('seguridad:alerta')) return; // las alertas no se evalúan a sí mismas
  const ts = Date.parse(ev.created_at);

  if (ev.accion === 'auth:login' && ev.resultado === 'FALLIDO') {
    if (contar('FUERZA_BRUTA', ev.actor_id, ts) >= REGLAS.FUERZA_BRUTA.umbral) {
      emitir('FUERZA_BRUTA', ev.actor_id, REGLAS.FUERZA_BRUTA.descripcion, ts);
    }
    // Con origen conocido, el relleno se cuenta por origen: la alerta apunta al atacante, no al sistema entero.
    const origen = ev.origen_ref ?? 'global';
    if (contar('RELLENO_CREDENCIALES', origen, ts, ev.actor_id) >= REGLAS.RELLENO_CREDENCIALES.umbral) {
      emitir('RELLENO_CREDENCIALES', origen, REGLAS.RELLENO_CREDENCIALES.descripcion, ts);
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
    const ticket = /^(TCK-\d+)/.exec(ev.motivo ?? '')?.[1];
    if (ticket && contar('TICKET_REUTILIZADO', ticket, ts, ev.titular_ref) >= REGLAS.TICKET_REUTILIZADO.umbral) {
      emitir('TICKET_REUTILIZADO', ev.actor_id, `${REGLAS.TICKET_REUTILIZADO.descripcion}; ticket=${ticket}`, ts);
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

  // ---- Reglas propias de NortiShop ----
  reglasTomaDeCuenta(ev, ts);

  if (ev.accion === 'envios:etiqueta' && ev.resultado === 'PERMITIDO') {
    const sinNecesidad = /estado_envio=(ENTREGADO|CANCELADO)/.exec(ev.motivo ?? '')?.[1];
    if (sinNecesidad) {
      emitir('ETIQUETAS_ANOMALAS', ev.actor_id, `Etiqueta de un envío ${sinNecesidad} (sin necesidad operativa); ${ev.recurso}`, ts);
    } else if (contar('ETIQUETAS_ANOMALAS', ev.actor_id, ts) >= REGLAS.ETIQUETAS_ANOMALAS.umbral) {
      emitir('ETIQUETAS_ANOMALAS', ev.actor_id, `${REGLAS.ETIQUETAS_ANOMALAS.umbral} o más etiquetas en 1 hora`, ts);
    }
  }

  if (ACCIONES_DATOS_COMPLETOS.has(ev.accion) && ['PERMITIDO', 'EXITO'].includes(ev.resultado) &&
      !ROLES_NO_PERSONAL.has(ev.actor_rol) && fueraDeHorario(ts)) {
    emitir('ACCESO_FUERA_DE_HORARIO', ev.actor_id, `${ev.accion} fuera del horario laboral; rol=${ev.actor_rol}`, ts);
  }
}

suscribirEventos(procesarEvento);

/** Solo para pruebas y demo: reinicia ventanas, enfriamientos y orígenes conocidos. */
export function reiniciarDeteccion() {
  ventanas.clear();
  enfriamiento.clear();
  origenesConocidos.clear();
  sesionesNuevoOrigen.clear();
}
