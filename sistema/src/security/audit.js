import crypto from 'node:crypto';
import { DB, ROLES_BD } from '../db/repository.js';
import { hmacHex } from '../crypto/integrity.js';
import { FINALIDADES } from '../crypto/keyring.js';
import { redactarTexto, logger } from './logger.js';
import { definicionEvento, CAMPOS_DATOS } from './catalogoAuditoria.js';
import { contextoActual } from './contexto.js';

/**
 * Registro de auditoría.
 *
 * QUÉ SE REGISTRA (ver security/catalogoAuditoria.js): quién (id interno + rol), qué (acción y
 * categoría del catálogo), sobre qué recurso y de qué titular, qué campos personales se tocaron
 * (solo sus nombres), cuándo, resultado, motivo, y desde dónde (sesión, origen seudonimizado y
 * correlación de la solicitud).
 * QUÉ NO SE REGISTRA: contraseñas, tokens de sesión o de pago, llaves, códigos de verificación,
 * criptogramas, ni el contenido de los datos personales (nombre, email, dirección, valores
 * rectificados...). Recurso y motivo pasan además por la redacción automática del logger.
 *
 * PROTECCIÓN:
 *  - La aplicación (svc_app) solo puede INSERTAR; no puede leer, modificar ni borrar.
 *  - Cada fila se sella con HMAC(K_auditoria, hash_previo + contenido) en un disparador de la BD:
 *    modificar, borrar o reordenar registros rompe la cadena (ver auditService.verificarCadena).
 *  - Anclas periódicas (secuencia + hash) en una tabla de solo inserción detectan el truncamiento.
 */

export const HASH_GENESIS = '0'.repeat(64);

const CAMPOS_SELLADOS = ['secuencia', 'id', 'created_at', 'actor_id', 'actor_rol', 'accion', 'categoria', 'recurso',
  'titular_ref', 'datos', 'resultado', 'motivo', 'sesion_ref', 'origen_ref', 'correlacion_id', 'hash_previo'];

export function sellar(fila) {
  return hmacHex(FINALIDADES.AUDITORIA, JSON.stringify(CAMPOS_SELLADOS.map(c => fila[c] ?? null)));
}

// Disparador BEFORE INSERT: la secuencia y el sello los asigna la base, no quien inserta.
DB.registrarDisparador('audit_log', (fila, ultima) => {
  const completa = {
    ...fila,
    secuencia: (ultima?.secuencia ?? 0) + 1,
    hash_previo: ultima?.hash ?? HASH_GENESIS
  };
  completa.hash = sellar(completa);
  return completa;
});

function clasificar(accion, resultado) {
  const def = definicionEvento(accion, resultado);
  if (!def) logger.error('evento_no_catalogado', { accion });
  return def ?? { categoria: 'NO_CATALOGADO', datos: [] };
}

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const RECURSO_TITULAR = new RegExp(`^(?:users|cuenta|loyalty|orders:user|consentimiento:[A-Z_]+):(${UUID})$`);
/** Si no se indica el titular, se deduce del recurso cuando este es un usuario (users:<uuid>...). */
const titularDe = (recurso) => (recurso ? RECURSO_TITULAR.exec(recurso)?.[1] ?? null : null);

const bd = DB.conectar(ROLES_BD.SVC_APP);
const suscriptores = [];

/** Permite que el motor de detección reciba cada evento (sin acoplar auditoría y detección). */
export function suscribirEventos(fn) {
  suscriptores.push(fn);
}

/**
 * @param {{sesion?:object, actorId?:string, actorRol?:string, accion:string, recurso?:string,
 *          titular?:string, datos?:string[], resultado:'PERMITIDO'|'DENEGADO'|'EXITO'|'FALLIDO',
 *          motivo?:string, sesionRef?:string}} evento
 * `datos` son NOMBRES de campos del vocabulario del catálogo; si se omite, se usan los del catálogo.
 */
export function registrarAuditoria({ sesion, actorId, actorRol, accion, recurso = null, titular, datos, resultado, motivo = null, sesionRef }) {
  const def = clasificar(accion, resultado);
  const ctx = contextoActual();
  // Los eventos del sistema (alertas, procesos) conservan la correlación con la solicitud que los
  // disparó, pero no heredan la sesión ni el origen del usuario: no son acciones suyas.
  const delSistema = (actorRol ?? sesion?.rol) === 'SISTEMA';
  const campos = resultado === 'DENEGADO' ? [] : (datos ?? def.datos);
  const fila = bd.insertar('audit_log', {
    id: crypto.randomUUID(),
    created_at: new Date().toISOString(),
    actor_id: actorId ?? sesion?.usuarioId ?? 'anonimo',
    actor_rol: actorRol ?? sesion?.rol ?? 'ANONIMO',
    accion,
    categoria: def.categoria,
    recurso: recurso === null ? null : redactarTexto(recurso).slice(0, 200),
    titular_ref: titular ?? titularDe(recurso),
    datos: campos.length ? campos.filter(c => c in CAMPOS_DATOS).join(',') || null : null,
    resultado,
    motivo: motivo === null ? null : redactarTexto(motivo).slice(0, 300),
    sesion_ref: delSistema ? null : sesionRef ?? sesion?.sesionRef ?? ctx.sesionRef ?? null,
    origen_ref: delSistema ? null : ctx.origenRef ?? null,
    correlacion_id: ctx.correlacionId ?? null
  });
  for (const fn of suscriptores) fn(fila);
  return fila;
}
