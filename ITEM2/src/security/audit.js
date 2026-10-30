import crypto from 'node:crypto';
import { DB, ROLES_BD } from '../db/repository.js';
import { hmacHex } from '../crypto/integrity.js';
import { FINALIDADES } from '../crypto/keyring.js';
import { redactarTexto } from './logger.js';

/**
 * Registro de auditoría.
 *
 * QUÉ SE REGISTRA: quién (id interno + rol), qué (acción y categoría), sobre qué (tipo:id del
 * recurso), cuándo, resultado y motivo.
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

const CAMPOS_SELLADOS = ['secuencia', 'id', 'created_at', 'actor_id', 'actor_rol', 'accion', 'categoria', 'recurso', 'resultado', 'motivo', 'hash_previo'];

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

const REGLAS_CATEGORIA = [
  [/^auth:/, 'AUTENTICACION'],
  [/^consentimiento/, 'CONSENTIMIENTO'],
  [/^derechos:(acceso|portabilidad):ejecutada/, 'EXPORTACION'],
  [/^derechos:supresion:ejecutada/, 'SUPRESION'],
  [/^derechos:rectificacion:ejecutada|^perfil:propio:editar/, 'MODIFICACION'],
  [/^derechos:/, 'DERECHOS'], // recepción, verificación, rechazo y anulación de solicitudes
  [/^clientes:pii:revelar|^envios:etiqueta|^seudonimos:revertir|^perfil:propio:leer/, 'ACCESO_SENSIBLE'],
  [/^marketing:exportar|^copia_desarrollo/, 'EXPORTACION'],
  [/^roles:|^catalogo:|^pedidos:/, 'ADMINISTRACION'],
  [/^etl:|^job:/, 'PROCESO_PRIVACIDAD'],
  [/^seguridad:|^incidente:|^contencion:|^recuperacion:/, 'SEGURIDAD'],
  [/^auditoria:/, 'AUDITORIA']
];

function categoriaDe(accion, resultado) {
  if (resultado === 'DENEGADO') return 'CONTROL_ACCESO';
  return REGLAS_CATEGORIA.find(([re]) => re.test(accion))?.[1] ?? 'OPERACION';
}

const bd = DB.conectar(ROLES_BD.SVC_APP);
const suscriptores = [];

/** Permite que el motor de detección reciba cada evento (sin acoplar auditoría y detección). */
export function suscribirEventos(fn) {
  suscriptores.push(fn);
}

/**
 * @param {{sesion?:object, actorId?:string, actorRol?:string, accion:string, recurso?:string,
 *          resultado:'PERMITIDO'|'DENEGADO'|'EXITO'|'FALLIDO', motivo?:string}} evento
 */
export function registrarAuditoria({ sesion, actorId, actorRol, accion, recurso = null, resultado, motivo = null }) {
  const fila = bd.insertar('audit_log', {
    id: crypto.randomUUID(),
    created_at: new Date().toISOString(),
    actor_id: actorId ?? sesion?.usuarioId ?? 'anonimo',
    actor_rol: actorRol ?? sesion?.rol ?? 'ANONIMO',
    accion,
    categoria: categoriaDe(accion, resultado),
    recurso: recurso === null ? null : redactarTexto(recurso).slice(0, 200),
    resultado,
    motivo: motivo === null ? null : redactarTexto(motivo).slice(0, 300)
  });
  for (const fn of suscriptores) fn(fila);
  return fila;
}
