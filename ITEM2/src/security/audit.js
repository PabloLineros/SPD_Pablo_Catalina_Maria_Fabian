import crypto from 'node:crypto';
import { DB, ROLES_BD } from '../db/repository.js';

/**
 * Auditoría de accesos.
 * - Registra QUIÉN (id interno + rol), QUÉ (permiso/acción), SOBRE QUÉ (id de recurso),
 *   RESULTADO y MOTIVO. Nunca registra el contenido de los datos personales.
 * - La tabla audit_log es de solo inserción para la aplicación (sin UPDATE/DELETE en GRANTS).
 */
const bd = DB.conectar(ROLES_BD.SVC_APP);

export function registrarAuditoria({ sesion, accion, recurso = null, resultado, motivo = null }) {
  bd.insertar('audit_log', {
    id: crypto.randomUUID(),
    actor_id: sesion?.usuarioId ?? 'anonimo',
    actor_rol: sesion?.rol ?? 'ANONIMO',
    accion,
    recurso,
    resultado,
    motivo,
    created_at: new Date().toISOString()
  });
}
