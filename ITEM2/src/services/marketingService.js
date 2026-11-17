import { DB, ROLES_BD } from '../db/repository.js';
import { decryptField, contexto } from '../crypto/cipher.js';
import { autorizar, PERMISOS } from '../security/rbac.js';
import { registrarAuditoria } from '../security/audit.js';
import { errores } from '../security/errors.js';

/**
 * Marketing con consentimiento explícito (opt-in, desmarcado por defecto).
 * - El consentimiento (fecha, versión, estado, historial) lo gestiona consentService; aquí solo
 *   existe la lista de envío, que contiene a un titular únicamente mientras su consentimiento
 *   MARKETING_EMAIL está vigente.
 * - El rol MARKETING solo ve la vista v_export_marketing, identificada por un seudónimo propio de
 *   marketing (no el user_id) y con un token de baja aleatorio.
 */

const bdMarketing = DB.conectar(ROLES_BD.ROL_MARKETING);
const bdControles = DB.conectar(ROLES_BD.SVC_APP);

export class MarketingService {
  /** Exportación hacia la plataforma de correo: seudónimo + correo + token de baja. */
  static exportarSuscriptores(sesion) {
    autorizar(sesion, PERMISOS.MARKETING_EXPORTAR, { recurso: 'v_export_marketing' });
    if (bdControles.obtener('controles_operacion', 'exportaciones_suspendidas')?.activo) {
      registrarAuditoria({ sesion, accion: PERMISOS.MARKETING_EXPORTAR, recurso: 'v_export_marketing', resultado: 'DENEGADO', motivo: 'EXPORTACIONES_SUSPENDIDAS_POR_INCIDENTE' });
      throw errores.accesoDenegado();
    }
    const filas = bdMarketing.vista('v_export_marketing').map(s => ({
      suscriptor_pseudo: s.suscriptor_pseudo,
      email: decryptField(s.email_cifrado, contexto('suscripciones_marketing', 'email_cifrado', s.id)),
      token_desuscripcion: s.token_desuscripcion
    }));
    registrarAuditoria({ sesion, accion: PERMISOS.MARKETING_EXPORTAR, recurso: 'v_export_marketing', resultado: 'PERMITIDO', motivo: `${filas.length} suscriptores` });
    return filas;
  }
}
