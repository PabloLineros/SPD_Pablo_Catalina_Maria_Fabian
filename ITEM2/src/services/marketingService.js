import crypto from 'node:crypto';
import { DB, ROLES_BD } from '../db/repository.js';
import { encryptField, decryptField, contexto } from '../crypto/cipher.js';
import { referenciaAleatoria } from '../crypto/pseudonymization.js';
import { autorizar, PERMISOS } from '../security/rbac.js';
import { registrarAuditoria } from '../security/audit.js';
import { errores } from '../security/errors.js';
import { soloCampos, validar } from '../security/validation.js';
import { seudonimoRegistrado } from './privacyService.js';

/**
 * Marketing con consentimiento explícito (opt-in, desmarcado por defecto).
 * - Solo se guarda el correo (nombre_contacto eliminado por minimización).
 * - El rol MARKETING solo ve la vista v_export_marketing: suscriptores VIGENTES, identificados
 *   por un seudónimo propio de marketing (no el user_id) y con un token de baja aleatorio.
 */

const bdApp = DB.conectar(ROLES_BD.SVC_APP);
const bdMarketing = DB.conectar(ROLES_BD.ROL_MARKETING);
const VERSION_TEXTO_CONSENTIMIENTO = 'v1.0';

/** Registra el consentimiento de un cliente (uso interno y desde gestionarConsentimiento). */
export function otorgarConsentimiento(userId, email) {
  const vigente = bdApp.buscarUno('suscripciones_marketing', s => s.user_id === userId && !s.revocado_el);
  if (vigente) return { suscrito: true };

  const id = crypto.randomUUID();
  bdApp.insertar('suscripciones_marketing', {
    id,
    user_id: userId,
    suscriptor_pseudo: seudonimoRegistrado('marketing', userId),
    email_cifrado: encryptField(validar.email(email), contexto('suscripciones_marketing', 'email_cifrado', id)),
    consentimiento_otorgado_el: new Date().toISOString(),
    version_texto: VERSION_TEXTO_CONSENTIMIENTO,
    revocado_el: null,
    token_desuscripcion: referenciaAleatoria()
  });
  return { suscrito: true };
}

function revocar(filtro) {
  const vigentes = bdApp.seleccionar('suscripciones_marketing', s => !s.revocado_el && filtro(s));
  for (const s of vigentes) bdApp.actualizar('suscripciones_marketing', s.id, { revocado_el: new Date().toISOString() });
  return vigentes.length;
}

export class MarketingService {
  /** El cliente acepta o revoca el consentimiento sobre su propia cuenta. */
  static gestionarConsentimiento(sesion, userId, entrada) {
    autorizar(sesion, PERMISOS.CONSENTIMIENTO_PROPIO, { propietarioId: userId, recurso: `consentimiento:${userId}` });
    soloCampos(entrada, { obligatorios: ['acepta'] });
    if (typeof entrada.acepta !== 'boolean') throw errores.datoInvalido('acepta debe ser verdadero o falso.');

    if (!entrada.acepta) {
      revocar(s => s.user_id === userId);
      return { suscrito: false };
    }
    const user = bdApp.obtener('users', userId);
    return otorgarConsentimiento(userId, decryptField(user.email_cifrado, contexto('users', 'email_cifrado', userId)));
  }

  /** Baja con un clic desde el enlace del correo (sin sesión, token aleatorio). */
  static desuscribirPorToken(token) {
    validar.uuid(token, 'token');
    revocar(s => s.token_desuscripcion === token);
    // Respuesta idéntica exista o no el token: no revela qué tokens son válidos.
    return { suscrito: false };
  }

  /** Exportación hacia la plataforma de correo: seudónimo + correo + token de baja. */
  static exportarSuscriptores(sesion) {
    autorizar(sesion, PERMISOS.MARKETING_EXPORTAR, { recurso: 'v_export_marketing' });
    const filas = bdMarketing.vista('v_export_marketing').map(s => ({
      suscriptor_pseudo: s.suscriptor_pseudo,
      email: decryptField(s.email_cifrado, contexto('suscripciones_marketing', 'email_cifrado', s.id)),
      token_desuscripcion: s.token_desuscripcion
    }));
    registrarAuditoria({ sesion, accion: PERMISOS.MARKETING_EXPORTAR, recurso: 'v_export_marketing', resultado: 'PERMITIDO', motivo: `${filas.length} suscriptores` });
    return filas;
  }
}
