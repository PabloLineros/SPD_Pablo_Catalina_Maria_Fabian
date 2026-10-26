import crypto from 'node:crypto';
import { DB, ROLES_BD } from '../db/repository.js';
import { hashPassword, validarPoliticaPassword } from '../crypto/hashing.js';
import { encryptField, contexto } from '../crypto/cipher.js';
import { indiceCiegoEmail } from '../crypto/pseudonymization.js';
import { autorizar, PERMISOS, ROLES_PERSONAL } from '../security/rbac.js';
import { registrarAuditoria } from '../security/audit.js';
import { errores } from '../security/errors.js';
import { soloCampos, validar } from '../security/validation.js';
import { cerrarTodasLasSesiones } from './authService.js';

/**
 * Administración de cuentas del personal y roles.
 * - Solo ADMINISTRADOR (permiso roles:gestionar).
 * - Un administrador no puede cambiar su propio rol ni desactivarse (evita auto-escalamiento
 *   y bloqueo accidental; un cambio así lo hace OTRO administrador).
 * - El administrador NO obtiene acceso a PII completa ni a llaves por tener este rol.
 */

const bd = DB.conectar(ROLES_BD.SVC_APP);

function impedirSobreSiMismo(sesion, personalId, accion) {
  if (personalId === sesion.usuarioId) {
    registrarAuditoria({ sesion, accion, recurso: `personal:${personalId}`, resultado: 'DENEGADO', motivo: 'AUTO_MODIFICACION' });
    throw errores.accesoDenegado();
  }
}

function validarRol(rol) {
  if (!ROLES_PERSONAL.includes(rol)) throw errores.datoInvalido(`Rol inválido. Roles válidos: ${ROLES_PERSONAL.join(', ')}.`);
  return rol;
}

async function insertarPersonal({ nombre, email, password, rol }) {
  const problema = validarPoliticaPassword(password);
  if (problema) throw errores.datoInvalido(problema);
  const emailNorm = validar.email(email);
  const emailHmac = indiceCiegoEmail(emailNorm);
  if (bd.buscarUno('personal', p => p.email_hmac === emailHmac)) throw errores.conflicto('Ya existe una cuenta de personal con ese correo.');

  const id = crypto.randomUUID();
  bd.insertar('personal', {
    id,
    nombre_cifrado: encryptField(validar.nombre(nombre), contexto('personal', 'nombre_cifrado', id)),
    email_cifrado: encryptField(emailNorm, contexto('personal', 'email_cifrado', id)),
    email_hmac: emailHmac,
    password_hash: await hashPassword(password),
    rol: validarRol(rol),
    activo: true,
    created_at: new Date().toISOString()
  });
  return id;
}

export class AdminService {
  /**
   * Siembra del primer administrador (equivale a un script de instalación ejecutado una vez
   * por el custodio del sistema). Falla si ya existe personal.
   */
  static async inicializarAdministrador(datos) {
    if (bd.seleccionar('personal').length > 0) throw errores.conflicto('El sistema ya fue inicializado.');
    return { id: await insertarPersonal({ ...datos, rol: 'ADMINISTRADOR' }) };
  }

  static async crearPersonal(sesion, datos) {
    autorizar(sesion, PERMISOS.ROLES_GESTIONAR, { recurso: 'personal' });
    soloCampos(datos, { obligatorios: ['nombre', 'email', 'password', 'rol'] });
    const id = await insertarPersonal(datos);
    registrarAuditoria({ sesion, accion: PERMISOS.ROLES_GESTIONAR, recurso: `personal:${id}`, resultado: 'PERMITIDO', motivo: `crear rol=${datos.rol}` });
    return { id, rol: datos.rol };
  }

  static asignarRol(sesion, personalId, rol) {
    autorizar(sesion, PERMISOS.ROLES_GESTIONAR, { recurso: `personal:${personalId}` });
    impedirSobreSiMismo(sesion, personalId, PERMISOS.ROLES_GESTIONAR);
    if (!bd.obtener('personal', personalId)) throw errores.noEncontrado('Cuenta de personal');
    bd.actualizar('personal', personalId, { rol: validarRol(rol) });
    registrarAuditoria({ sesion, accion: PERMISOS.ROLES_GESTIONAR, recurso: `personal:${personalId}`, resultado: 'PERMITIDO', motivo: `asignar rol=${rol}` });
    return { id: personalId, rol };
  }

  static desactivarPersonal(sesion, personalId) {
    autorizar(sesion, PERMISOS.ROLES_GESTIONAR, { recurso: `personal:${personalId}` });
    impedirSobreSiMismo(sesion, personalId, PERMISOS.ROLES_GESTIONAR);
    if (!bd.obtener('personal', personalId)) throw errores.noEncontrado('Cuenta de personal');
    bd.actualizar('personal', personalId, { activo: false });
    cerrarTodasLasSesiones(personalId);
    registrarAuditoria({ sesion, accion: PERMISOS.ROLES_GESTIONAR, recurso: `personal:${personalId}`, resultado: 'PERMITIDO', motivo: 'desactivar' });
    return { id: personalId, activo: false };
  }

  static leerAuditoria(sesion, { limite = 50 } = {}) {
    autorizar(sesion, PERMISOS.AUDITORIA_LEER, { recurso: 'audit_log' });
    return bd.seleccionar('audit_log').slice(-Math.min(Math.max(1, limite), 500));
  }
}
