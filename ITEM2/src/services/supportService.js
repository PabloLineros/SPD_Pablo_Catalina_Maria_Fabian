import { DB, ROLES_BD } from '../db/repository.js';
import { decryptField, contexto } from '../crypto/cipher.js';
import { indiceCiegoEmail } from '../crypto/pseudonymization.js';
import { autorizar, PERMISOS } from '../security/rbac.js';
import { registrarAuditoria } from '../security/audit.js';
import { errores } from '../security/errors.js';
import { soloCampos, validar, enmascarar } from '../security/validation.js';

/**
 * Atención al cliente.
 * - Búsqueda por email exacto vía índice ciego; resultado ENMASCARADO por defecto.
 * - Revelar la PII completa exige un permiso adicional (solo SOPORTE), un ticket y un motivo,
 *   y queda en la auditoría. Nunca se exponen hash de contraseña, token de pago ni puntos.
 */

const bd = DB.conectar(ROLES_BD.SVC_APP);
const ctx = (campo, id) => contexto('users', campo, id);

export class SupportService {
  static buscarCliente(sesion, email) {
    autorizar(sesion, PERMISOS.CLIENTES_BUSCAR_ENMASCARADO, { recurso: 'users' });
    const u = bd.buscarUno('users', x => x.email_hmac === indiceCiegoEmail(validar.email(email)));
    registrarAuditoria({ sesion, accion: PERMISOS.CLIENTES_BUSCAR_ENMASCARADO, recurso: u ? `users:${u.id}` : 'users:sin_resultado', resultado: 'PERMITIDO' });
    if (!u) throw errores.noEncontrado('Cliente');

    return {
      id: u.id,
      nombre: enmascarar.nombre(decryptField(u.nombre_cifrado, ctx('nombre_cifrado', u.id))),
      email: enmascarar.email(decryptField(u.email_cifrado, ctx('email_cifrado', u.id))),
      telefono: u.telefono_cifrado ? enmascarar.telefono(decryptField(u.telefono_cifrado, ctx('telefono_cifrado', u.id))) : null,
      comuna: u.comuna,
      pedidos: bd.seleccionar('orders', o => o.user_id === u.id).length
    };
  }

  static revelarDatosContacto(sesion, userId, entrada) {
    autorizar(sesion, PERMISOS.CLIENTES_PII_REVELAR, { recurso: `users:${userId}` });
    soloCampos(entrada, { obligatorios: ['ticket', 'motivo'] });
    if (!/^TCK-\d{4,}$/.test(String(entrada.ticket))) throw errores.datoInvalido('ticket debe tener formato TCK-0000.');
    const motivo = String(entrada.motivo).trim();
    if (motivo.length < 15) throw errores.datoInvalido('Debe justificar el acceso (mín. 15 caracteres).');

    const u = bd.obtener('users', validar.uuid(userId, 'userId'));
    if (!u) throw errores.noEncontrado('Cliente');
    registrarAuditoria({ sesion, accion: PERMISOS.CLIENTES_PII_REVELAR, recurso: `users:${userId}`, resultado: 'PERMITIDO', motivo: `${entrada.ticket}: ${motivo}` });

    return {
      nombre: decryptField(u.nombre_cifrado, ctx('nombre_cifrado', u.id)),
      email: decryptField(u.email_cifrado, ctx('email_cifrado', u.id)),
      telefono: u.telefono_cifrado ? decryptField(u.telefono_cifrado, ctx('telefono_cifrado', u.id)) : null,
      direccionDespacho: decryptField(u.direccion_despacho_cifrada, ctx('direccion_despacho_cifrada', u.id)),
      comuna: u.comuna
    };
  }
}
