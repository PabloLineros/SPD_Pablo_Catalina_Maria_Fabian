import crypto from 'node:crypto';
import { DB, ROLES_BD } from '../db/repository.js';
import { hashPassword, validarPoliticaPassword } from '../crypto/hashing.js';
import { encryptField, decryptField, contexto } from '../crypto/cipher.js';
import { indiceCiegoEmail } from '../crypto/pseudonymization.js';
import { PaymentVault } from '../crypto/tokenization.js';
import { autorizar, PERMISOS } from '../security/rbac.js';
import { errores } from '../security/errors.js';
import { soloCampos, validar } from '../security/validation.js';
import { logger } from '../security/logger.js';
import { LoyaltyService } from './loyaltyService.js';
import { otorgarConsentimiento } from './marketingService.js';
import { suprimirCliente } from './privacyService.js';

/**
 * Servicio de Clientes.
 * Minimización aplicada en el registro:
 *  - Obligatorios: nombre, email, password, direccionDespacho, comuna.
 *  - Opcionales: telefono, guardarMedioPago (+ tarjeta), aceptaMarketing.
 *  - Cualquier otro campo (fecha de nacimiento, sexo, RUT, foto...) se RECHAZA.
 *  - La tarjeta solo se acepta si el cliente marca guardarMedioPago (privacidad por defecto).
 */

const bd = DB.conectar(ROLES_BD.SVC_APP);
const ctxUser = (campo, id) => contexto('users', campo, id);

const POLITICA_REGISTRO = {
  obligatorios: ['nombre', 'email', 'password', 'direccionDespacho', 'comuna'],
  opcionales: ['telefono', 'guardarMedioPago', 'tarjeta', 'aceptaMarketing']
};

const POLITICA_EDICION = {
  opcionales: ['telefono', 'direccionDespacho', 'comuna', 'guardarMedioPago']
};

export class UserService {
  static async registrarCliente(datos) {
    soloCampos(datos, POLITICA_REGISTRO);

    const nombre = validar.nombre(datos.nombre);
    const email = validar.email(datos.email);
    const direccion = validar.direccion(datos.direccionDespacho);
    const comuna = validar.comuna(datos.comuna);
    const telefono = datos.telefono ? validar.telefono(datos.telefono) : null;
    const problemaPassword = validarPoliticaPassword(datos.password);
    if (problemaPassword) throw errores.datoInvalido(problemaPassword);

    const guardarMedioPago = datos.guardarMedioPago === true;
    if (datos.tarjeta && !guardarMedioPago) {
      throw errores.campoNoPermitido(['tarjeta (solo se acepta si guardarMedioPago es verdadero)']);
    }
    if (guardarMedioPago && !datos.tarjeta) {
      throw errores.datoInvalido('Para guardar un medio de pago debe ingresar la tarjeta.');
    }

    const emailHmac = indiceCiegoEmail(email);
    if (bd.buscarUno('users', u => u.email_hmac === emailHmac)) {
      throw errores.conflicto('No fue posible completar el registro con los datos entregados.');
    }

    let pago = { token_pago: null, last4: null, brand: null };
    if (guardarMedioPago) {
      try {
        pago = PaymentVault.tokenizeCard(datos.tarjeta);
      } catch (e) {
        throw errores.datoInvalido(e.message);
      }
    }

    const id = crypto.randomUUID();
    bd.insertar('users', {
      id,
      nombre_cifrado: encryptField(nombre, ctxUser('nombre_cifrado', id)),
      email_cifrado: encryptField(email, ctxUser('email_cifrado', id)),
      email_hmac: emailHmac,
      telefono_cifrado: telefono ? encryptField(telefono, ctxUser('telefono_cifrado', id)) : null,
      direccion_despacho_cifrada: encryptField(direccion, ctxUser('direccion_despacho_cifrada', id)),
      comuna,
      password_hash: await hashPassword(datos.password),
      guardar_medio_pago: guardarMedioPago,
      token_pago: pago.token_pago,
      tarjeta_last4: pago.last4,
      tarjeta_marca: pago.brand,
      created_at: new Date().toISOString()
    });

    LoyaltyService.inicializarCuenta(id, 500);
    if (datos.aceptaMarketing === true) otorgarConsentimiento(id, email);

    logger.info('cliente_registrado', { usuarioId: id });
    return { id };
  }

  /** Perfil propio: descifrado bajo demanda solo para el titular. No expone el token de pago. */
  static verPerfilPropio(sesion, userId) {
    autorizar(sesion, PERMISOS.PERFIL_PROPIO_LEER, { propietarioId: userId, recurso: `users:${userId}` });
    const u = bd.obtener('users', userId);
    if (!u) throw errores.noEncontrado('Usuario');

    return {
      id: u.id,
      nombre: decryptField(u.nombre_cifrado, ctxUser('nombre_cifrado', u.id)),
      email: decryptField(u.email_cifrado, ctxUser('email_cifrado', u.id)),
      telefono: u.telefono_cifrado ? decryptField(u.telefono_cifrado, ctxUser('telefono_cifrado', u.id)) : null,
      direccionDespacho: decryptField(u.direccion_despacho_cifrada, ctxUser('direccion_despacho_cifrada', u.id)),
      comuna: u.comuna,
      medioPago: u.guardar_medio_pago ? { marca: u.tarjeta_marca, last4: u.tarjeta_last4 } : null
    };
  }

  /** Edición propia: teléfono (o eliminarlo con null), dirección/comuna, dejar de guardar la tarjeta. */
  static actualizarPerfilPropio(sesion, userId, cambios) {
    autorizar(sesion, PERMISOS.PERFIL_PROPIO_EDITAR, { propietarioId: userId, recurso: `users:${userId}` });
    soloCampos(cambios, POLITICA_EDICION);
    const u = bd.obtener('users', userId);
    if (!u) throw errores.noEncontrado('Usuario');

    const fila = {};
    if ('telefono' in cambios) {
      fila.telefono_cifrado = cambios.telefono === null
        ? null
        : encryptField(validar.telefono(cambios.telefono), ctxUser('telefono_cifrado', userId));
    }
    if ('direccionDespacho' in cambios) {
      fila.direccion_despacho_cifrada = encryptField(validar.direccion(cambios.direccionDespacho), ctxUser('direccion_despacho_cifrada', userId));
    }
    if ('comuna' in cambios) fila.comuna = validar.comuna(cambios.comuna);
    if ('guardarMedioPago' in cambios) {
      if (cambios.guardarMedioPago !== false) {
        throw errores.datoInvalido('Para agregar un medio de pago use el flujo de pago de la pasarela.');
      }
      if (u.token_pago) PaymentVault.revokeToken(u.token_pago);
      Object.assign(fila, { guardar_medio_pago: false, token_pago: null, tarjeta_last4: null, tarjeta_marca: null });
    }

    bd.actualizar('users', userId, fila);
    return { actualizado: Object.keys(cambios) };
  }

  /** Derecho de supresión ejercido por el titular. */
  static suprimirCuentaPropia(sesion, userId) {
    autorizar(sesion, PERMISOS.CUENTA_PROPIA_SUPRIMIR, { propietarioId: userId, recurso: `users:${userId}` });
    return suprimirCliente(userId);
  }
}
