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
import { registrarAuditoria } from '../security/audit.js';
import { LoyaltyService } from './loyaltyService.js';
import { otorgarConsentimiento, revocarConsentimiento } from './consentService.js';

/**
 * Servicio de Clientes.
 * Minimización aplicada en el registro:
 *  - Obligatorios: nombre, email, password, direccionDespacho, comuna.
 *  - Opcionales: telefono, guardarMedioPago (+ tarjeta), aceptaMarketing.
 *  - Cualquier otro campo (fecha de nacimiento, sexo, RUT, foto...) se RECHAZA.
 *  - La tarjeta solo se acepta si el cliente marca guardarMedioPago (privacidad por defecto).
 *  - Cada consentimiento (guardar tarjeta, marketing, analítica) es una casilla independiente,
 *    desmarcada por defecto; solo cuenta el valor booleano true.
 *  - Mayoría de edad: NortiShop no ofrece cuentas a menores (ver informe). Se guarda solo la
 *    fecha de la declaración, nunca la fecha de nacimiento.
 */

const bd = DB.conectar(ROLES_BD.SVC_APP);
const ctxUser = (campo, id) => contexto('users', campo, id);

const POLITICA_REGISTRO = {
  obligatorios: ['nombre', 'email', 'password', 'direccionDespacho', 'comuna', 'declaraMayorDeEdad'],
  opcionales: ['telefono', 'guardarMedioPago', 'tarjeta', 'aceptaMarketing', 'aceptaAnalitica']
};

const POLITICA_EDICION = {
  opcionales: ['telefono', 'direccionDespacho', 'comuna', 'guardarMedioPago']
};

const ESTADOS_PEDIDO_MODIFICABLES = ['PAGADO', 'PREPARANDO'];

/**
 * Aplica cambios validados al perfil y los PROPAGA a los módulos que guardan copias:
 *  - dirección/comuna: pedidos aún no despachados (los despachados conservan la dirección usada).
 *  - email: índice ciego del login y lista de envío de marketing.
 *  - nombre y teléfono: solo users (las etiquetas se generan bajo demanda).
 * Devuelve los nombres de los campos modificados (nunca los valores).
 */
export function aplicarCambiosPerfil(userId, cambios) {
  const u = bd.obtener('users', userId);
  if (!u) throw errores.noEncontrado('Usuario');
  const fila = {};
  const modificados = [];
  const propagado = [];

  if ('nombre' in cambios) {
    fila.nombre_cifrado = encryptField(validar.nombre(cambios.nombre), ctxUser('nombre_cifrado', userId));
    modificados.push('nombre');
  }
  if ('telefono' in cambios) {
    fila.telefono_cifrado = cambios.telefono === null
      ? null
      : encryptField(validar.telefono(cambios.telefono), ctxUser('telefono_cifrado', userId));
    modificados.push('telefono');
  }
  let nuevaDireccion = null;
  if ('direccionDespacho' in cambios) {
    nuevaDireccion = validar.direccion(cambios.direccionDespacho);
    fila.direccion_despacho_cifrada = encryptField(nuevaDireccion, ctxUser('direccion_despacho_cifrada', userId));
    modificados.push('direccionDespacho');
  }
  if ('comuna' in cambios) {
    fila.comuna = validar.comuna(cambios.comuna);
    modificados.push('comuna');
  }
  let nuevoEmail = null;
  if ('email' in cambios) {
    nuevoEmail = validar.email(cambios.email);
    const hmac = indiceCiegoEmail(nuevoEmail);
    if (bd.buscarUno('users', x => x.email_hmac === hmac && x.id !== userId)) {
      throw errores.conflicto('No es posible usar ese correo.');
    }
    fila.email_cifrado = encryptField(nuevoEmail, ctxUser('email_cifrado', userId));
    fila.email_hmac = hmac;
    modificados.push('email');
  }

  bd.actualizar('users', userId, fila);

  if (nuevaDireccion || fila.comuna) {
    for (const o of bd.seleccionar('orders', x => x.user_id === userId && ESTADOS_PEDIDO_MODIFICABLES.includes(x.estado))) {
      const cambio = {};
      if (nuevaDireccion) cambio.direccion_envio_cifrada = encryptField(nuevaDireccion, contexto('orders', 'direccion_envio_cifrada', o.id));
      if (fila.comuna) cambio.comuna_envio = fila.comuna;
      bd.actualizar('orders', o.id, cambio);
      propagado.push(`orders:${o.id}`);
    }
  }
  if (nuevoEmail) {
    const s = bd.buscarUno('suscripciones_marketing', x => x.user_id === userId);
    if (s) {
      bd.actualizar('suscripciones_marketing', s.id, { email_cifrado: encryptField(nuevoEmail, contexto('suscripciones_marketing', 'email_cifrado', s.id)) });
      propagado.push('suscripciones_marketing');
    }
  }
  return { modificados, propagado };
}

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
    if (datos.declaraMayorDeEdad !== true) {
      throw errores.datoInvalido('NortiShop solo ofrece cuentas a personas mayores de 18 años.');
    }

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
      mayor_edad_declarado_el: new Date().toISOString(),
      created_at: new Date().toISOString()
    });

    LoyaltyService.inicializarCuenta(id, 500);
    // Una decisión independiente por finalidad; ninguna se deduce de otra.
    if (guardarMedioPago) otorgarConsentimiento(id, 'GUARDAR_MEDIO_PAGO', { canal: 'REGISTRO' });
    if (datos.aceptaMarketing === true) otorgarConsentimiento(id, 'MARKETING_EMAIL', { canal: 'REGISTRO' });
    if (datos.aceptaAnalitica === true) otorgarConsentimiento(id, 'ANALITICA_COMPRAS', { canal: 'REGISTRO' });

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

  /** Edición propia de datos de bajo riesgo: teléfono (o eliminarlo con null), dirección/comuna, dejar de guardar la tarjeta. */
  static actualizarPerfilPropio(sesion, userId, cambios) {
    autorizar(sesion, PERMISOS.PERFIL_PROPIO_EDITAR, { propietarioId: userId, recurso: `users:${userId}` });
    soloCampos(cambios, POLITICA_EDICION);
    if (!bd.obtener('users', userId)) throw errores.noEncontrado('Usuario');

    const { guardarMedioPago, ...datos } = cambios;
    if ('guardarMedioPago' in cambios) {
      if (guardarMedioPago !== false) {
        throw errores.datoInvalido('Para guardar una tarjeta use el Centro de privacidad (consentimiento GUARDAR_MEDIO_PAGO).');
      }
      revocarConsentimiento(userId, 'GUARDAR_MEDIO_PAGO', { canal: 'CENTRO_PRIVACIDAD', sesion });
    }
    const { modificados, propagado } = aplicarCambiosPerfil(userId, datos);
    registrarAuditoria({ sesion, accion: PERMISOS.PERFIL_PROPIO_EDITAR, recurso: `users:${userId}`, resultado: 'EXITO', motivo: `campos=${Object.keys(cambios).join(',')}; propagado=${propagado.length}` });
    return { actualizado: [...modificados, ...('guardarMedioPago' in cambios ? ['guardarMedioPago'] : [])] };
  }
}
