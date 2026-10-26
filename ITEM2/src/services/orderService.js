import crypto from 'node:crypto';
import { CONFIG } from '../config/env.js';
import { DB, ROLES_BD } from '../db/repository.js';
import { encryptField, decryptField, contexto } from '../crypto/cipher.js';
import { PaymentVault } from '../crypto/tokenization.js';
import { referenciaAleatoria } from '../crypto/pseudonymization.js';
import { autorizar, PERMISOS } from '../security/rbac.js';
import { registrarAuditoria } from '../security/audit.js';
import { errores } from '../security/errors.js';
import { soloCampos, validar } from '../security/validation.js';
import { CatalogService } from './catalogService.js';
import { LoyaltyService } from './loyaltyService.js';

/**
 * Servicio de Pedidos.
 * - La orden guarda la dirección de envío CIFRADA con su propio contexto (orders.<campo>:<id>),
 *   nunca en texto plano (antes: direccionDespachoDescifradaLogistica).
 * - De la tarjeta solo se guardan los últimos 4 dígitos.
 * - Los datos de facturación (RUT, razón social) SOLO se aceptan si el cliente pide FACTURA.
 * - Cada pedido genera un envío con referencia aleatoria (ref_envio) para el courier.
 * - Invitados: contacto cifrado + token de seguimiento UUID v4; plazo de conservación al entregar.
 */

const bd = DB.conectar(ROLES_BD.SVC_APP);

function cobrar({ tokenGuardado, tarjeta, total }) {
  if (tokenGuardado && tarjeta) throw errores.campoNoPermitido(['tarjeta (ya tiene un medio de pago guardado)']);
  if (tokenGuardado) return { ...PaymentVault.chargeWithToken(tokenGuardado, total), last4: null };
  if (!tarjeta) throw errores.datoInvalido('Debe ingresar una tarjeta para pagar.');

  // Pago de una sola vez: se tokeniza, se cobra y el token se revoca de inmediato (no se guarda).
  let temp;
  try {
    temp = PaymentVault.tokenizeCard(tarjeta);
  } catch (e) {
    throw errores.datoInvalido(e.message);
  }
  try {
    return { ...PaymentVault.chargeWithToken(temp.token_pago, total), last4: temp.last4 };
  } finally {
    PaymentVault.revokeToken(temp.token_pago);
  }
}

function crearEnvio(orderId, tipoPedido) {
  bd.insertar('envios', {
    id: crypto.randomUUID(),
    order_id: orderId,
    tipo_pedido: tipoPedido,
    ref_envio: referenciaAleatoria(),
    estado_envio: 'PENDIENTE',
    updated_at: new Date().toISOString()
  });
}

function guardarItems(orderId, lineas) {
  for (const l of lineas) bd.insertar('order_items', { id: `${orderId}:${l.producto_id}`, order_id: orderId, ...l });
}

export class OrderService {
  /** Compra de un cliente registrado (siempre sobre su propia cuenta). */
  static crearPedido(sesion, entrada) {
    autorizar(sesion, PERMISOS.PEDIDO_CREAR, { recurso: 'orders' });
    soloCampos(entrada, { obligatorios: ['items'], opcionales: ['tipoDocumento', 'facturacion', 'tarjeta'] });

    const tipoDocumento = entrada.tipoDocumento ?? 'BOLETA';
    if (!['BOLETA', 'FACTURA'].includes(tipoDocumento)) throw errores.datoInvalido('tipoDocumento debe ser BOLETA o FACTURA.');
    if (tipoDocumento === 'BOLETA' && entrada.facturacion) {
      throw errores.campoNoPermitido(['facturacion (la boleta no requiere RUT ni razón social)']);
    }
    let factura = null;
    if (tipoDocumento === 'FACTURA') {
      soloCampos(entrada.facturacion, { obligatorios: ['rut', 'razonSocial', 'direccion'] });
      factura = {
        rut: validar.rut(entrada.facturacion.rut),
        razonSocial: validar.nombre(entrada.facturacion.razonSocial),
        direccion: validar.direccion(entrada.facturacion.direccion)
      };
    }

    const userId = sesion.usuarioId;
    const user = bd.obtener('users', userId);
    if (!user) throw errores.noEncontrado('Usuario');

    const { total, lineas } = CatalogService.reservarItems(entrada.items);
    const pago = cobrar({ tokenGuardado: user.token_pago, tarjeta: entrada.tarjeta, total });

    const orderId = crypto.randomUUID();
    const direccion = decryptField(user.direccion_despacho_cifrada, contexto('users', 'direccion_despacho_cifrada', userId));

    let facturacionId = null;
    if (factura) {
      facturacionId = crypto.randomUUID();
      const ctx = (campo) => contexto('facturacion', campo, facturacionId);
      bd.insertar('facturacion', {
        id: facturacionId,
        user_id: userId,
        rut_facturacion_cifrado: encryptField(factura.rut, ctx('rut_facturacion_cifrado')),
        razon_social_cifrada: encryptField(factura.razonSocial, ctx('razon_social_cifrada')),
        direccion_facturacion_cifrada: encryptField(factura.direccion, ctx('direccion_facturacion_cifrada')),
        bloqueado: false,
        created_at: new Date().toISOString()
      });
    }

    bd.insertar('orders', {
      id: orderId,
      user_id: userId,
      total_clp: total,
      transaccion_id: pago.transactionId,
      codigo_autorizacion: pago.authorizationCode,
      tarjeta_last4: pago.last4 ?? user.tarjeta_last4,
      direccion_envio_cifrada: encryptField(direccion, contexto('orders', 'direccion_envio_cifrada', orderId)),
      comuna_envio: user.comuna,
      tipo_documento: tipoDocumento,
      facturacion_id: facturacionId,
      estado: 'PAGADO',
      created_at: new Date().toISOString()
    });
    guardarItems(orderId, lineas);
    crearEnvio(orderId, 'REGISTRADO');
    const puntosGanados = LoyaltyService.acreditarCompra(userId, total);

    return { id: orderId, total_clp: total, estado: 'PAGADO', tipoDocumento, tarjeta_last4: pago.last4 ?? user.tarjeta_last4, puntosGanados };
  }

  /** Historial de pedidos propios (sin dirección: el cliente ya la ve en su perfil). */
  static listarPedidosPropios(sesion, userId) {
    autorizar(sesion, PERMISOS.PEDIDOS_PROPIOS_LEER, { propietarioId: userId, recurso: `orders:user:${userId}` });
    return bd.seleccionar('orders', o => o.user_id === userId).map(o => ({
      id: o.id,
      fecha: o.created_at,
      total_clp: o.total_clp,
      estado: o.estado,
      tipoDocumento: o.tipo_documento,
      items: bd.seleccionar('order_items', i => i.order_id === o.id).map(({ producto_id, cantidad, precio_unitario_clp }) => ({ producto_id, cantidad, precio_unitario_clp }))
    }));
  }

  /** Compra de invitado: sin cuenta, contacto cifrado, seguimiento por token aleatorio. */
  static crearPedidoInvitado(entrada) {
    soloCampos(entrada, {
      obligatorios: ['nombre', 'email', 'direccionDespacho', 'comuna', 'items', 'tarjeta'],
      opcionales: ['telefono']
    });
    const nombre = validar.nombre(entrada.nombre);
    const email = validar.email(entrada.email);
    const direccion = validar.direccion(entrada.direccionDespacho);
    const comuna = validar.comuna(entrada.comuna);
    const telefono = entrada.telefono ? validar.telefono(entrada.telefono) : null;

    const { total, lineas } = CatalogService.reservarItems(entrada.items);
    const pago = cobrar({ tokenGuardado: null, tarjeta: entrada.tarjeta, total });

    const id = crypto.randomUUID();
    const ctx = (campo) => contexto('orders_invitado', campo, id);
    const tokenSeguimiento = referenciaAleatoria();
    bd.insertar('orders_invitado', {
      id,
      token_seguimiento: tokenSeguimiento,
      nombre_invitado_cifrado: encryptField(nombre, ctx('nombre_invitado_cifrado')),
      email_invitado_cifrado: encryptField(email, ctx('email_invitado_cifrado')),
      telefono_invitado_cifrado: telefono ? encryptField(telefono, ctx('telefono_invitado_cifrado')) : null,
      direccion_envio_cifrada: encryptField(direccion, ctx('direccion_envio_cifrada')),
      comuna_envio: comuna,
      total_clp: total,
      transaccion_id: pago.transactionId,
      estado: 'PAGADO',
      created_at: new Date().toISOString(),
      eliminar_contacto_desde: null // se fija al entregar o cancelar
    });
    guardarItems(id, lineas);
    crearEnvio(id, 'INVITADO');

    // En producción el token viaja solo por correo (enlace HTTPS); nunca se registra en logs.
    return { tokenSeguimiento, total_clp: total };
  }

  /** Seguimiento del invitado: solo estado y montos, ningún dato de contacto. */
  static consultarPedidoInvitado(tokenSeguimiento) {
    validar.uuid(tokenSeguimiento, 'token de seguimiento');
    const o = bd.buscarUno('orders_invitado', x => x.token_seguimiento === tokenSeguimiento);
    if (!o) throw errores.noEncontrado('Pedido');
    return { estado: o.estado, total_clp: o.total_clp, comuna_envio: o.comuna_envio, fecha: o.created_at.slice(0, 10) };
  }

  /** Vista de gestión (ADMINISTRADOR, SOPORTE): sin nombres, correos ni direcciones. */
  static listarPedidosGestion(sesion) {
    autorizar(sesion, PERMISOS.PEDIDOS_GESTIONAR, { recurso: 'orders' });
    const registrados = bd.seleccionar('orders').map(o => ({ id: o.id, tipo: 'REGISTRADO', estado: o.estado, total_clp: o.total_clp, comuna_envio: o.comuna_envio, fecha: o.created_at }));
    const invitados = bd.seleccionar('orders_invitado').map(o => ({ id: o.id, tipo: 'INVITADO', estado: o.estado, total_clp: o.total_clp, comuna_envio: o.comuna_envio, fecha: o.created_at }));
    registrarAuditoria({ sesion, accion: PERMISOS.PEDIDOS_GESTIONAR, recurso: 'orders', resultado: 'PERMITIDO', motivo: 'listar' });
    return [...registrados, ...invitados];
  }

  static cancelarPedido(sesion, orderId) {
    autorizar(sesion, PERMISOS.PEDIDOS_GESTIONAR, { recurso: `orders:${orderId}` });
    validar.uuid(orderId, 'orderId');
    const tabla = bd.obtener('orders', orderId) ? 'orders' : bd.obtener('orders_invitado', orderId) ? 'orders_invitado' : null;
    if (!tabla) throw errores.noEncontrado('Pedido');
    const pedido = bd.obtener(tabla, orderId);
    if (['DESPACHADO', 'ENTREGADO', 'CANCELADO'].includes(pedido.estado)) throw errores.conflicto('El pedido ya no puede cancelarse.');

    const cambios = { estado: 'CANCELADO' };
    if (tabla === 'orders_invitado') cambios.eliminar_contacto_desde = fechaRetencion();
    bd.actualizar(tabla, orderId, cambios);
    const envio = bd.buscarUno('envios', e => e.order_id === orderId);
    if (envio) bd.actualizar('envios', envio.id, { estado_envio: 'CANCELADO', updated_at: new Date().toISOString() });
    registrarAuditoria({ sesion, accion: PERMISOS.PEDIDOS_GESTIONAR, recurso: `orders:${orderId}`, resultado: 'PERMITIDO', motivo: 'cancelar' });
    return { id: orderId, estado: 'CANCELADO' };
  }
}

export function fechaRetencion(desde = new Date(), dias = CONFIG.RETENCION_INVITADO_DIAS) {
  return new Date(desde.getTime() + dias * 86_400_000).toISOString();
}
