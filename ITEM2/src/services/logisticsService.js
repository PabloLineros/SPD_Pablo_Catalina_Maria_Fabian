import { DB, ROLES_BD } from '../db/repository.js';
import { decryptField, contexto } from '../crypto/cipher.js';
import { autorizar, PERMISOS } from '../security/rbac.js';
import { registrarAuditoria } from '../security/audit.js';
import { errores } from '../security/errors.js';
import { validar } from '../security/validation.js';
import { fechaRetencion } from './orderService.js';

/**
 * Logística y operador de despacho.
 * El rol LOGISTICA trabaja con ref_envio (referencia aleatoria). Solo al generar la etiqueta
 * se descifran nombre y dirección, y esa operación queda auditada.
 * NO se entrega: order_id, user_id, email, teléfono, monto ni medio de pago.
 */

const bd = DB.conectar(ROLES_BD.SVC_APP);

const TRANSICIONES = { PENDIENTE: ['EN_RUTA', 'CANCELADO'], EN_RUTA: ['ENTREGADO'], ENTREGADO: [], CANCELADO: [] };

function envioPorRef(ref) {
  validar.uuid(ref, 'ref_envio');
  const envio = bd.buscarUno('envios', e => e.ref_envio === ref);
  if (!envio) throw errores.noEncontrado('Envío');
  return envio;
}

function pedidoDe(envio) {
  return envio.tipo_pedido === 'REGISTRADO' ? bd.obtener('orders', envio.order_id) : bd.obtener('orders_invitado', envio.order_id);
}

export class LogisticsService {
  static listarPendientes(sesion) {
    autorizar(sesion, PERMISOS.ENVIOS_GESTIONAR, { recurso: 'envios' });
    return bd.seleccionar('envios', e => ['PENDIENTE', 'EN_RUTA'].includes(e.estado_envio))
      .map(e => ({ ref_envio: e.ref_envio, comuna: pedidoDe(e)?.comuna_envio, estado_envio: e.estado_envio }));
  }

  static generarEtiqueta(sesion, ref) {
    autorizar(sesion, PERMISOS.ENVIOS_GESTIONAR, { recurso: 'envios:etiqueta' });
    const envio = envioPorRef(ref);
    const pedido = pedidoDe(envio);
    if (!pedido?.direccion_envio_cifrada) throw errores.conflicto('El envío no tiene datos de despacho disponibles.');

    let destinatario;
    let direccion;
    if (envio.tipo_pedido === 'REGISTRADO') {
      const user = bd.obtener('users', pedido.user_id);
      destinatario = decryptField(user.nombre_cifrado, contexto('users', 'nombre_cifrado', user.id));
      direccion = decryptField(pedido.direccion_envio_cifrada, contexto('orders', 'direccion_envio_cifrada', pedido.id));
    } else {
      destinatario = decryptField(pedido.nombre_invitado_cifrado, contexto('orders_invitado', 'nombre_invitado_cifrado', pedido.id));
      direccion = decryptField(pedido.direccion_envio_cifrada, contexto('orders_invitado', 'direccion_envio_cifrada', pedido.id));
    }

    registrarAuditoria({ sesion, accion: 'envios:etiqueta', recurso: `envio:${ref}`, resultado: 'PERMITIDO' });
    return { ref_envio: ref, destinatario, direccion, comuna: pedido.comuna_envio };
  }

  static actualizarEstado(sesion, ref, nuevoEstado) {
    autorizar(sesion, PERMISOS.ENVIOS_GESTIONAR, { recurso: 'envios:estado' });
    const envio = envioPorRef(ref);
    if (!TRANSICIONES[envio.estado_envio]?.includes(nuevoEstado)) {
      throw errores.datoInvalido(`Transición no permitida: ${envio.estado_envio} -> ${nuevoEstado}.`);
    }
    bd.actualizar('envios', envio.id, { estado_envio: nuevoEstado, updated_at: new Date().toISOString() });

    const tabla = envio.tipo_pedido === 'REGISTRADO' ? 'orders' : 'orders_invitado';
    const estadoPedido = { EN_RUTA: 'DESPACHADO', ENTREGADO: 'ENTREGADO', CANCELADO: 'CANCELADO' }[nuevoEstado];
    const cambios = { estado: estadoPedido };
    if (tabla === 'orders_invitado' && ['ENTREGADO', 'CANCELADO'].includes(estadoPedido)) {
      // Inicia el plazo de conservación del contacto del invitado.
      cambios.eliminar_contacto_desde = fechaRetencion();
    }
    bd.actualizar(tabla, envio.order_id, cambios);

    registrarAuditoria({ sesion, accion: 'envios:estado', recurso: `envio:${ref}`, resultado: 'PERMITIDO', motivo: nuevoEstado });
    return { ref_envio: ref, estado_envio: nuevoEstado };
  }
}
