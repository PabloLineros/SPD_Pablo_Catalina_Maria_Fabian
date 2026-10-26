import { iniciarSesion, cerrarSesion, resolverSesion } from './services/authService.js';
import { UserService } from './services/userService.js';
import { OrderService } from './services/orderService.js';
import { LoyaltyService } from './services/loyaltyService.js';
import { ReviewService } from './services/reviewService.js';
import { MarketingService } from './services/marketingService.js';
import { SupportService } from './services/supportService.js';
import { LogisticsService } from './services/logisticsService.js';
import { CatalogService } from './services/catalogService.js';
import { AdminService } from './services/adminService.js';
import * as Privacidad from './services/privacyService.js';
import { respuestaDeError } from './security/errors.js';
import { logger } from './security/logger.js';

/**
 * Capa de API del servidor (equivalente a los controladores/rutas HTTP).
 * - protegido(): exige token de sesión válido; la autorización por rol/propiedad la hace
 *   cada servicio con autorizar() (defensa en profundidad: no depende de la interfaz).
 * - Toda respuesta es { ok, data } o { ok:false, error:{codigo, estado, mensaje} }.
 *   Los errores internos se registran (redactados) y al cliente solo llega un mensaje genérico.
 */

async function ejecutar(operacion, fn) {
  try {
    return { ok: true, data: await fn() };
  } catch (error) {
    const respuesta = respuestaDeError(error);
    if (respuesta.estado >= 500) {
      logger.error('error_interno', { operacion, codigo: error.code ?? null, error });
    }
    return { ok: false, error: respuesta };
  }
}

const publico = (operacion, fn) => (...args) => ejecutar(operacion, () => fn(...args));
const protegido = (operacion, fn) => (token, ...args) => ejecutar(operacion, () => fn(resolverSesion(token), ...args));

export const API = {
  auth: {
    registrar: publico('auth.registrar', (datos) => UserService.registrarCliente(datos)),
    iniciarSesion: publico('auth.iniciarSesion', (credenciales) => iniciarSesion(credenciales)),
    cerrarSesion: publico('auth.cerrarSesion', (token) => { cerrarSesion(token); return { cerrada: true }; })
  },
  catalogo: {
    listar: publico('catalogo.listar', () => CatalogService.listarProductos()),
    resenas: publico('catalogo.resenas', (productoId) => ReviewService.listarPublicas(productoId)),
    crearProducto: protegido('catalogo.crear', (s, datos) => CatalogService.crearProducto(s, datos)),
    actualizarProducto: protegido('catalogo.actualizar', (s, id, cambios) => CatalogService.actualizarProducto(s, id, cambios))
  },
  cliente: {
    verPerfil: protegido('cliente.verPerfil', (s, userId) => UserService.verPerfilPropio(s, userId)),
    actualizarPerfil: protegido('cliente.actualizarPerfil', (s, userId, cambios) => UserService.actualizarPerfilPropio(s, userId, cambios)),
    suprimirCuenta: protegido('cliente.suprimirCuenta', (s, userId) => UserService.suprimirCuentaPropia(s, userId)),
    crearPedido: protegido('cliente.crearPedido', (s, entrada) => OrderService.crearPedido(s, entrada)),
    misPedidos: protegido('cliente.misPedidos', (s, userId) => OrderService.listarPedidosPropios(s, userId)),
    saldoPuntos: protegido('cliente.saldoPuntos', (s, userId) => LoyaltyService.saldoPropio(s, userId)),
    canjearPuntos: protegido('cliente.canjearPuntos', (s, userId, puntos) => LoyaltyService.canjear(s, userId, puntos)),
    publicarResena: protegido('cliente.publicarResena', (s, entrada) => ReviewService.publicar(s, entrada)),
    consentimientoMarketing: protegido('cliente.consentimiento', (s, userId, entrada) => MarketingService.gestionarConsentimiento(s, userId, entrada))
  },
  invitado: {
    crearPedido: publico('invitado.crearPedido', (entrada) => OrderService.crearPedidoInvitado(entrada)),
    consultarPedido: publico('invitado.consultarPedido', (token) => OrderService.consultarPedidoInvitado(token))
  },
  marketing: {
    exportarSuscriptores: protegido('marketing.exportar', (s) => MarketingService.exportarSuscriptores(s)),
    desuscribir: publico('marketing.desuscribir', (token) => MarketingService.desuscribirPorToken(token))
  },
  soporte: {
    buscarCliente: protegido('soporte.buscar', (s, email) => SupportService.buscarCliente(s, email)),
    revelarDatosContacto: protegido('soporte.revelar', (s, userId, entrada) => SupportService.revelarDatosContacto(s, userId, entrada))
  },
  pedidos: {
    listar: protegido('pedidos.listar', (s) => OrderService.listarPedidosGestion(s)),
    cancelar: protegido('pedidos.cancelar', (s, orderId) => OrderService.cancelarPedido(s, orderId))
  },
  logistica: {
    pendientes: protegido('logistica.pendientes', (s) => LogisticsService.listarPendientes(s)),
    etiqueta: protegido('logistica.etiqueta', (s, ref) => LogisticsService.generarEtiqueta(s, ref)),
    actualizarEstado: protegido('logistica.estado', (s, ref, estado) => LogisticsService.actualizarEstado(s, ref, estado))
  },
  analitica: {
    compras: protegido('analitica.compras', (s) => Privacidad.consultarAnalitica(s)),
    ventasPorComuna: protegido('analitica.ventasPorComuna', (s) => Privacidad.ventasPorComuna(s))
  },
  privacidad: {
    ejecutarEtl: protegido('privacidad.etl', (s) => Privacidad.ejecutarEtlAnalitica(s)),
    anonimizarInvitados: protegido('privacidad.anonimizar', (s, ahora) => Privacidad.anonimizarInvitadosVencidos(s, ahora)),
    revertirSeudonimo: protegido('privacidad.revertir', (s, entrada) => Privacidad.revertirSeudonimo(s, entrada)),
    copiaDesarrollo: protegido('privacidad.copiaDesarrollo', (s) => Privacidad.generarCopiaDesarrollo(s))
  },
  admin: {
    crearPersonal: protegido('admin.crearPersonal', (s, datos) => AdminService.crearPersonal(s, datos)),
    asignarRol: protegido('admin.asignarRol', (s, id, rol) => AdminService.asignarRol(s, id, rol)),
    desactivarPersonal: protegido('admin.desactivar', (s, id) => AdminService.desactivarPersonal(s, id)),
    auditoria: protegido('admin.auditoria', (s, opciones) => AdminService.leerAuditoria(s, opciones))
  }
};
