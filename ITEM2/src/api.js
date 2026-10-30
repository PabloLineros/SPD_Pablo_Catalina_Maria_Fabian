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
import { ConsentService } from './services/consentService.js';
import { RightsService } from './services/rightsService.js';
import { AuditService } from './services/auditService.js';
import { IncidentService } from './services/incidentService.js';
import * as Privacidad from './services/privacyService.js';
import './security/detection.js'; // activa la detección sobre el flujo de auditoría
import { respuestaDeError } from './security/errors.js';
import { logger } from './security/logger.js';

/**
 * Capa de API del servidor (la usan src/server.js, la demo y las pruebas).
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
    crearPedido: protegido('cliente.crearPedido', (s, entrada) => OrderService.crearPedido(s, entrada)),
    misPedidos: protegido('cliente.misPedidos', (s, userId) => OrderService.listarPedidosPropios(s, userId)),
    saldoPuntos: protegido('cliente.saldoPuntos', (s, userId) => LoyaltyService.saldoPropio(s, userId)),
    canjearPuntos: protegido('cliente.canjearPuntos', (s, userId, puntos) => LoyaltyService.canjear(s, userId, puntos)),
    publicarResena: protegido('cliente.publicarResena', (s, entrada) => ReviewService.publicar(s, entrada))
  },
  consentimiento: {
    estado: protegido('consentimiento.estado', (s, userId) => ConsentService.estado(s, userId)),
    otorgar: protegido('consentimiento.otorgar', (s, userId, entrada) => ConsentService.otorgar(s, userId, entrada)),
    revocar: protegido('consentimiento.revocar', (s, userId, entrada) => ConsentService.revocar(s, userId, entrada)),
    historial: protegido('consentimiento.historial', (s, userId) => ConsentService.historial(s, userId)),
    desuscribir: publico('consentimiento.desuscribir', (token) => ConsentService.desuscribirPorToken(token)),
    publicarVersion: protegido('consentimiento.publicarVersion', (s, entrada) => ConsentService.publicarVersion(s, entrada))
  },
  derechos: {
    solicitar: protegido('derechos.solicitar', (s, userId, entrada) => RightsService.solicitar(s, userId, entrada)),
    confirmar: protegido('derechos.confirmar', (s, userId, solicitudId, entrada) => RightsService.confirmar(s, userId, solicitudId, entrada)),
    misSolicitudes: protegido('derechos.misSolicitudes', (s, userId) => RightsService.misSolicitudes(s, userId)),
    gestion: protegido('derechos.gestion', (s) => RightsService.listarGestion(s))
  },
  invitado: {
    crearPedido: publico('invitado.crearPedido', (entrada) => OrderService.crearPedidoInvitado(entrada)),
    consultarPedido: publico('invitado.consultarPedido', (token) => OrderService.consultarPedidoInvitado(token))
  },
  marketing: {
    exportarSuscriptores: protegido('marketing.exportar', (s) => MarketingService.exportarSuscriptores(s))
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
    anonimizarInvitados: protegido('privacidad.anonimizar', (s, ahora) => Privacidad.anonimizarInvitadosVencidos(s, ahora ? new Date(ahora) : undefined)),
    revertirSeudonimo: protegido('privacidad.revertir', (s, entrada) => Privacidad.revertirSeudonimo(s, entrada)),
    copiaDesarrollo: protegido('privacidad.copiaDesarrollo', (s) => Privacidad.generarCopiaDesarrollo(s)),
    reaplicarSupresiones: protegido('privacidad.reaplicarSupresiones', (s) => Privacidad.reaplicarSupresiones(s))
  },
  auditoria: {
    consultar: protegido('auditoria.consultar', (s, filtros) => AuditService.consultar(s, filtros)),
    verificar: protegido('auditoria.verificar', (s) => AuditService.verificar(s)),
    purgarVencidos: protegido('auditoria.purgar', (s, ahora) => AuditService.purgarVencidos(s, ahora ? new Date(ahora) : undefined))
  },
  seguridad: {
    alertas: protegido('seguridad.alertas', (s, filtros) => IncidentService.listarAlertas(s, filtros)),
    descartarAlerta: protegido('seguridad.descartarAlerta', (s, id, entrada) => IncidentService.descartarAlerta(s, id, entrada)),
    abrirIncidente: protegido('seguridad.abrir', (s, entrada) => IncidentService.abrir(s, entrada)),
    analizar: protegido('seguridad.analizar', (s, id, entrada) => IncidentService.analizar(s, id, entrada)),
    preservarEvidencia: protegido('seguridad.evidencia', (s, id) => IncidentService.preservarEvidencia(s, id)),
    contener: protegido('seguridad.contener', (s, id, entrada) => IncidentService.contener(s, id, entrada)),
    erradicar: protegido('seguridad.erradicar', (s, id, entrada) => IncidentService.erradicar(s, id, entrada)),
    recuperar: protegido('seguridad.recuperar', (s, id) => IncidentService.recuperar(s, id)),
    evaluarNotificacion: protegido('seguridad.evaluarNotificacion', (s, id) => IncidentService.evaluarNotificacion(s, id)),
    autorizarNotificacion: protegido('seguridad.autorizarNotificacion', (s, id, entrada) => IncidentService.autorizarNotificacion(s, id, entrada)),
    cerrar: protegido('seguridad.cerrar', (s, id, entrada) => IncidentService.cerrar(s, id, entrada)),
    incidentes: protegido('seguridad.incidentes', (s) => IncidentService.listar(s)),
    detalle: protegido('seguridad.detalle', (s, id) => IncidentService.detalle(s, id))
  },
  admin: {
    crearPersonal: protegido('admin.crearPersonal', (s, datos) => AdminService.crearPersonal(s, datos)),
    asignarRol: protegido('admin.asignarRol', (s, id, rol) => AdminService.asignarRol(s, id, rol)),
    desactivarPersonal: protegido('admin.desactivar', (s, id) => AdminService.desactivarPersonal(s, id)),
    auditoria: protegido('admin.auditoria', (s, filtros) => AuditService.consultar(s, filtros))
  }
};
