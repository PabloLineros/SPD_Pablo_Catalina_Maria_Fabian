import { errores } from './errors.js';
import { logger } from './logger.js';
import { registrarAuditoria } from './audit.js';
import { DB, ROLES_BD } from '../db/repository.js';

/**
 * Modelo de Control de Acceso Basado en Roles (RBAC) — mínimo privilegio.
 * Todo lo que no está explícitamente concedido está DENEGADO (lista blanca).
 * La matriz que se presenta en el informe se genera desde este archivo (npm run matriz).
 */

export const ROLES = Object.freeze({
  ADMINISTRADOR: 'ADMINISTRADOR',           // Gestiona cuentas del personal, roles y auditoría
  OFICIAL_PRIVACIDAD: 'OFICIAL_PRIVACIDAD', // DPO: privacidad, derechos, notificación de incidentes
  SEGURIDAD: 'SEGURIDAD',                   // Responsable de seguridad: alertas, incidentes y contención
  SOPORTE: 'SOPORTE',                       // Atención al cliente y reclamos
  LOGISTICA: 'LOGISTICA',                   // Preparación y despacho de envíos
  CATALOGO: 'CATALOGO',                     // Productos, precios y stock
  MARKETING: 'MARKETING',                   // Campañas a suscriptores con consentimiento
  ANALISTA: 'ANALISTA',                     // Análisis de negocio sobre datos seudonimizados
  CLIENTE: 'CLIENTE'                        // Cliente registrado (usuario final)
});

export const ROLES_PERSONAL = Object.freeze(Object.values(ROLES).filter(r => r !== ROLES.CLIENTE));

export const PERMISOS = Object.freeze({
  ROLES_GESTIONAR: 'roles:gestionar',
  AUDITORIA_LEER: 'auditoria:leer',
  PERFIL_PROPIO_LEER: 'perfil:propio:leer',
  PERFIL_PROPIO_EDITAR: 'perfil:propio:editar',
  PEDIDO_CREAR: 'pedido:crear',
  PEDIDOS_PROPIOS_LEER: 'pedidos:propios:leer',
  PUNTOS_PROPIOS: 'puntos:propios',
  RESENA_PUBLICAR: 'resena:publicar',
  CONSENTIMIENTO_PROPIO: 'consentimiento:propio',
  CLIENTES_BUSCAR_ENMASCARADO: 'clientes:buscar:enmascarado',
  CLIENTES_PII_REVELAR: 'clientes:pii:revelar',
  PEDIDOS_GESTIONAR: 'pedidos:gestionar',
  ENVIOS_GESTIONAR: 'envios:gestionar',
  CATALOGO_GESTIONAR: 'catalogo:gestionar',
  MARKETING_EXPORTAR: 'marketing:exportar',
  ANALITICA_LEER: 'analitica:leer',
  REPORTES_AGREGADOS: 'reportes:agregados',
  PRIVACIDAD_PROCESOS: 'privacidad:procesos',
  SEUDONIMOS_REVERTIR: 'seudonimos:revertir',
  DERECHOS_SOLICITAR: 'derechos:propios:solicitar',
  DERECHOS_GESTIONAR: 'derechos:gestionar',
  CONSENTIMIENTO_TEXTOS: 'consentimiento:textos:publicar',
  AUDITORIA_RETENCION: 'auditoria:retencion',
  ALERTAS_GESTIONAR: 'alertas:gestionar',
  INCIDENTES_LEER: 'incidentes:leer',
  INCIDENTES_GESTIONAR: 'incidentes:gestionar',
  CONTENCION_EJECUTAR: 'contencion:ejecutar',
  RECUPERACION_EJECUTAR: 'recuperacion:ejecutar',
  INCIDENTES_NOTIFICAR: 'incidentes:notificar',
  LLAVES_ACCEDER: 'llaves:acceder'
});

/** Permisos que solo aplican sobre recursos del propio usuario (verificación de propiedad). */
const PERMISOS_PROPIOS = new Set([
  PERMISOS.PERFIL_PROPIO_LEER,
  PERMISOS.PERFIL_PROPIO_EDITAR,
  PERMISOS.PEDIDOS_PROPIOS_LEER,
  PERMISOS.PUNTOS_PROPIOS,
  PERMISOS.CONSENTIMIENTO_PROPIO,
  PERMISOS.DERECHOS_SOLICITAR
]);

const P = PERMISOS;

export const MATRIZ = Object.freeze({
  [ROLES.ADMINISTRADOR]: [P.ROLES_GESTIONAR, P.AUDITORIA_LEER, P.CLIENTES_BUSCAR_ENMASCARADO, P.PEDIDOS_GESTIONAR, P.REPORTES_AGREGADOS,
    P.INCIDENTES_LEER, P.RECUPERACION_EJECUTAR],
  [ROLES.OFICIAL_PRIVACIDAD]: [P.PRIVACIDAD_PROCESOS, P.SEUDONIMOS_REVERTIR, P.AUDITORIA_LEER, P.REPORTES_AGREGADOS,
    P.DERECHOS_GESTIONAR, P.CONSENTIMIENTO_TEXTOS, P.AUDITORIA_RETENCION, P.INCIDENTES_LEER, P.INCIDENTES_NOTIFICAR],
  [ROLES.SEGURIDAD]: [P.AUDITORIA_LEER, P.ALERTAS_GESTIONAR, P.INCIDENTES_LEER, P.INCIDENTES_GESTIONAR, P.CONTENCION_EJECUTAR],
  [ROLES.SOPORTE]: [P.CLIENTES_BUSCAR_ENMASCARADO, P.CLIENTES_PII_REVELAR, P.PEDIDOS_GESTIONAR],
  [ROLES.LOGISTICA]: [P.ENVIOS_GESTIONAR],
  [ROLES.CATALOGO]: [P.CATALOGO_GESTIONAR],
  [ROLES.MARKETING]: [P.MARKETING_EXPORTAR, P.REPORTES_AGREGADOS],
  [ROLES.ANALISTA]: [P.ANALITICA_LEER, P.REPORTES_AGREGADOS],
  [ROLES.CLIENTE]: [P.PERFIL_PROPIO_LEER, P.PERFIL_PROPIO_EDITAR, P.PEDIDO_CREAR,
    P.PEDIDOS_PROPIOS_LEER, P.PUNTOS_PROPIOS, P.RESENA_PUBLICAR, P.CONSENTIMIENTO_PROPIO, P.DERECHOS_SOLICITAR]
  // P.LLAVES_ACCEDER no se asigna a ningún rol: las llaves solo las usa src/crypto/ internamente.
});

export function tienePermiso(rol, permiso) {
  return Boolean(MATRIZ[rol]?.includes(permiso));
}

const bdControles = DB.conectar(ROLES_BD.SVC_APP);

/** Contención: un rol suspendido durante un incidente pierde TODOS sus permisos hasta la recuperación. */
export function rolSuspendido(rol) {
  return Boolean(bdControles.obtener('controles_operacion', `rol_suspendido:${rol}`)?.activo);
}

/**
 * Punto único de autorización del servidor. Lanza ACCESO_DENEGADO si:
 *  - no hay sesión válida,
 *  - el rol no tiene el permiso,
 *  - el permiso es "propio" y el recurso pertenece a otro usuario.
 * Toda denegación queda auditada (sin datos personales).
 * @param {{usuarioId:string, rol:string}} sesion
 * @param {string} permiso
 * @param {{propietarioId?: string, recurso?: string}} [opciones]
 */
export function autorizar(sesion, permiso, { propietarioId, recurso } = {}) {
  if (!sesion?.usuarioId || !sesion?.rol) {
    throw errores.noAutenticado();
  }

  let motivo = null;
  if (!tienePermiso(sesion.rol, permiso)) {
    motivo = 'ROL_SIN_PERMISO';
  } else if (rolSuspendido(sesion.rol)) {
    motivo = 'ROL_SUSPENDIDO_POR_INCIDENTE';
  } else if (PERMISOS_PROPIOS.has(permiso) && propietarioId !== sesion.usuarioId) {
    motivo = 'RECURSO_AJENO';
  }

  if (motivo) {
    registrarAuditoria({ sesion, accion: permiso, recurso, resultado: 'DENEGADO', motivo });
    logger.warn('acceso_denegado', { rol: sesion.rol, permiso, motivo });
    throw errores.accesoDenegado();
  }
}
