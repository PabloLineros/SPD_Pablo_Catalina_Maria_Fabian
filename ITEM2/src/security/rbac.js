import { errores } from './errors.js';
import { logger } from './logger.js';
import { registrarAuditoria } from './audit.js';

/**
 * Modelo de Control de Acceso Basado en Roles (RBAC) — mínimo privilegio.
 * Todo lo que no está explícitamente concedido está DENEGADO (lista blanca).
 * La matriz que se presenta en el informe se genera desde este archivo (npm run matriz).
 */

export const ROLES = Object.freeze({
  ADMINISTRADOR: 'ADMINISTRADOR',           // Gestiona cuentas del personal, roles y auditoría
  OFICIAL_PRIVACIDAD: 'OFICIAL_PRIVACIDAD', // DPO: procesos de privacidad y reidentificación excepcional
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
  CUENTA_PROPIA_SUPRIMIR: 'cuenta:propia:suprimir',
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
  LLAVES_ACCEDER: 'llaves:acceder'
});

/** Permisos que solo aplican sobre recursos del propio usuario (verificación de propiedad). */
const PERMISOS_PROPIOS = new Set([
  PERMISOS.PERFIL_PROPIO_LEER,
  PERMISOS.PERFIL_PROPIO_EDITAR,
  PERMISOS.CUENTA_PROPIA_SUPRIMIR,
  PERMISOS.PEDIDOS_PROPIOS_LEER,
  PERMISOS.PUNTOS_PROPIOS,
  PERMISOS.CONSENTIMIENTO_PROPIO
]);

const P = PERMISOS;

export const MATRIZ = Object.freeze({
  [ROLES.ADMINISTRADOR]: [P.ROLES_GESTIONAR, P.AUDITORIA_LEER, P.CLIENTES_BUSCAR_ENMASCARADO, P.PEDIDOS_GESTIONAR, P.REPORTES_AGREGADOS],
  [ROLES.OFICIAL_PRIVACIDAD]: [P.PRIVACIDAD_PROCESOS, P.SEUDONIMOS_REVERTIR, P.AUDITORIA_LEER, P.REPORTES_AGREGADOS],
  [ROLES.SOPORTE]: [P.CLIENTES_BUSCAR_ENMASCARADO, P.CLIENTES_PII_REVELAR, P.PEDIDOS_GESTIONAR],
  [ROLES.LOGISTICA]: [P.ENVIOS_GESTIONAR],
  [ROLES.CATALOGO]: [P.CATALOGO_GESTIONAR],
  [ROLES.MARKETING]: [P.MARKETING_EXPORTAR, P.REPORTES_AGREGADOS],
  [ROLES.ANALISTA]: [P.ANALITICA_LEER, P.REPORTES_AGREGADOS],
  [ROLES.CLIENTE]: [P.PERFIL_PROPIO_LEER, P.PERFIL_PROPIO_EDITAR, P.CUENTA_PROPIA_SUPRIMIR, P.PEDIDO_CREAR,
    P.PEDIDOS_PROPIOS_LEER, P.PUNTOS_PROPIOS, P.RESENA_PUBLICAR, P.CONSENTIMIENTO_PROPIO]
  // P.LLAVES_ACCEDER no se asigna a ningún rol: las llaves solo las usa src/crypto/ internamente.
});

export function tienePermiso(rol, permiso) {
  return Boolean(MATRIZ[rol]?.includes(permiso));
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
  } else if (PERMISOS_PROPIOS.has(permiso) && propietarioId !== sesion.usuarioId) {
    motivo = 'RECURSO_AJENO';
  }

  if (motivo) {
    registrarAuditoria({ sesion, accion: permiso, recurso, resultado: 'DENEGADO', motivo });
    logger.warn('acceso_denegado', { rol: sesion.rol, permiso, motivo });
    throw errores.accesoDenegado();
  }
}
