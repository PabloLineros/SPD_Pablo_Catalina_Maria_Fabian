import crypto from 'node:crypto';
import { CONFIG } from '../config/env.js';
import { DB, ROLES_BD } from '../db/repository.js';
import { seudonimo, huellaSupresion } from '../crypto/pseudonymization.js';
import { titularesHabilitados, revocarTodoPorSupresion } from './consentService.js';
import { autorizar, PERMISOS } from '../security/rbac.js';
import { registrarAuditoria } from '../security/audit.js';
import { errores } from '../security/errors.js';
import { soloCampos } from '../security/validation.js';
import { logger } from '../security/logger.js';
import { cerrarTodasLasSesiones } from './authService.js';

/**
 * Servicio de Privacidad: seudonimización, anonimización y derechos del titular.
 * Usa credenciales de BD separadas:
 *  - svc_privacidad: único rol con acceso a pseudo.pseudonimos (tabla que revierte seudónimos).
 *  - svc_etl: lee tablas operativas y escribe SOLO en el esquema analitica.
 *  - rol_analista: lee SOLO el esquema analitica.
 */

const bdApp = DB.conectar(ROLES_BD.SVC_APP);
const bdPrivacidad = DB.conectar(ROLES_BD.SVC_PRIVACIDAD);
const bdEtl = DB.conectar(ROLES_BD.SVC_ETL);
const bdAnalista = DB.conectar(ROLES_BD.ROL_ANALISTA);

/**
 * Calcula el seudónimo HMAC de un usuario para una finalidad y registra la equivalencia
 * en pseudo.pseudonimos (necesaria para atender derechos del titular o una orden judicial).
 */
export function seudonimoRegistrado(finalidad, userId) {
  const pseudoId = seudonimo(finalidad, userId);
  const id = `${finalidad}:${pseudoId}`;
  if (!bdPrivacidad.obtener('pseudo.pseudonimos', id)) {
    bdPrivacidad.insertar('pseudo.pseudonimos', {
      id, pseudo_id: pseudoId, user_id: userId, finalidad, creado_el: new Date().toISOString()
    });
  }
  return pseudoId;
}

/**
 * Reidentificación EXCEPCIONAL: solo OFICIAL_PRIVACIDAD, con motivo documentado y auditoría.
 */
export function revertirSeudonimo(sesion, entrada) {
  autorizar(sesion, PERMISOS.SEUDONIMOS_REVERTIR, { recurso: 'pseudo.pseudonimos' });
  soloCampos(entrada, { obligatorios: ['pseudoId', 'finalidad', 'motivo'] });
  const motivo = String(entrada.motivo).trim();
  if (motivo.length < 15) throw errores.datoInvalido('Debe documentar el motivo de la reidentificación (mín. 15 caracteres).');

  const fila = bdPrivacidad.obtener('pseudo.pseudonimos', `${entrada.finalidad}:${entrada.pseudoId}`);
  registrarAuditoria({ sesion, accion: PERMISOS.SEUDONIMOS_REVERTIR, recurso: `pseudo:${String(entrada.pseudoId).slice(0, 12)}`, resultado: 'PERMITIDO', motivo });
  if (!fila) throw errores.noEncontrado('Seudónimo');
  return { userId: fila.user_id, finalidad: fila.finalidad };
}

const rangoMonto = (total) => (total < 20000 ? '0-20k' : total < 50000 ? '20-50k' : total < 100000 ? '50-100k' : '100k+');
const primerDiaDelMes = (iso) => `${iso.slice(0, 7)}-01`;

/**
 * ETL hacia el esquema analitica: seudonimiza (HMAC con llave de analítica) y generaliza
 * (mes en vez de fecha, rango en vez de monto, categoría en vez de producto, comuna en vez
 * de dirección). Suprime ids de pedido, transacción, autorización, tarjeta y dirección.
 * Solo incluye a titulares con consentimiento ANALITICA_COMPRAS vigente y no suprimidos.
 */
export function ejecutarEtlAnalitica(sesion) {
  autorizar(sesion, PERMISOS.PRIVACIDAD_PROCESOS, { recurso: 'analitica' });

  for (const t of ['analitica.compras', 'analitica.movimientos_puntos']) {
    for (const f of bdEtl.seleccionar(t)) bdEtl.eliminar(t, f.id);
  }

  const habilitados = titularesHabilitados('ANALITICA_COMPRAS', bdEtl);
  const suprimidos = new Set(bdEtl.seleccionar('supresiones').map(s => s.id));
  const incluir = (userId) => habilitados.has(userId) && !suprimidos.has(huellaSupresion(userId));

  const productos = new Map(bdEtl.seleccionar('productos').map(p => [p.id, p]));
  const items = bdEtl.seleccionar('order_items');
  let compras = 0;
  for (const o of bdEtl.seleccionar('orders', o => o.estado !== 'CANCELADO' && incluir(o.user_id))) {
    const categorias = new Set(items.filter(i => i.order_id === o.id).map(i => productos.get(i.producto_id)?.categoria ?? 'OTRA'));
    const clientePseudo = seudonimoRegistrado('analitica', o.user_id);
    for (const categoria of categorias) {
      bdEtl.insertar('analitica.compras', {
        id: crypto.randomUUID(),
        cliente_pseudo: clientePseudo,
        mes_compra: primerDiaDelMes(o.created_at),
        rango_monto: rangoMonto(o.total_clp),
        categoria_producto: categoria,
        comuna: o.comuna_envio
      });
      compras++;
    }
  }

  let movimientos = 0;
  for (const h of bdEtl.seleccionar('historial_puntos', x => incluir(x.user_id))) {
    bdEtl.insertar('analitica.movimientos_puntos', {
      id: crypto.randomUUID(),
      cliente_pseudo: seudonimoRegistrado('analitica', h.user_id),
      mes_movimiento: primerDiaDelMes(h.created_at),
      motivo: h.motivo,
      delta: h.delta
    });
    movimientos++;
  }

  registrarAuditoria({ sesion, accion: 'etl:analitica', recurso: 'analitica', resultado: 'EXITO', motivo: `titulares con consentimiento=${habilitados.size}` });
  return { compras, movimientos };
}

/** Datos seudonimizados para análisis (sin PII, sin seudónimos de otras finalidades). */
export function consultarAnalitica(sesion) {
  autorizar(sesion, PERMISOS.ANALITICA_LEER, { recurso: 'analitica.compras' });
  return bdAnalista.seleccionar('analitica.compras');
}

/** Reporte ANONIMIZADO: agregado y con supresión de grupos con menos de k clientes. */
export function ventasPorComuna(sesion) {
  autorizar(sesion, PERMISOS.REPORTES_AGREGADOS, { recurso: 'analitica.v_ventas_por_comuna' });
  return bdAnalista.vista('analitica.v_ventas_por_comuna', { k: CONFIG.K_ANONIMATO });
}

/**
 * Job diario: anonimiza pedidos de invitados cuyo plazo de conservación venció.
 * Conserva total, estado y fechas (obligación contable); elimina todo dato de contacto.
 */
export function anonimizarInvitadosVencidos(sesion, ahora = new Date()) {
  autorizar(sesion, PERMISOS.PRIVACIDAD_PROCESOS, { recurso: 'orders_invitado' });
  const vencidos = bdPrivacidad.seleccionar('orders_invitado', o =>
    o.eliminar_contacto_desde && Date.parse(o.eliminar_contacto_desde) <= ahora.getTime() &&
    ['ENTREGADO', 'CANCELADO'].includes(o.estado) &&
    (o.nombre_invitado_cifrado || o.email_invitado_cifrado || o.telefono_invitado_cifrado || o.direccion_envio_cifrada));

  for (const o of vencidos) {
    bdPrivacidad.actualizar('orders_invitado', o.id, {
      nombre_invitado_cifrado: null,
      email_invitado_cifrado: null,
      telefono_invitado_cifrado: null,
      direccion_envio_cifrada: null
    });
  }
  registrarAuditoria({ sesion, accion: 'job:anonimizar_invitados', recurso: 'orders_invitado', resultado: 'PERMITIDO', motivo: `${vencidos.length} registros` });
  return { anonimizados: vencidos.length };
}

/** Motivo fundamentado por el que la supresión no puede ejecutarse ahora (o null si procede). */
export function impedimentoSupresion(userId) {
  const enCurso = bdApp.seleccionar('orders', o => o.user_id === userId && !['ENTREGADO', 'CANCELADO'].includes(o.estado));
  if (enCurso.length > 0) {
    return `La cuenta tiene ${enCurso.length} pedido(s) en curso. Sus datos son necesarios para cumplir el contrato (entrega); podrá solicitar la supresión cuando finalicen.`;
  }
  return null;
}

/**
 * Derecho de supresión del titular.
 *  - Elimina: cuenta, contacto, dirección de pedidos, puntos, suscripción, token de pago, sesiones,
 *    equivalencias de seudónimos y filas analíticas.
 *  - Revoca todos los consentimientos (el historial queda como prueba, sin datos personales).
 *  - BLOQUEA (no borra) la facturación y conserva montos/estados de pedidos: obligación tributaria
 *    de conservar documentos (Código Tributario, art. 17: 6 años).
 *  - Registra una lápida (HMAC del user_id) para que el ETL y la restauración de respaldos no
 *    vuelvan a usar sus datos.
 */
export function suprimirCliente(userId) {
  const usuario = bdApp.obtener('users', userId);
  if (!usuario) throw errores.noEncontrado('Usuario');
  const impedimento = impedimentoSupresion(userId);
  if (impedimento) throw errores.conflicto(impedimento);

  const huella = huellaSupresion(userId);
  if (!bdApp.obtener('supresiones', huella)) bdApp.insertar('supresiones', { id: huella, suprimido_el: new Date().toISOString() });
  return limpiarDatosTitular(userId);
}

function limpiarDatosTitular(userId) {
  revocarTodoPorSupresion(userId); // token de pago, suscripción y filas analíticas
  const pedidos = bdApp.seleccionar('orders', o => o.user_id === userId);
  for (const o of pedidos) bdApp.actualizar('orders', o.id, { direccion_envio_cifrada: null });
  for (const f of bdApp.seleccionar('facturacion', f => f.user_id === userId)) bdApp.actualizar('facturacion', f.id, { bloqueado: true });
  for (const h of bdApp.seleccionar('historial_puntos', h => h.user_id === userId)) bdApp.eliminar('historial_puntos', h.id);
  bdApp.eliminar('loyalty_accounts', userId);
  const pseudo = seudonimo('analitica', userId);
  for (const t of ['analitica.compras', 'analitica.movimientos_puntos']) {
    for (const f of bdEtl.seleccionar(t, x => x.cliente_pseudo === pseudo)) bdEtl.eliminar(t, f.id);
  }
  // Sin la tabla de equivalencias, las reseñas del titular dejan de ser atribuibles.
  for (const p of bdPrivacidad.seleccionar('pseudo.pseudonimos', p => p.user_id === userId)) bdPrivacidad.eliminar('pseudo.pseudonimos', p.id);
  cerrarTodasLasSesiones(userId);
  bdApp.eliminar('users', userId);

  logger.info('cuenta_suprimida', { usuarioId: userId });
  return { suprimido: true, pedidosConservados: pedidos.length, facturasBloqueadas: bdApp.seleccionar('facturacion', f => f.user_id === userId).length };
}

/**
 * Tras restaurar un respaldo anterior, vuelve a aplicar las supresiones registradas: ningún
 * titular suprimido "revive" por una restauración. Se ejecuta antes de reabrir el servicio.
 */
export function reaplicarSupresiones(sesion) {
  autorizar(sesion, PERMISOS.PRIVACIDAD_PROCESOS, { recurso: 'supresiones' });
  const suprimidos = new Set(bdApp.seleccionar('supresiones').map(s => s.id));
  const revividos = bdApp.seleccionar('users', u => suprimidos.has(huellaSupresion(u.id)));
  for (const u of revividos) limpiarDatosTitular(u.id);
  registrarAuditoria({ sesion, accion: 'job:reaplicar_supresiones', recurso: 'users', resultado: 'EXITO', motivo: `${revividos.length} titulares` });
  return { reaplicadas: revividos.length };
}

/**
 * Copia para ambientes de desarrollo/pruebas: NUNCA se copian datos reales.
 * Identificadores re-generados, PII reemplazada por datos sintéticos, sin hashes, tokens ni
 * criptogramas (el ambiente de desarrollo usa sus propias llaves). Se conservan solo
 * distribuciones útiles para probar (comunas, montos, estados).
 */
export function generarCopiaDesarrollo(sesion) {
  autorizar(sesion, PERMISOS.PRIVACIDAD_PROCESOS, { recurso: 'copia_desarrollo' });
  const nuevoId = new Map();
  const idFicticio = (id) => {
    if (!nuevoId.has(id)) nuevoId.set(id, crypto.randomUUID());
    return nuevoId.get(id);
  };

  const usuarios = bdApp.seleccionar('users').map((u, i) => ({
    id: idFicticio(u.id),
    nombre: `Cliente Prueba ${i + 1}`,
    email: `cliente${i + 1}@ejemplo.test`,
    direccion_despacho: `Direccion Sintetica ${100 + i}`,
    comuna: u.comuna
  }));
  const pedidos = bdApp.seleccionar('orders').map(o => ({
    id: idFicticio(o.id),
    user_id: idFicticio(o.user_id),
    total_clp: o.total_clp,
    comuna_envio: o.comuna_envio,
    estado: o.estado,
    tipo_documento: o.tipo_documento
  }));

  registrarAuditoria({ sesion, accion: 'copia_desarrollo', recurso: 'users,orders', resultado: 'PERMITIDO' });
  return { usuarios, pedidos };
}
