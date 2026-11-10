import crypto from 'node:crypto';
import { CONFIG } from '../config/env.js';
import { FINALIDADES_CONSENTIMIENTO, FINALIDADES_OTRAS_BASES } from '../config/finalidades.js';
import { DB, ROLES_BD } from '../db/repository.js';
import { encryptField, decryptField, contexto } from '../crypto/cipher.js';
import { verifyPassword } from '../crypto/hashing.js';
import { hmacHex, compararHmac } from '../crypto/integrity.js';
import { FINALIDADES } from '../crypto/keyring.js';
import { seudonimo, indiceCiegoEmail } from '../crypto/pseudonymization.js';
import { enviarCorreo } from '../infra/correo.js';
import { comunicarATercero } from '../infra/terceros.js';
import { autorizar, PERMISOS } from '../security/rbac.js';
import { registrarAuditoria } from '../security/audit.js';
import { errores, AppError } from '../security/errors.js';
import { soloCampos, validar, enmascarar } from '../security/validation.js';
import { aplicarCambiosPerfil } from './userService.js';
import { suprimirCliente, impedimentoSupresion, anonimizarContactoInvitado } from './privacyService.js';
import {
  TRATAMIENTOS_OPONIBLES, MOTIVOS_BLOQUEO, tieneOposicion, bloqueoActivo,
  registrarOposicion, registrarBloqueo, levantarBloqueo
} from './restrictionService.js';

/**
 * Ejercicio de derechos del titular: acceso, portabilidad, rectificación, supresión, oposición y bloqueo.
 *
 * Canales:
 *   - CENTRO_PRIVACIDAD: titular con cuenta (sesión + contraseña, y código según el riesgo).
 *   - FORMULARIO_SIN_CUENTA: invitados o personas que ya no tienen cuenta (acceso y supresión),
 *     verificados con un código enviado al correo que informan: un dato que el sistema ya tiene.
 *
 * Flujo (estado y fecha de cada etapa en solicitudes_derechos, con folio de seguimiento):
 *   RECIBIDA -> VERIFICADA -> EN_EVALUACION -> CERRADA (EJECUTADA, PARCIAL o RECHAZADA, con fundamento)
 *   ANULADA si la verificación falla 5 veces o el código vence.
 *
 * Verificación proporcional al riesgo, sin pedir datos adicionales:
 *   RECTIFICACION (nombre, teléfono, dirección), OPOSICION, BLOQUEO: sesión + contraseña.
 *   RECTIFICACION de email: + código al correo NUEVO.
 *   ACCESO, PORTABILIDAD, SUPRESION: + código al correo REGISTRADO.
 *   Sin cuenta: código al correo informado.
 */

const bd = DB.conectar(ROLES_BD.SVC_APP);
const bdPrivacidad = DB.conectar(ROLES_BD.SVC_PRIVACIDAD);
const bdEtl = DB.conectar(ROLES_BD.SVC_ETL);

const TIPOS = ['ACCESO', 'PORTABILIDAD', 'RECTIFICACION', 'SUPRESION', 'OPOSICION', 'BLOQUEO'];
const TIPOS_SIN_CUENTA = ['ACCESO', 'SUPRESION'];
const CAMPOS_RECTIFICABLES = ['nombre', 'telefono', 'direccionDespacho', 'comuna', 'email'];
const ABIERTAS = ['RECIBIDA', 'VERIFICADA', 'EN_EVALUACION'];
const HORAS_DESCARGA = 24;
const DIAS_AVISO_VENCIMIENTO = 5;
const DIAS_ROTACION_RESPALDOS = 35;
const CORREO_DPO = 'privacidad@nortishop.test';

const ctxUser = (campo, id) => contexto('users', campo, id);
const ahoraIso = () => new Date().toISOString();
const sha256 = (t) => crypto.createHash('sha256').update(String(t)).digest('hex');

const ORIGEN = {
  TITULAR: 'Entregado por el titular',
  SISTEMA: 'Generado por NortiShop al usar el servicio',
  PASARELA: 'Recibido de la pasarela de pago'
};

function nuevoFolio() {
  const n = bd.seleccionar('solicitudes_derechos').length + 1;
  return `DER-${new Date().getFullYear()}-${String(n).padStart(6, '0')}`;
}

function nivelVerificacion(tipo, cambios) {
  if (tipo === 'RECTIFICACION') return cambios && 'email' in cambios ? 'CLAVE+CODIGO_EMAIL_NUEVO' : 'CLAVE';
  if (tipo === 'OPOSICION' || tipo === 'BLOQUEO') return 'CLAVE';
  return 'CLAVE+CODIGO_EMAIL_REGISTRADO';
}

/** Valida los valores propuestos ANTES de aceptar la solicitud (reglas del sistema). */
function validarCambios(cambios) {
  soloCampos(cambios, { opcionales: CAMPOS_RECTIFICABLES });
  if (Object.keys(cambios).length === 0) throw errores.datoInvalido('Indique al menos un dato a rectificar.');
  if ('nombre' in cambios) validar.nombre(cambios.nombre);
  if ('telefono' in cambios && cambios.telefono !== null) validar.telefono(cambios.telefono);
  if ('direccionDespacho' in cambios) validar.direccion(cambios.direccionDespacho);
  if ('comuna' in cambios) validar.comuna(cambios.comuna);
  if ('email' in cambios) validar.email(cambios.email);
}

function registrarVerificacion(solicitud, destino, destinoEmail) {
  const codigo = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  const conCodigo = destino !== 'SOLO_CONTRASENA';
  bd.insertar('verificaciones', {
    id: crypto.randomUUID(),
    solicitud_id: solicitud.id,
    codigo_hmac: hmacHex(FINALIDADES.VERIFICACION, `${solicitud.id}:${conCodigo ? codigo : crypto.randomBytes(16).toString('hex')}`),
    destino,
    expira_el: conCodigo ? new Date(Date.now() + CONFIG.CODIGO_VERIFICACION_MINUTOS * 60_000).toISOString() : solicitud.plazo_vence_el,
    intentos: 0,
    usado: false
  });
  if (conCodigo) {
    enviarCorreo({
      para: destinoEmail,
      asunto: `NortiShop: confirma tu solicitud ${solicitud.folio}`,
      cuerpo: `Tu código para confirmar la solicitud de ${solicitud.tipo.toLowerCase()} (folio ${solicitud.folio}) es ${codigo}. ` +
        `Vence en ${CONFIG.CODIGO_VERIFICACION_MINUTOS} minutos. Si no hiciste esta solicitud, ignora este mensaje.`
    });
  }
}

function resumen(s) {
  return {
    id: s.id, folio: s.folio, canal: s.canal, presentada_por: s.presentada_por,
    tipo: s.tipo, objeto: s.objeto ?? null, estado: s.estado, resultado: s.resultado ?? null,
    campos_solicitados: s.campos_solicitados ? s.campos_solicitados.split(',') : null,
    nivel_verificacion: s.nivel_verificacion, fundamento: s.fundamento ?? null,
    recibida_el: s.recibida_el, verificada_el: s.verificada_el ?? null, evaluada_el: s.evaluada_el ?? null,
    resuelta_el: s.resuelta_el ?? null, cerrada_el: s.cerrada_el ?? null, plazo_vence_el: s.plazo_vence_el
  };
}

/** Actor de auditoría para quien no tiene sesión: prefijo del índice ciego de su correo. */
const actorSinCuenta = (s) => ({ usuarioId: `solicitante:${s.titular_ref.slice(0, 12)}`, rol: 'ANONIMO' });

function transicion(actor, solicitud, cambios, evento, resultado = 'EXITO', motivo = null) {
  const actualizada = bd.actualizar('solicitudes_derechos', solicitud.id, cambios);
  registrarAuditoria({ sesion: actor, accion: `derechos:${solicitud.tipo.toLowerCase()}:${evento}`, recurso: `solicitud:${solicitud.folio}`, resultado, motivo });
  return actualizada;
}

/** Verifica contraseña (si corresponde) y código; ANULA la solicitud tras 5 fallos o si el código venció. */
async function verificarIdentidad(actor, s, { password, codigo }, passwordHash) {
  const verif = bd.buscarUno('verificaciones', v => v.solicitud_id === s.id && !v.usado);
  const requiereClave = s.canal === 'CENTRO_PRIVACIDAD';
  const requiereCodigo = s.nivel_verificacion !== 'CLAVE';

  if (requiereCodigo && verif && Date.parse(verif.expira_el) <= Date.now()) {
    bd.actualizar('verificaciones', verif.id, { usado: true });
    transicion(actor, s, { estado: 'ANULADA', cerrada_el: ahoraIso(), fundamento: 'El código de verificación venció. Puede presentar una nueva solicitud.' }, 'anulada', 'FALLIDO', 'CODIGO_VENCIDO');
    throw errores.datoInvalido('El código venció. Presente una nueva solicitud.');
  }
  const claveOk = !requiereClave || await verifyPassword(password, passwordHash);
  const codigoOk = !requiereCodigo || Boolean(verif && /^\d{6}$/.test(String(codigo ?? '')) &&
    compararHmac(hmacHex(FINALIDADES.VERIFICACION, `${s.id}:${codigo}`), verif.codigo_hmac));

  if (!claveOk || !codigoOk) {
    const intentos = (verif?.intentos ?? 0) + 1;
    if (verif) bd.actualizar('verificaciones', verif.id, { intentos });
    registrarAuditoria({ sesion: actor, accion: `derechos:${s.tipo.toLowerCase()}:verificacion`, recurso: `solicitud:${s.folio}`, resultado: 'FALLIDO', motivo: `intento=${intentos}` });
    if (intentos >= CONFIG.CODIGO_VERIFICACION_MAX_INTENTOS) {
      if (verif) bd.actualizar('verificaciones', verif.id, { usado: true });
      transicion(actor, s, { estado: 'ANULADA', cerrada_el: ahoraIso(), fundamento: 'Se superó el máximo de intentos de verificación.' }, 'anulada', 'FALLIDO', 'MAX_INTENTOS');
    }
    throw new AppError('CREDENCIALES_INVALIDAS', 'No fue posible verificar su identidad.');
  }
  if (verif) bd.actualizar('verificaciones', verif.id, { usado: true });
  const verificada = transicion(actor, s, { estado: 'VERIFICADA', verificada_el: ahoraIso() }, 'verificada');
  return bd.actualizar('solicitudes_derechos', verificada.id, { estado: 'EN_EVALUACION', evaluada_el: ahoraIso() });
}

function cerrar(actor, s, resultado, fundamento, motivoAuditoria) {
  const cierre = ahoraIso();
  const evento = { EJECUTADA: 'ejecutada', PARCIAL: 'parcial', RECHAZADA: 'rechazada' }[resultado];
  return transicion(actor, s, {
    estado: 'CERRADA', resultado, fundamento, resuelta_el: cierre, cerrada_el: cierre,
    cambios_cifrados: null // los valores propuestos ya no son necesarios
  }, evento, resultado === 'RECHAZADA' ? 'FALLIDO' : 'EXITO', motivoAuditoria ?? fundamento);
}

/**
 * Copia de la exportación cifrada, con enlace (token) de un solo uso que vence en 24 horas.
 * El token no se guarda: solo su SHA-256.
 */
function crearDescarga(solicitud, datos, userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const id = sha256(token);
  const expira = new Date(Date.now() + HORAS_DESCARGA * 3_600_000).toISOString();
  bd.insertar('descargas', {
    id, solicitud_id: solicitud.id, user_id: userId ?? null,
    contenido_cifrado: encryptField(JSON.stringify(datos), contexto('descargas', 'contenido_cifrado', id)),
    expira_el: expira, created_at: ahoraIso()
  });
  return { token, expira_el: expira, formato: 'application/json', un_solo_uso: true };
}

const DESCRIPCIONES = {
  users: 'Cuenta y datos de contacto',
  orders: 'Pedidos',
  order_items: 'Productos de cada pedido',
  envios: 'Estado de los envíos',
  facturacion: 'Datos de facturación',
  loyalty_accounts: 'Saldo de NortiPuntos',
  historial_puntos: 'Movimientos de NortiPuntos',
  'resenas (por seudónimo)': 'Reseñas publicadas (con alias)',
  consentimientos: 'Estado de sus consentimientos',
  consentimientos_historial: 'Historial de sus consentimientos',
  suscripciones_marketing: 'Lista de envío de ofertas',
  solicitudes_derechos: 'Sus solicitudes de derechos',
  rectificaciones: 'Registro de sus rectificaciones',
  oposiciones: 'Sus oposiciones',
  bloqueos: 'Bloqueos de sus datos',
  'descargas pendientes': 'Copias de sus datos pendientes de descarga',
  sesiones: 'Sesiones abiertas',
  'analitica.compras (por seudónimo)': 'Análisis de compras (seudonimizado)',
  'pseudo.pseudonimos': 'Identificadores seudónimos que lo representan'
};

/**
 * Mapa de dónde hay datos del titular (sin su contenido): todas las tablas que lo referencian por
 * su identificador único, los datos derivados por seudónimo y los terceros que los recibieron.
 */
export function localizarDatosTitular(userId) {
  const pedidos = bd.seleccionar('orders', o => o.user_id === userId);
  const idsPedidos = new Set(pedidos.map(o => o.id));
  const pseudoResenas = seudonimo('resenas', userId);
  const pseudoAnalitica = seudonimo('analitica', userId);
  const usuario = bd.obtener('users', userId);
  const suscripcion = bd.buscarUno('suscripciones_marketing', s => s.user_id === userId);
  const contar = (conexion, tabla, filtro) => conexion.seleccionar(tabla, filtro).length;

  const ubicaciones = [
    ['users', usuario ? 1 : 0], ['orders', pedidos.length],
    ['order_items', contar(bd, 'order_items', i => idsPedidos.has(i.order_id))],
    ['envios', contar(bd, 'envios', e => idsPedidos.has(e.order_id))],
    ['facturacion', contar(bd, 'facturacion', f => f.user_id === userId)],
    ['loyalty_accounts', bd.obtener('loyalty_accounts', userId) ? 1 : 0],
    ['historial_puntos', contar(bd, 'historial_puntos', h => h.user_id === userId)],
    ['resenas (por seudónimo)', contar(bdPrivacidad, 'resenas', r => r.autor_pseudo === pseudoResenas)],
    ['consentimientos', contar(bd, 'consentimientos', c => c.user_id === userId)],
    ['consentimientos_historial', contar(bd, 'consentimientos_historial', c => c.user_id === userId)],
    ['suscripciones_marketing', suscripcion ? 1 : 0],
    ['solicitudes_derechos', contar(bd, 'solicitudes_derechos', s => s.user_id === userId)],
    ['rectificaciones', contar(bd, 'rectificaciones', r => r.user_id === userId)],
    ['oposiciones', contar(bd, 'oposiciones', o => o.user_id === userId)],
    ['bloqueos', contar(bd, 'bloqueos', b => b.user_id === userId)],
    ['descargas pendientes', contar(bd, 'descargas', d => d.user_id === userId)],
    ['sesiones', contar(bd, 'sesiones', s => s.usuario_id === userId)],
    ['analitica.compras (por seudónimo)', contar(bdEtl, 'analitica.compras', a => a.cliente_pseudo === pseudoAnalitica)],
    ['pseudo.pseudonimos', contar(bdPrivacidad, 'pseudo.pseudonimos', p => p.user_id === userId)]
  ].filter(([, n]) => n > 0).map(([ubicacion, registros]) => ({ ubicacion, descripcion: DESCRIPCIONES[ubicacion], registros }));

  const terceros = [];
  if (usuario?.token_pago) terceros.push({ tercero: 'Pasarela de pago', datos: 'Número de tarjeta, vencimiento y titular (NortiShop solo guarda un token y los últimos 4 dígitos)' });
  if (suscripcion) terceros.push({ tercero: 'Plataforma de correo', datos: 'Correo electrónico y seudónimo de suscriptor' });
  if (pedidos.length) terceros.push({ tercero: 'Operador logístico', datos: 'Nombre, dirección y comuna de despacho, con una referencia de envío aleatoria' });
  return { ubicaciones, terceros };
}

function valoresActuales(userId, campos) {
  const u = bd.obtener('users', userId);
  const leer = (col) => (u[col] ? decryptField(u[col], ctxUser(col, userId)) : null);
  const mapa = {
    nombre: () => leer('nombre_cifrado'), telefono: () => leer('telefono_cifrado'),
    direccionDespacho: () => leer('direccion_despacho_cifrada'), comuna: () => u.comuna, email: () => leer('email_cifrado')
  };
  return Object.fromEntries(campos.map(c => [c, mapa[c]()]));
}

/** Copia de los datos del titular con cuenta. Excluye información interna y datos de terceros. */
function construirExportacion(userId, tipo) {
  const u = bd.obtener('users', userId);
  const productos = new Map(bd.seleccionar('productos').map(p => [p.id, p.nombre]));
  const envios = new Map(bd.seleccionar('envios').map(e => [e.order_id, e.estado_envio]));
  const pseudoResenas = seudonimo('resenas', userId);

  const datos = {
    formato: 'nortishop.export.v1',
    tipo,
    generado_el: ahoraIso(),
    titular_id: userId,
    datos_personales: {
      nombre: decryptField(u.nombre_cifrado, ctxUser('nombre_cifrado', userId)),
      email: decryptField(u.email_cifrado, ctxUser('email_cifrado', userId)),
      telefono: u.telefono_cifrado ? decryptField(u.telefono_cifrado, ctxUser('telefono_cifrado', userId)) : null,
      direccion_despacho: decryptField(u.direccion_despacho_cifrada, ctxUser('direccion_despacho_cifrada', userId)),
      comuna: u.comuna,
      mayor_de_edad_declarado_el: u.mayor_edad_declarado_el,
      cuenta_creada_el: u.created_at,
      medio_pago_guardado: u.guardar_medio_pago ? { marca: u.tarjeta_marca, ultimos_4: u.tarjeta_last4 } : null
    },
    pedidos: bd.seleccionar('orders', o => o.user_id === userId).map(o => ({
      id: o.id,
      fecha: o.created_at,
      estado: o.estado,
      estado_envio: envios.get(o.id) ?? null,
      total_clp: o.total_clp,
      documento: o.tipo_documento,
      comuna_envio: o.comuna_envio,
      direccion_envio: o.direccion_envio_cifrada ? decryptField(o.direccion_envio_cifrada, contexto('orders', 'direccion_envio_cifrada', o.id)) : null,
      productos: bd.seleccionar('order_items', i => i.order_id === o.id)
        .map(i => ({ producto: productos.get(i.producto_id) ?? i.producto_id, cantidad: i.cantidad, precio_unitario_clp: i.precio_unitario_clp }))
    })),
    datos_facturacion: bd.seleccionar('facturacion', f => f.user_id === userId).map(f => ({
      rut: decryptField(f.rut_facturacion_cifrado, contexto('facturacion', 'rut_facturacion_cifrado', f.id)),
      razon_social: decryptField(f.razon_social_cifrada, contexto('facturacion', 'razon_social_cifrada', f.id)),
      direccion: decryptField(f.direccion_facturacion_cifrada, contexto('facturacion', 'direccion_facturacion_cifrada', f.id))
    })),
    nortipuntos: {
      saldo: bd.obtener('loyalty_accounts', userId)?.saldo_puntos ?? 0,
      movimientos: bd.seleccionar('historial_puntos', h => h.user_id === userId).map(({ created_at, delta, motivo }) => ({ fecha: created_at, delta, motivo }))
    },
    resenas: bdPrivacidad.seleccionar('resenas', r => r.autor_pseudo === pseudoResenas).map(r => ({
      producto: productos.get(r.producto_id) ?? r.producto_id, alias: r.alias_publico, calificacion: r.calificacion, comentario: r.comentario, fecha: r.created_at
    })),
    origen_y_finalidad: {
      datos_personales: { origen: ORIGEN.TITULAR, finalidad: 'Gestión de la cuenta, compras y despacho' },
      medio_pago_guardado: { origen: ORIGEN.PASARELA, finalidad: 'Pagar futuras compras (consentimiento GUARDAR_MEDIO_PAGO)' },
      pedidos: { origen: `${ORIGEN.TITULAR} (productos) y ${ORIGEN.SISTEMA} (estado, totales)`, finalidad: 'Ejecución del contrato de compraventa y despacho' },
      datos_facturacion: { origen: ORIGEN.TITULAR, finalidad: 'Emisión de facturas (obligación legal)' },
      nortipuntos: { origen: ORIGEN.SISTEMA, finalidad: 'Programa de fidelización' },
      resenas: { origen: ORIGEN.TITULAR, finalidad: 'Publicación de reseñas con alias' }
    }
  };

  if (tipo === 'ACCESO') {
    const decifrar = (r, col) => (r[col] ? decryptField(r[col], contexto('rectificaciones', col, r.id)) : null);
    datos.consentimientos = bd.seleccionar('consentimientos_historial', h => h.user_id === userId)
      .map(({ finalidad, accion, version_texto, canal, ocurrido_el }) => ({ finalidad, accion, version_texto, canal, ocurrido_el }));
    datos.rectificaciones = bd.seleccionar('rectificaciones', r => r.user_id === userId)
      .map(r => ({ campo: r.campo, valor_anterior: decifrar(r, 'valor_anterior_cifrado'), valor_nuevo: decifrar(r, 'valor_nuevo_cifrado'), fecha: r.created_at }));
    datos.oposiciones = bd.seleccionar('oposiciones', o => o.user_id === userId).map(({ tratamiento, estado, desde, retirada_el }) => ({ tratamiento, estado, desde, retirada_el }));
    datos.bloqueos = bd.seleccionar('bloqueos', b => b.user_id === userId).map(({ motivo, estado, desde, levantado_el }) => ({ motivo, estado, desde, levantado_el }));
    datos.solicitudes_de_derechos = bd.seleccionar('solicitudes_derechos', s => s.user_id === userId)
      .map(s => ({ folio: s.folio, tipo: s.tipo, estado: s.estado, resultado: s.resultado ?? null, recibida_el: s.recibida_el, cerrada_el: s.cerrada_el ?? null }));
    const mapa = localizarDatosTitular(userId);
    datos.informacion_del_tratamiento = {
      finalidades: [
        ...Object.entries(FINALIDADES_CONSENTIMIENTO).map(([codigo, f]) => ({ codigo, nombre: f.nombre, base: 'CONSENTIMIENTO' })),
        ...Object.entries(FINALIDADES_OTRAS_BASES).map(([codigo, f]) => ({ codigo, nombre: f.nombre, base: f.base }))
      ],
      donde_se_encontraron_sus_datos: mapa.ubicaciones.map(({ descripcion, registros }) => ({ descripcion, registros })),
      destinatarios: mapa.terceros,
      plazos_de_conservacion: {
        cuenta: 'Mientras la cuenta esté activa.',
        documentos_tributarios: '6 años (Código Tributario, art. 17), bloqueados ante supresión y luego eliminados.',
        contacto_de_invitados: '90 días desde la entrega.',
        historial_de_puntos: '2 años.',
        respaldos: `Se sobrescriben en un máximo de ${DIAS_ROTACION_RESPALDOS} días.`,
        auditoria: '24 meses, sin datos personales.'
      },
      contacto_privacidad: CORREO_DPO
    };
  }
  // NO se incluye: hash de contraseña, índice ciego, token de pago, seudónimos, ids de transacción
  // y autorización, referencias de envío, registros de auditoría ni datos de otros titulares.
  return datos;
}

/** Copia para quien compró como invitado (solo pedidos asociados a su correo). */
function exportarInvitado(pedidos, tipo) {
  const leer = (o, col) => (o[col] ? decryptField(o[col], contexto('orders_invitado', col, o.id)) : null);
  return {
    formato: 'nortishop.export.v1',
    tipo,
    generado_el: ahoraIso(),
    pedidos_como_invitado: pedidos.map(o => ({
      fecha: o.created_at, estado: o.estado, total_clp: o.total_clp, comuna_envio: o.comuna_envio,
      nombre: leer(o, 'nombre_invitado_cifrado'), email: leer(o, 'email_invitado_cifrado'),
      telefono: leer(o, 'telefono_invitado_cifrado'), direccion_envio: leer(o, 'direccion_envio_cifrada')
    })),
    origen_y_finalidad: { pedidos_como_invitado: { origen: ORIGEN.TITULAR, finalidad: 'Ejecución de la compra y despacho' } },
    informacion_del_tratamiento: {
      destinatarios: ['Pasarela de pago (datos de la tarjeta, no los guarda NortiShop)', 'Operador logístico (nombre, dirección y comuna)'],
      plazo_de_conservacion: 'El contacto se elimina 90 días después de la entrega; montos y estado se conservan por obligación contable.',
      contacto_privacidad: CORREO_DPO
    }
  };
}

function ejecutarRectificacion(sesion, s, userId) {
  const cambios = JSON.parse(decryptField(s.cambios_cifrados, contexto('solicitudes_derechos', 'cambios_cifrados', s.id)));
  const anteriores = valoresActuales(userId, Object.keys(cambios));
  const r = aplicarCambiosPerfil(userId, cambios);

  // Registro del cambio: valor anterior, valor nuevo, quién y cuándo (cifrados con su contexto).
  const ahora = ahoraIso();
  for (const campo of r.modificados) {
    const id = crypto.randomUUID();
    const cifrar = (v, col) => (v === null || v === undefined ? null : encryptField(String(v), contexto('rectificaciones', col, id)));
    bd.insertar('rectificaciones', {
      id, solicitud_id: s.id, user_id: userId, campo,
      valor_anterior_cifrado: cifrar(anteriores[campo], 'valor_anterior_cifrado'),
      valor_nuevo_cifrado: cifrar(cambios[campo], 'valor_nuevo_cifrado'),
      actor_id: sesion.usuarioId, actor_rol: sesion.rol, created_at: ahora
    });
  }

  // La corrección se comunica a los terceros que habían recibido el dato.
  const avisados = [];
  for (const p of r.propagado) {
    if (p.startsWith('orders:')) {
      const envio = bd.buscarUno('envios', e => e.order_id === p.slice(7) && e.estado_envio === 'PENDIENTE');
      if (envio) avisados.push(comunicarATercero({ tercero: 'OPERADOR_LOGISTICO', tipo: 'RECTIFICACION', referencia: `actualizar dirección envio:${envio.ref_envio}`, solicitudId: s.id }).tercero);
    } else if (p === 'suscripciones_marketing') {
      const sus = bd.buscarUno('suscripciones_marketing', x => x.user_id === userId);
      avisados.push(comunicarATercero({ tercero: 'PLATAFORMA_CORREO', tipo: 'RECTIFICACION', referencia: `actualizar correo suscriptor:${sus.suscriptor_pseudo}`, solicitudId: s.id }).tercero);
    }
  }
  // Si los datos estaban bloqueados por exactitud en disputa, la rectificación resuelve la causa.
  const bloqueo = bloqueoActivo(userId);
  if (bloqueo?.motivo === 'EXACTITUD_EN_DISPUTA') levantarBloqueo(userId, `Exactitud resuelta por rectificación ${s.folio}`, sesion);

  const partes = [`Se corrigió: ${r.modificados.join(', ')}.`];
  if (r.propagado.length) partes.push(`Actualizado también en ${r.propagado.length} registro(s) relacionado(s) (pedidos no despachados, lista de envío).`);
  if (avisados.length) partes.push(`Se comunicó la corrección a: ${[...new Set(avisados)].join(', ')}.`);
  if (bloqueo?.motivo === 'EXACTITUD_EN_DISPUTA') partes.push('Se levantó el bloqueo de sus datos.');
  return { fundamento: partes.join(' '), motivo: `campos=${r.modificados.join(',')}; propagado_a=${r.propagado.length}; terceros=${avisados.length}` };
}

function ejecutarSupresion(s, userId) {
  const impedimento = impedimentoSupresion(userId);
  if (impedimento) return { resultado: 'RECHAZADA', fundamento: impedimento };
  const r = suprimirCliente(userId, s.id);
  const partes = ['Se eliminaron su cuenta, datos de contacto y dirección, puntos, suscripciones, medio de pago guardado, sesiones, copias exportadas y seudónimos.'];
  if (r.facturasBloqueadas || r.pedidosConservados) {
    partes.push(`Se conservan BLOQUEADOS ${r.facturasBloqueadas} documento(s) tributario(s) y los montos de ${r.pedidosConservados} pedido(s), sin datos de contacto, ` +
      `solo para cumplir la obligación tributaria (Código Tributario, art. 17)${r.bloqueadasHasta ? ` hasta el ${r.bloqueadasHasta.slice(0, 10)}` : ''}; después se eliminan.`);
  }
  if (r.tercerosNotificados.length) partes.push(`Se comunicó la supresión a: ${r.tercerosNotificados.join(', ')}.`);
  partes.push(`Los respaldos se sobrescriben en un máximo de ${DIAS_ROTACION_RESPALDOS} días; si se restaura uno, la supresión se vuelve a aplicar.`);
  return { resultado: r.facturasBloqueadas || r.pedidosConservados ? 'PARCIAL' : 'EJECUTADA', fundamento: partes.join(' ') };
}

export class RightsService {
  static solicitar(sesion, userId, entrada) {
    autorizar(sesion, PERMISOS.DERECHOS_SOLICITAR, { propietarioId: userId, recurso: `derechos:${userId}` });
    soloCampos(entrada, { obligatorios: ['tipo'], opcionales: ['cambios', 'tratamiento', 'motivo'] });
    if (!TIPOS.includes(entrada.tipo)) throw errores.datoInvalido(`tipo debe ser uno de: ${TIPOS.join(', ')}.`);
    const user = bd.obtener('users', userId);
    if (!user) throw errores.noEncontrado('Usuario');
    if (bd.buscarUno('solicitudes_derechos', s => s.user_id === userId && s.tipo === entrada.tipo && ABIERTAS.includes(s.estado))) {
      throw errores.conflicto('Ya tiene una solicitud de este tipo en curso.');
    }

    const permitido = { RECTIFICACION: 'cambios', OPOSICION: 'tratamiento', BLOQUEO: 'motivo' }[entrada.tipo];
    const sobrantes = ['cambios', 'tratamiento', 'motivo'].filter(c => c !== permitido && entrada[c] !== undefined);
    if (sobrantes.length) throw errores.campoNoPermitido(sobrantes);
    if (entrada.tipo === 'RECTIFICACION') validarCambios(entrada.cambios ?? {});
    if (entrada.tipo === 'OPOSICION') {
      if (!(entrada.tratamiento in TRATAMIENTOS_OPONIBLES)) throw errores.datoInvalido(`tratamiento debe ser: ${Object.keys(TRATAMIENTOS_OPONIBLES).join(', ')}.`);
      if (tieneOposicion(userId, entrada.tratamiento)) throw errores.conflicto('Ya se opuso a ese tratamiento.');
    }
    if (entrada.tipo === 'BLOQUEO') {
      if (!(entrada.motivo in MOTIVOS_BLOQUEO)) throw errores.datoInvalido(`motivo debe ser: ${Object.keys(MOTIVOS_BLOQUEO).join(', ')}.`);
      if (bloqueoActivo(userId)) throw errores.conflicto('Sus datos ya están bloqueados.');
    }

    const id = crypto.randomUUID();
    const recibida = new Date();
    const solicitud = bd.insertar('solicitudes_derechos', {
      id, folio: nuevoFolio(), user_id: userId, canal: 'CENTRO_PRIVACIDAD', presentada_por: 'TITULAR',
      tipo: entrada.tipo, estado: 'RECIBIDA',
      nivel_verificacion: nivelVerificacion(entrada.tipo, entrada.cambios),
      objeto: entrada.tratamiento ?? entrada.motivo ?? null,
      campos_solicitados: entrada.cambios ? Object.keys(entrada.cambios).join(',') : null,
      cambios_cifrados: entrada.cambios ? encryptField(JSON.stringify(entrada.cambios), contexto('solicitudes_derechos', 'cambios_cifrados', id)) : null,
      recibida_el: recibida.toISOString(),
      plazo_vence_el: new Date(recibida.getTime() + CONFIG.PLAZO_RESPUESTA_DERECHOS_DIAS * 86_400_000).toISOString()
    });

    const emailRegistrado = decryptField(user.email_cifrado, ctxUser('email_cifrado', userId));
    let destinoCodigo = null;
    if (solicitud.nivel_verificacion === 'CLAVE') {
      registrarVerificacion(solicitud, 'SOLO_CONTRASENA');
    } else if (solicitud.nivel_verificacion === 'CLAVE+CODIGO_EMAIL_REGISTRADO') {
      registrarVerificacion(solicitud, 'EMAIL_REGISTRADO', emailRegistrado);
      destinoCodigo = enmascarar.email(emailRegistrado);
    } else {
      const nuevo = validar.email(entrada.cambios.email);
      registrarVerificacion(solicitud, 'EMAIL_NUEVO', nuevo);
      destinoCodigo = enmascarar.email(nuevo);
      // Aviso al correo actual: si no fue el titular, puede reaccionar antes de que se confirme.
      enviarCorreo({ para: emailRegistrado, asunto: 'NortiShop: solicitud de cambio de correo', cuerpo: 'Se solicitó cambiar el correo de tu cuenta. Si no fuiste tú, cambia tu contraseña.' });
    }
    registrarAuditoria({ sesion, accion: `derechos:${entrada.tipo.toLowerCase()}:recibida`, recurso: `solicitud:${solicitud.folio}`, resultado: 'EXITO', motivo: solicitud.campos_solicitados ? `campos=${solicitud.campos_solicitados}` : solicitud.objeto });

    return {
      ...resumen(solicitud),
      verificacion: { requiereContrasena: true, requiereCodigo: destinoCodigo !== null, codigoEnviadoA: destinoCodigo }
    };
  }

  /**
   * Verifica la identidad y, si corresponde, evalúa, ejecuta y cierra la solicitud. Para ACCESO y
   * PORTABILIDAD entrega un enlace de descarga temporal y de un solo uso.
   */
  static async confirmar(sesion, userId, solicitudId, entrada) {
    autorizar(sesion, PERMISOS.DERECHOS_SOLICITAR, { propietarioId: userId, recurso: `derechos:${userId}` });
    soloCampos(entrada, { obligatorios: ['password'], opcionales: ['codigo'] });
    let s = bd.obtener('solicitudes_derechos', String(solicitudId));
    if (!s || s.user_id !== userId) throw errores.noEncontrado('Solicitud');
    if (s.estado !== 'RECIBIDA') throw errores.conflicto(`La solicitud está ${s.estado.toLowerCase()}.`);

    s = await verificarIdentidad(sesion, s, entrada, bd.obtener('users', userId).password_hash);

    let resultado = 'EJECUTADA';
    let fundamento = null;
    let motivo = null;
    let descarga = null;

    if (s.tipo === 'ACCESO' || s.tipo === 'PORTABILIDAD') {
      const datos = construirExportacion(userId, s.tipo);
      descarga = crearDescarga(s, datos, userId);
      fundamento = `Su copia está lista para descargar una sola vez antes del ${descarga.expira_el.replace('T', ' ').slice(0, 16)} UTC.`;
      motivo = `formato=${datos.formato}; pedidos=${datos.pedidos.length}`;
    } else if (s.tipo === 'RECTIFICACION') {
      try {
        ({ fundamento, motivo } = ejecutarRectificacion(sesion, s, userId));
      } catch (e) {
        if (!(e instanceof AppError)) throw e;
        resultado = 'RECHAZADA';
        fundamento = e.message;
      }
    } else if (s.tipo === 'SUPRESION') {
      ({ resultado, fundamento } = ejecutarSupresion(s, userId));
    } else if (s.tipo === 'OPOSICION') {
      registrarOposicion(userId, s.objeto, s.id);
      fundamento = `Desde ahora no usaremos sus datos para: ${TRATAMIENTOS_OPONIBLES[s.objeto]}. El resto del servicio no cambia.`;
    } else if (s.tipo === 'BLOQUEO') {
      registrarBloqueo(userId, s.objeto, s.id);
      const sus = bd.buscarUno('suscripciones_marketing', x => x.user_id === userId);
      if (sus) comunicarATercero({ tercero: 'PLATAFORMA_CORREO', tipo: 'BLOQUEO', referencia: `suspender suscriptor:${sus.suscriptor_pseudo}`, solicitudId: s.id });
      fundamento = 'Sus datos quedan restringidos: los conservamos, pero no los usamos para marketing, análisis ni encuestas. ' +
        'Solo se usan para cumplir sus pedidos en curso, obligaciones legales y atenderle. El bloqueo se levanta al corregir los datos o cuando usted lo pida.';
    }

    s = cerrar(sesion, s, resultado, fundamento, motivo);
    return { solicitud: resumen(s), descarga };
  }

  /** Descarga de un solo uso. Las copias de titulares con cuenta exigen además su sesión. */
  static descargar(sesion, token) {
    const id = sha256(token);
    const d = bd.obtener('descargas', id);
    if (!d) throw errores.noEncontrado('Descarga (ya usada o vencida)');
    if (d.user_id) {
      autorizar(sesion, PERMISOS.DERECHOS_SOLICITAR, { propietarioId: d.user_id, recurso: `descarga:${d.solicitud_id}` });
    }
    bd.eliminar('descargas', id); // un solo uso: la copia deja de existir al entregarse
    if (Date.parse(d.expira_el) <= Date.now()) throw errores.noEncontrado('Descarga (ya usada o vencida)');
    const datos = JSON.parse(decryptField(d.contenido_cifrado, contexto('descargas', 'contenido_cifrado', id)));
    const s = bd.obtener('solicitudes_derechos', d.solicitud_id);
    registrarAuditoria({ sesion: sesion ?? actorSinCuenta(s), accion: `derechos:${s.tipo.toLowerCase()}:descargada`, recurso: `solicitud:${s.folio}`, resultado: 'EXITO' });
    return datos;
  }

  /** El titular levanta el bloqueo que pidió (desapareció la causa). */
  static levantarBloqueoPropio(sesion, userId) {
    autorizar(sesion, PERMISOS.DERECHOS_SOLICITAR, { propietarioId: userId, recurso: `bloqueo:${userId}` });
    const r = levantarBloqueo(userId, 'A petición del titular', sesion);
    if (!r) throw errores.conflicto('No tiene datos bloqueados.');
    return { estado: r.estado, levantado_el: r.levantado_el };
  }

  /** Retira una oposición propia (vuelve a aceptar el tratamiento). */
  static retirarOposicion(sesion, userId, entrada) {
    autorizar(sesion, PERMISOS.DERECHOS_SOLICITAR, { propietarioId: userId, recurso: `oposicion:${userId}` });
    soloCampos(entrada, { obligatorios: ['tratamiento'] });
    if (!tieneOposicion(userId, entrada.tratamiento)) throw errores.conflicto('No tiene una oposición activa a ese tratamiento.');
    bd.actualizar('oposiciones', `${userId}:${entrada.tratamiento}`, { estado: 'RETIRADA', retirada_el: ahoraIso() });
    registrarAuditoria({ sesion, accion: 'derechos:oposicion:retirada', recurso: `oposicion:${entrada.tratamiento}`, resultado: 'EXITO' });
    return { tratamiento: entrada.tratamiento, estado: 'RETIRADA' };
  }

  /** Estado de las restricciones del titular (para el Centro de privacidad). */
  static misRestricciones(sesion, userId) {
    autorizar(sesion, PERMISOS.DERECHOS_SOLICITAR, { propietarioId: userId, recurso: `derechos:${userId}` });
    const b = bloqueoActivo(userId);
    return {
      oposiciones: Object.entries(TRATAMIENTOS_OPONIBLES).map(([tratamiento, descripcion]) => ({ tratamiento, descripcion, activa: tieneOposicion(userId, tratamiento) })),
      bloqueo: b ? { motivo: b.motivo, desde: b.desde } : null
    };
  }

  // ---------- Canal para quien no tiene cuenta (invitados o ex clientes) ----------

  /** Recibe la solicitud y envía un código al correo informado. La respuesta no revela si hay datos. */
  static solicitarSinCuenta(entrada) {
    soloCampos(entrada, { obligatorios: ['email', 'tipo'] });
    if (!TIPOS_SIN_CUENTA.includes(entrada.tipo)) throw errores.datoInvalido(`Sin cuenta puede solicitar: ${TIPOS_SIN_CUENTA.join(', ')}.`);
    const email = validar.email(entrada.email);
    const ref = indiceCiegoEmail(email);
    if (bd.buscarUno('solicitudes_derechos', s => s.titular_ref === ref && s.tipo === entrada.tipo && ABIERTAS.includes(s.estado))) {
      throw errores.conflicto('Ya hay una solicitud de este tipo en curso para ese correo.');
    }
    const recibida = new Date();
    const solicitud = bd.insertar('solicitudes_derechos', {
      id: crypto.randomUUID(), folio: nuevoFolio(), user_id: null, titular_ref: ref,
      canal: 'FORMULARIO_SIN_CUENTA', presentada_por: 'TITULAR', tipo: entrada.tipo, estado: 'RECIBIDA',
      nivel_verificacion: 'CODIGO_EMAIL_INFORMADO',
      recibida_el: recibida.toISOString(),
      plazo_vence_el: new Date(recibida.getTime() + CONFIG.PLAZO_RESPUESTA_DERECHOS_DIAS * 86_400_000).toISOString()
    });
    registrarVerificacion(solicitud, 'EMAIL_INFORMADO', email);
    registrarAuditoria({ sesion: actorSinCuenta(solicitud), accion: `derechos:${entrada.tipo.toLowerCase()}:recibida`, recurso: `solicitud:${solicitud.folio}`, resultado: 'EXITO', motivo: 'canal=FORMULARIO_SIN_CUENTA' });
    return { ...resumen(solicitud), mensaje: `Enviamos un código a ${enmascarar.email(email)}. Ingréselo para continuar.` };
  }

  static async confirmarSinCuenta(entrada) {
    soloCampos(entrada, { obligatorios: ['solicitudId', 'codigo'] });
    let s = bd.obtener('solicitudes_derechos', String(entrada.solicitudId));
    if (!s || s.canal !== 'FORMULARIO_SIN_CUENTA') throw errores.noEncontrado('Solicitud');
    if (s.estado !== 'RECIBIDA') throw errores.conflicto(`La solicitud está ${s.estado.toLowerCase()}.`);
    const actor = actorSinCuenta(s);
    s = await verificarIdentidad(actor, s, { codigo: entrada.codigo });

    let resultado = 'EJECUTADA';
    let fundamento;
    let descarga = null;
    const pedidos = bd.seleccionar('orders_invitado', o => o.email_hmac === s.titular_ref);

    if (bd.buscarUno('users', u => u.email_hmac === s.titular_ref)) {
      resultado = 'RECHAZADA';
      fundamento = 'Este correo pertenece a una cuenta activa. Por seguridad, ejerza el derecho ingresando al Centro de privacidad, donde además se verifica su contraseña.';
    } else if (pedidos.length === 0) {
      fundamento = 'No encontramos datos personales asociados a ese correo.';
    } else if (s.tipo === 'ACCESO') {
      descarga = crearDescarga(s, exportarInvitado(pedidos, 'ACCESO'), null);
      fundamento = `Encontramos ${pedidos.length} pedido(s) como invitado. Su copia está lista para descargar una sola vez antes del ${descarga.expira_el.replace('T', ' ').slice(0, 16)} UTC.`;
    } else {
      const enCurso = pedidos.filter(o => !['ENTREGADO', 'CANCELADO'].includes(o.estado));
      if (enCurso.length) {
        resultado = 'RECHAZADA';
        fundamento = `Tiene ${enCurso.length} pedido(s) en curso: el contacto es necesario para la entrega. Podrá solicitar la supresión cuando finalicen.`;
      } else {
        for (const o of pedidos) anonimizarContactoInvitado(o.id);
        resultado = 'PARCIAL';
        fundamento = `Se eliminó su nombre, correo, teléfono y dirección de ${pedidos.length} pedido(s). Se conservan el monto, el estado y la fecha, sin datos de contacto, por obligación contable.`;
      }
    }
    s = cerrar(actor, s, resultado, fundamento, `canal=FORMULARIO_SIN_CUENTA; pedidos=${pedidos.length}`);
    return { solicitud: resumen(s), descarga };
  }

  // ---------- Seguimiento del Oficial de Privacidad ----------

  static misSolicitudes(sesion, userId) {
    autorizar(sesion, PERMISOS.DERECHOS_SOLICITAR, { propietarioId: userId, recurso: `derechos:${userId}` });
    return bd.seleccionar('solicitudes_derechos', s => s.user_id === userId).map(resumen);
  }

  /** Seguimiento: estados, fechas y días restantes, sin datos personales. */
  static listarGestion(sesion, ahora = new Date()) {
    autorizar(sesion, PERMISOS.DERECHOS_GESTIONAR, { recurso: 'solicitudes_derechos' });
    return bd.seleccionar('solicitudes_derechos').map(s => {
      const abierta = ABIERTAS.includes(s.estado);
      const dias = Math.ceil((Date.parse(s.plazo_vence_el) - ahora.getTime()) / 86_400_000);
      return {
        ...resumen(s), titular_id: s.user_id,
        dias_restantes: abierta ? dias : null,
        por_vencer: abierta && dias >= 0 && dias <= DIAS_AVISO_VENCIMIENTO,
        vencida: abierta && dias < 0
      };
    });
  }

  /** Job diario: avisa al equipo de privacidad de las solicitudes abiertas próximas a vencer o vencidas. */
  static revisarPlazos(sesion, ahora = new Date()) {
    const pendientes = RightsService.listarGestion(sesion, ahora).filter(s => s.por_vencer || s.vencida);
    if (pendientes.length) {
      enviarCorreo({
        para: CORREO_DPO,
        asunto: `NortiShop: ${pendientes.length} solicitud(es) de derechos por vencer`,
        cuerpo: pendientes.map(s => `${s.folio} (${s.tipo}, ${s.estado}): ${s.vencida ? 'VENCIDA' : `vence en ${s.dias_restantes} día(s)`}`).join('\n')
      });
    }
    registrarAuditoria({ sesion, accion: 'derechos:plazos:revision', recurso: 'solicitudes_derechos', resultado: 'EXITO', motivo: `por_vencer_o_vencidas=${pendientes.length}` });
    return pendientes.map(({ folio, tipo, estado, dias_restantes, vencida }) => ({ folio, tipo, estado, dias_restantes, vencida }));
  }

  /** Mapa de dónde hay datos de un titular (sin contenido), para atender una solicitud. */
  static localizar(sesion, userId) {
    autorizar(sesion, PERMISOS.DERECHOS_GESTIONAR, { recurso: `users:${userId}` });
    const mapa = localizarDatosTitular(validar.uuid(userId, 'userId'));
    registrarAuditoria({ sesion, accion: 'derechos:localizar', recurso: `users:${userId}`, resultado: 'EXITO', motivo: `ubicaciones=${mapa.ubicaciones.length}` });
    return mapa;
  }
}
