/**
 * Catálogo de eventos auditados de NortiShop (actividad de trazabilidad).
 *
 * Es la fuente única de:
 *  1. QUÉ se audita: cada acción que la aplicación registra, con su categoría.
 *  2. QUÉ datos personales toca cada evento: solo NOMBRES de campos (nunca valores) y el nivel de
 *     exposición (COMPLETO = se vio o se entregó el dato en claro; ENMASCARADO; REFERENCIA = solo
 *     identificadores internos).
 *  3. QUÉ campos tiene cada registro (CAMPOS_REGISTRO), para el informe y para las pruebas.
 *
 * registrarAuditoria() clasifica con este catálogo. Una acción que no calza con ninguna entrada
 * queda como NO_CATALOGADO y se reporta en el log de la aplicación; las pruebas exigen que no
 * exista ninguna (test/trazabilidad.test.js).
 */

/** Campos de cada registro de audit_log. Ninguno contiene el valor de un dato personal. */
export const CAMPOS_REGISTRO = Object.freeze([
  ['secuencia', 'Número consecutivo asignado por la base de datos (detecta registros eliminados).'],
  ['id', 'UUID del registro.'],
  ['created_at', 'Fecha y hora UTC del evento.'],
  ['actor_id', 'Quién: id interno del usuario o del personal; "cuenta:<prefijo índice ciego>" si no inició sesión; "sistema" para procesos.'],
  ['actor_rol', 'Rol con que actuó (CLIENTE, SOPORTE, SISTEMA, ANONIMO...).'],
  ['accion', 'Qué hizo, según este catálogo (p. ej. clientes:pii:revelar).'],
  ['categoria', 'Categoría del catálogo (ACCESO_DATOS, MODIFICACION, EXPORTACION...).'],
  ['recurso', 'Sobre qué objeto: tipo:id interno (users:<uuid>, envio:<ref>, solicitud:<folio>).'],
  ['titular_ref', 'De quién son los datos: id interno del titular afectado (o referencia del invitado/solicitante).'],
  ['datos', 'Qué datos personales se tocaron: NOMBRES de campos (nombre,direccion...), nunca sus valores.'],
  ['resultado', 'PERMITIDO, DENEGADO, EXITO o FALLIDO.'],
  ['motivo', 'Justificación o detalle sin datos personales (ticket, causa de denegación, contadores). Se redacta automáticamente.'],
  ['sesion_ref', 'Prefijo del SHA-256 del token de sesión: une las acciones de una misma sesión sin guardar el token.'],
  ['origen_ref', 'Seudónimo HMAC del origen de red (llave propia): agrupa por origen sin guardar la IP.'],
  ['correlacion_id', 'Id aleatorio de la solicitud HTTP/API que produjo el evento.'],
  ['hash_previo', 'Sello del registro anterior (encadenamiento).'],
  ['hash', 'HMAC(K_auditoria) de todo el registro y del sello anterior: detecta modificaciones.']
]);

/**
 * Vocabulario de datos personales que puede aparecer en el campo `datos`, y el tipo de dato que
 * usa el plan de respuesta (incidentService.TIPOS_DATOS) para evaluar el impacto y notificar.
 */
export const CAMPOS_DATOS = Object.freeze({
  nombre: 'IDENTIFICACION',
  email: 'CONTACTO',
  telefono: 'CONTACTO',
  direccion: 'DIRECCION',
  comuna: 'DIRECCION',
  medio_pago: 'FINANCIEROS',
  facturacion: 'IDENTIFICACION',
  pedidos: 'HISTORIAL_COMPRAS',
  puntos: 'HISTORIAL_COMPRAS',
  resena: 'HISTORIAL_COMPRAS',
  credenciales: 'CREDENCIALES',
  seudonimo: 'IDENTIFICACION',
  consentimientos: null,
  copia_completa: 'IDENTIFICACION'
});

const PERFIL = ['nombre', 'email', 'telefono', 'direccion', 'medio_pago'];
const ev = (patron, categoria, descripcion, datos = [], exposicion = null) => Object.freeze({ patron, categoria, descripcion, datos, exposicion });

/** El orden importa: gana la primera entrada que calza. */
export const EVENTOS = Object.freeze([
  // Autenticación y sesiones
  ev(/^auth:login$/, 'AUTENTICACION', 'Inicio de sesión exitoso o fallido (cuenta por índice ciego si falla).', ['credenciales'], 'REFERENCIA'),
  ev(/^auth:logout$/, 'AUTENTICACION', 'Cierre de sesión.'),
  ev(/^auth:registro$/, 'AUTENTICACION', 'Creación de una cuenta de cliente.', [...PERFIL, 'credenciales'], 'REFERENCIA'),

  // Accesos a datos personales
  ev(/^perfil:propio:leer$/, 'ACCESO_DATOS', 'El titular ve su perfil completo.', PERFIL, 'COMPLETO'),
  ev(/^pedidos:propios:leer$/, 'ACCESO_DATOS', 'El titular ve su historial de pedidos.', ['pedidos'], 'COMPLETO'),
  ev(/^puntos:consultar$/, 'ACCESO_DATOS', 'El titular consulta su saldo de NortiPuntos (tras verificar la firma).', ['puntos'], 'COMPLETO'),
  ev(/^invitado:pedido:consultar$/, 'ACCESO_DATOS', 'Seguimiento de un pedido sin cuenta por su token (solo estado y monto, sin contacto).', ['pedidos'], 'COMPLETO'),
  ev(/^clientes:buscar:enmascarado$/, 'ACCESO_DATOS', 'Soporte busca un cliente por correo exacto; ve datos enmascarados.', ['nombre', 'email', 'telefono'], 'ENMASCARADO'),
  ev(/^clientes:pii:revelar$/, 'ACCESO_SENSIBLE', 'Soporte revela los datos completos de un cliente (exige ticket y motivo).', ['nombre', 'email', 'telefono', 'direccion'], 'COMPLETO'),
  ev(/^envios:etiqueta$/, 'ACCESO_SENSIBLE', 'Logística genera una etiqueta: descifra nombre y dirección del destinatario.', ['nombre', 'direccion'], 'COMPLETO'),
  ev(/^seudonimos:revertir$/, 'ACCESO_SENSIBLE', 'El DPO revierte un seudónimo a la identidad interna.', ['seudonimo'], 'REFERENCIA'),
  ev(/^derechos:localizar$/, 'ACCESO_SENSIBLE', 'El DPO obtiene el mapa de tablas donde hay datos de un titular (sin contenido).', [], 'REFERENCIA'),

  // Operaciones sobre datos personales
  ev(/^perfil:propio:editar$/, 'MODIFICACION', 'El titular cambia su teléfono, dirección o comuna (campos en `datos`).', [], 'REFERENCIA'),
  ev(/^derechos:rectificacion:ejecutada$/, 'MODIFICACION', 'Se aplica una rectificación (valores anterior y nuevo solo cifrados en rectificaciones).', [], 'REFERENCIA'),
  ev(/^pedido:crear$/, 'TRANSACCION', 'Compra de un cliente: usa su dirección y, si existe, su medio de pago guardado.', ['direccion', 'pedidos'], 'REFERENCIA'),
  ev(/^puntos:canjear$/, 'TRANSACCION', 'Canje de NortiPuntos: cambia el saldo del titular.', ['puntos'], 'REFERENCIA'),
  ev(/^resena:publicar$/, 'MODIFICACION', 'Publicación de una reseña con autor seudonimizado (el titular interno solo queda en la auditoría).', ['resena'], 'REFERENCIA'),
  ev(/^invitado:pedido:crear$/, 'TRANSACCION', 'Compra sin cuenta: se guardan nombre, contacto y dirección cifrados.', ['nombre', 'email', 'telefono', 'direccion', 'medio_pago'], 'REFERENCIA'),
  ev(/^derechos:(acceso|portabilidad):(ejecutada|descargada)$/, 'EXPORTACION', 'Se genera o descarga la copia de los datos del titular.', ['copia_completa'], 'COMPLETO'),
  ev(/^derechos:supresion:(ejecutada|parcial)$/, 'SUPRESION', 'Supresión de los datos de un titular (o bloqueo legal de una parte).', [...PERFIL, 'pedidos', 'puntos', 'facturacion'], 'REFERENCIA'),
  ev(/^derechos:bloqueo:levantado$/, 'DERECHOS', 'Fin de un bloqueo de tratamiento.'),
  ev(/^derechos:oposicion:retirada$/, 'DERECHOS', 'El titular retira una oposición.'),
  ev(/^derechos:plazos:revision$/, 'DERECHOS', 'Revisión de solicitudes por vencer.'),
  ev(/^derechos:[a-z]+:[a-z]+$/, 'DERECHOS', 'Recepción, verificación, rechazo, anulación o cierre de una solicitud de derechos.'),
  ev(/^consentimiento:texto_publicado$/, 'CONSENTIMIENTO', 'Nueva versión del texto de una finalidad.'),
  ev(/^consentimiento:(otorgado|revocado|renovado)$/, 'CONSENTIMIENTO', 'Cambio del consentimiento de un titular para una finalidad.', ['consentimientos'], 'REFERENCIA'),
  ev(/^tratamiento:encuesta_satisfaccion$/, 'TRATAMIENTO', 'Envío (u omisión por oposición o bloqueo) de la encuesta de satisfacción.', ['email'], 'REFERENCIA'),
  ev(/^marketing:exportar$/, 'EXPORTACION', 'Exportación de la lista de suscriptores (correos cifrados) a la plataforma de correo.', ['email'], 'REFERENCIA'),
  ev(/^copia_desarrollo$/, 'EXPORTACION', 'Copia sintética de la base para desarrollo (sin datos reales).'),

  // Administración y procesos
  ev(/^roles:gestionar$/, 'ADMINISTRACION', 'Alta, cambio de rol o desactivación de una cuenta del personal.'),
  ev(/^catalogo:gestionar$/, 'ADMINISTRACION', 'Cambios en productos.'),
  ev(/^pedidos:gestionar$/, 'ADMINISTRACION', 'Listado o cancelación de pedidos (sin datos de contacto).'),
  ev(/^envios:estado$/, 'ADMINISTRACION', 'Cambio de estado de un envío.'),
  ev(/^(etl:analitica|job:[a-z_]+)$/, 'PROCESO_PRIVACIDAD', 'ETL seudonimizado, anonimización y eliminación por vencimiento de plazos.'),

  // Seguridad y la propia auditoría
  ev(/^seguridad:[a-z_]+$/, 'SEGURIDAD', 'Alertas de detección, descarte de alertas y fallas de integridad.'),
  ev(/^(incidente|contencion|recuperacion):[a-z_:]+$/, 'SEGURIDAD', 'Fases del incidente: apertura, análisis, evidencia, contención, recuperación, notificación y cierre.'),
  ev(/^auditoria:(consulta|verificacion|purga|reconstruccion)$/, 'AUDITORIA', 'Consulta, verificación, purga por retención o reconstrucción de la auditoría (cada acceso queda auditado).')
]);

/** Toda denegación se audita con el permiso pedido como acción. */
export const EVENTO_DENEGACION = Object.freeze({ categoria: 'CONTROL_ACCESO', descripcion: 'Intento de usar un permiso que el rol no tiene, sobre un recurso ajeno o con el rol suspendido.', datos: [], exposicion: null });

export function definicionEvento(accion, resultado) {
  if (resultado === 'DENEGADO') return EVENTO_DENEGACION;
  return EVENTOS.find(e => e.patron.test(accion)) ?? null;
}

const ALIAS = { direccionDespacho: 'direccion', guardarMedioPago: 'medio_pago', tarjeta: 'medio_pago' };
/** Traduce nombres de campos de la API (direccionDespacho...) al vocabulario de `datos`. */
export function camposDe(claves) {
  return [...new Set([...claves].map(c => ALIAS[c] ?? c).filter(c => c in CAMPOS_DATOS))];
}

/** Tipos de dato (para el plan de respuesta) a partir de la lista de campos de `datos`. */
export function tiposDeDatos(campos) {
  return [...new Set(campos.map(c => CAMPOS_DATOS[c]).filter(Boolean))];
}
