/**
 * Catálogo de finalidades del tratamiento de NortiShop.
 *
 * Cada finalidad declara su BASE DE LICITUD. Solo las que tienen base CONSENTIMIENTO pasan por
 * el módulo de consentimiento; las demás (contrato, obligación legal, interés legítimo) no se le
 * piden al usuario porque no dependen de su autorización, y pedirla sería engañoso.
 *
 * El texto informado se versiona: si cambia el texto de una finalidad, se publica una versión
 * nueva y los consentimientos otorgados sobre la versión anterior dejan de habilitar el
 * tratamiento hasta que el titular los renueve.
 */

export const BASES = Object.freeze({
  CONSENTIMIENTO: 'CONSENTIMIENTO',
  CONTRATO: 'EJECUCION_DEL_CONTRATO',
  OBLIGACION_LEGAL: 'OBLIGACION_LEGAL',
  INTERES_LEGITIMO: 'INTERES_LEGITIMO'
});

/** Finalidades que requieren consentimiento (una decisión independiente por cada una). */
export const FINALIDADES_CONSENTIMIENTO = Object.freeze({
  MARKETING_EMAIL: {
    nombre: 'Ofertas y novedades por correo',
    version: '2.0',
    texto: 'Autorizo a NortiShop a usar mi correo electrónico para enviarme ofertas y novedades. ' +
      'Puedo retirar esta autorización en cualquier momento desde el Centro de privacidad o con el enlace de cada correo.',
    procesos: ['Exportación de suscriptores a la plataforma de correo (v_export_marketing)']
  },
  GUARDAR_MEDIO_PAGO: {
    nombre: 'Guardar mi tarjeta para próximas compras',
    version: '1.0',
    texto: 'Autorizo a NortiShop a conservar un token de mi tarjeta, emitido por la pasarela de pago, y sus últimos 4 dígitos, ' +
      'para pagar futuras compras sin volver a ingresarla. NortiShop nunca almacena el número completo.',
    procesos: ['Cobro con token guardado', 'Visualización de los últimos 4 dígitos en el perfil']
  },
  ANALITICA_COMPRAS: {
    nombre: 'Análisis de mis compras para mejorar la tienda',
    version: '1.0',
    texto: 'Autorizo a NortiShop a incluir mi historial de compras, seudonimizado y generalizado por mes, rango de monto, ' +
      'categoría y comuna, en sus análisis de negocio.',
    procesos: ['ETL hacia el esquema analitica', 'Reportes agregados por comuna']
  }
});

/** Tratamientos que NO dependen del consentimiento (se informan, no se piden). */
export const FINALIDADES_OTRAS_BASES = Object.freeze({
  CUENTA_Y_COMPRAS: { nombre: 'Gestión de la cuenta y de las compras', base: BASES.CONTRATO },
  DESPACHO: { nombre: 'Despacho de pedidos', base: BASES.CONTRATO },
  FACTURACION: { nombre: 'Emisión y conservación de boletas y facturas', base: BASES.OBLIGACION_LEGAL },
  NORTIPUNTOS: { nombre: 'Programa NortiPuntos', base: BASES.CONTRATO },
  SEGURIDAD: { nombre: 'Seguridad, auditoría y prevención de fraude', base: BASES.INTERES_LEGITIMO }
});

export const CODIGOS_FINALIDAD = Object.freeze(Object.keys(FINALIDADES_CONSENTIMIENTO));
