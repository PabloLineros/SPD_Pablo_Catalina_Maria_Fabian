/**
 * Proveedor de correo SIMULADO.
 * El envío real (SMTP o API de un proveedor) es infraestructura externa no disponible en este
 * prototipo; esta bandeja en memoria permite verificar la lógica (códigos de verificación,
 * notificaciones) en la demo, las pruebas y la pantalla de desarrollo.
 * El contenido de los correos nunca se escribe en los registros de actividad.
 */

const enviados = [];

export function enviarCorreo({ para, asunto, cuerpo }) {
  enviados.push({ para: String(para).toLowerCase(), asunto, cuerpo, enviado_el: new Date().toISOString() });
}

/** Solo para desarrollo y pruebas: mensajes recibidos por una dirección. */
export function bandejaDe(email) {
  return enviados.filter(m => m.para === String(email).toLowerCase()).map(m => ({ ...m }));
}

export function ultimoCodigoPara(email) {
  const m = bandejaDe(email).reverse().find(x => /\b\d{6}\b/.test(x.cuerpo));
  return m?.cuerpo.match(/\b(\d{6})\b/)[1] ?? null;
}

export function vaciarBandejas() {
  enviados.length = 0;
}
