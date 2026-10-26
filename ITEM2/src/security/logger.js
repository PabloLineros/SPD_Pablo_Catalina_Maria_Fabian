import { CONFIG } from '../config/env.js';

/**
 * Registro de actividad con REDACCIÓN automática.
 * Ningún log debe contener datos personales, contraseñas, hashes, tokens, criptogramas ni llaves.
 *  1. Claves sensibles (por nombre de campo) -> '[REDACTADO]'.
 *  2. Patrones sensibles dentro de textos libres (emails, PAN, hashes bcrypt, tokens) -> marcadores.
 * Los registros se guardan en memoria (evidencia para pruebas) y opcionalmente en consola.
 */

const CLAVE_SENSIBLE = /pass|contrase|email|correo|nombre|direcci|telefono|rut|razon|tarjeta|pan$|cvv|token|llave|key|secret|hash|cifrad|alias|comentario/i;

const PATRONES = [
  [/\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}/g, '[HASH_REDACTADO]'],
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '[EMAIL_REDACTADO]'],
  [/tok_[A-Za-z0-9_]+/g, '[TOKEN_REDACTADO]'],
  [/\b\d(?:[ -]?\d){12,18}\b/g, '[PAN_REDACTADO]'],
  [/\b[0-9a-f]{24}:[0-9a-f]{32}:[0-9a-f]+\b/g, '[CIFRADO_REDACTADO]']
];

export function redactarTexto(texto) {
  return PATRONES.reduce((acc, [patron, marcador]) => acc.replace(patron, marcador), String(texto));
}

export function redactar(valor, profundidad = 0) {
  if (profundidad > 6) return '[PROFUNDIDAD_MAXIMA]';
  if (valor === null || valor === undefined) return valor;
  if (typeof valor === 'string') return redactarTexto(valor);
  if (typeof valor !== 'object') return valor;
  if (valor instanceof Error) return { error: valor.name, mensaje: redactarTexto(valor.message) };
  if (Array.isArray(valor)) return valor.map(v => redactar(v, profundidad + 1));

  const salida = {};
  for (const [clave, v] of Object.entries(valor)) {
    salida[clave] = CLAVE_SENSIBLE.test(clave) ? '[REDACTADO]' : redactar(v, profundidad + 1);
  }
  return salida;
}

const registros = [];

function escribir(nivel, evento, datos = {}) {
  const entrada = { ts: new Date().toISOString(), nivel, evento: redactarTexto(evento), datos: redactar(datos) };
  registros.push(entrada);
  if (CONFIG.LOG_A_CONSOLA) {
    console.log(JSON.stringify(entrada));
  }
}

export const logger = {
  info: (evento, datos) => escribir('INFO', evento, datos),
  warn: (evento, datos) => escribir('WARN', evento, datos),
  error: (evento, datos) => escribir('ERROR', evento, datos),
  /** Copia de los registros (evidencia y pruebas). */
  registros: () => registros.map(r => ({ ...r })),
  limpiar: () => { registros.length = 0; }
};
