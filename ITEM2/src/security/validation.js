import { errores } from './errors.js';

/**
 * Validaciones de entrada y enmascaramiento.
 * Minimización en el servidor: cada operación declara qué campos acepta. Cualquier campo
 * extra (fecha_nacimiento, sexo, rut en una boleta, etc.) se RECHAZA en vez de ignorarse,
 * para que ningún cliente ni formulario pueda introducir datos no necesarios.
 */

/**
 * @param {object} entrada Datos recibidos.
 * @param {{obligatorios?: string[], opcionales?: string[]}} politica
 */
export function soloCampos(entrada, { obligatorios = [], opcionales = [] }) {
  if (!entrada || typeof entrada !== 'object' || Array.isArray(entrada)) {
    throw errores.datoInvalido('Se esperaba un objeto con los datos de la solicitud.');
  }
  const permitidos = new Set([...obligatorios, ...opcionales]);
  const extra = Object.keys(entrada).filter(c => !permitidos.has(c));
  if (extra.length > 0) {
    throw errores.campoNoPermitido(extra);
  }
  const faltantes = obligatorios.filter(c => entrada[c] === undefined || entrada[c] === null || entrada[c] === '');
  if (faltantes.length > 0) {
    throw errores.datoInvalido(`Faltan campos obligatorios: ${faltantes.join(', ')}.`);
  }
}

function texto(valor, nombre, min, max) {
  if (typeof valor !== 'string') throw errores.datoInvalido(`${nombre} debe ser texto.`);
  const limpio = valor.trim();
  if (limpio.length < min || limpio.length > max) {
    throw errores.datoInvalido(`${nombre} debe tener entre ${min} y ${max} caracteres.`);
  }
  return limpio;
}

export const validar = {
  nombre: (v) => texto(v, 'nombre', 2, 100),
  email: (v) => {
    const e = texto(v, 'email', 6, 254).toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e)) throw errores.datoInvalido('email no tiene un formato válido.');
    return e;
  },
  direccion: (v) => texto(v, 'direccion', 5, 200),
  comuna: (v) => texto(v, 'comuna', 2, 50),
  telefono: (v) => {
    const t = String(v).replace(/[\s-]/g, '');
    if (!/^\+?56?9\d{8}$/.test(t)) throw errores.datoInvalido('telefono debe ser un móvil chileno (+56 9 XXXX XXXX).');
    return t.startsWith('+') ? t : `+56${t.slice(-9)}`;
  },
  alias: (v) => {
    const a = texto(v, 'alias', 3, 30);
    if (!/^[\p{L}\p{N}_.-]+$/u.test(a)) throw errores.datoInvalido('alias solo admite letras, números, punto, guion y guion bajo.');
    return a;
  },
  calificacion: (v) => {
    if (!Number.isInteger(v) || v < 1 || v > 5) throw errores.datoInvalido('calificacion debe ser un entero entre 1 y 5.');
    return v;
  },
  categoria: (v) => texto(v, 'categoria', 2, 50),
  enteroPositivo: (v, nombre) => {
    if (!Number.isInteger(v) || v <= 0) throw errores.datoInvalido(`${nombre} debe ser un entero positivo.`);
    return v;
  },
  enteroNoNegativo: (v, nombre) => {
    if (!Number.isInteger(v) || v < 0) throw errores.datoInvalido(`${nombre} debe ser un entero mayor o igual a cero.`);
    return v;
  },
  uuid: (v, nombre = 'identificador') => {
    if (typeof v !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v)) {
      throw errores.datoInvalido(`${nombre} no es válido.`);
    }
    return v;
  },
  rut: (v) => {
    const limpio = String(v).replace(/[.\s]/g, '').toUpperCase();
    const m = /^(\d{7,8})-([\dK])$/.exec(limpio);
    if (!m) throw errores.datoInvalido('rut debe tener formato 12345678-9.');
    let suma = 0;
    let mult = 2;
    for (let i = m[1].length - 1; i >= 0; i--) {
      suma += Number(m[1][i]) * mult;
      mult = mult === 7 ? 2 : mult + 1;
    }
    const resto = 11 - (suma % 11);
    const dv = resto === 11 ? '0' : resto === 10 ? 'K' : String(resto);
    if (dv !== m[2]) throw errores.datoInvalido('rut no es válido.');
    return limpio;
  }
};

/** Neutraliza HTML en textos públicos (reseñas) para prevenir XSS almacenado. */
export function sanitizarTexto(v, max = 1000) {
  const t = texto(v, 'comentario', 1, max);
  return t.replace(/[&<>"'`=/]/g, (c) => `&#${c.charCodeAt(0)};`);
}

export const enmascarar = {
  email: (e) => {
    const [usuario, dominio] = String(e).split('@');
    return `${usuario[0]}***@${dominio?.[0] ?? ''}***.${dominio?.split('.').pop() ?? ''}`;
  },
  nombre: (n) => String(n).split(/\s+/).map(p => `${p[0]}.`).join(' '),
  telefono: (t) => (t ? `*****${String(t).slice(-4)}` : null)
};
