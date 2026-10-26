import { API } from '../api.js';
import { DB } from '../db/repository.js';
import { AdminService } from '../services/adminService.js';
import { reiniciarIntentos } from '../services/authService.js';
import { logger } from '../security/logger.js';

/**
 * Escenario de DATOS SINTÉTICOS para la demo y las pruebas.
 * Ningún dato corresponde a personas reales (dominio reservado .test, tarjetas de prueba
 * que solo pasan la validación de Luhn). Así se evita usar datos personales en desarrollo.
 */

export const PASSWORD_PRUEBA = 'ClaveDePrueba#2026';

/** Desenvuelve una respuesta de la API o lanza un error legible. */
export function ok(respuesta) {
  if (!respuesta.ok) {
    throw new Error(`Se esperaba éxito y se obtuvo ${respuesta.error.codigo}: ${respuesta.error.mensaje}`);
  }
  return respuesta.data;
}

export const TARJETA_VISA = { pan: '4111 1111 1111 1111', expirationDate: '12/29', cvv: '123' };
export const TARJETA_MC = { pan: '5555555555554444', expirationDate: '08/28', cvv: '321' };

const PERSONAL = [
  ['OFICIAL_PRIVACIDAD', 'privacidad'],
  ['SOPORTE', 'soporte'],
  ['LOGISTICA', 'logistica'],
  ['CATALOGO', 'catalogo'],
  ['MARKETING', 'marketing'],
  ['ANALISTA', 'analista']
];

async function login(email) {
  return ok(await API.auth.iniciarSesion({ email, password: PASSWORD_PRUEBA }));
}

export async function prepararEscenario() {
  DB.reiniciar();
  reiniciarIntentos();
  logger.limpiar();

  const tokens = {};
  const ids = {};

  const admin = await AdminService.inicializarAdministrador({ nombre: 'Admin Sistema', email: 'admin@nortishop.test', password: PASSWORD_PRUEBA });
  ids.admin = admin.id;
  tokens.admin = (await login('admin@nortishop.test')).token;

  for (const [rol, clave] of PERSONAL) {
    const email = `${clave}@nortishop.test`;
    ids[clave] = ok(await API.admin.crearPersonal(tokens.admin, { nombre: `Personal ${rol}`, email, password: PASSWORD_PRUEBA, rol })).id;
    tokens[clave] = (await login(email)).token;
  }

  ids.productos = [];
  for (const p of [
    { nombre: 'Polerón NortiShop', categoria: 'VESTUARIO', precio_clp: 24990, stock: 100 },
    { nombre: 'Taza Térmica', categoria: 'HOGAR', precio_clp: 8990, stock: 100 },
    { nombre: 'Audífonos Inalámbricos', categoria: 'TECNOLOGIA', precio_clp: 59990, stock: 100 }
  ]) {
    ids.productos.push(ok(await API.catalogo.crearProducto(tokens.catalogo, p)).id);
  }

  ids.clienteA = ok(await API.auth.registrar({
    nombre: 'Ana Prueba Uno',
    email: 'ana.prueba@ejemplo.test',
    password: PASSWORD_PRUEBA,
    direccionDespacho: 'Calle Ficticia 123, Depto 4',
    comuna: 'Antofagasta',
    telefono: '+56 9 1111 2222',
    guardarMedioPago: true,
    tarjeta: TARJETA_VISA,
    aceptaMarketing: true
  })).id;
  tokens.clienteA = (await login('ana.prueba@ejemplo.test')).token;

  ids.clienteB = ok(await API.auth.registrar({
    nombre: 'Bruno Prueba Dos',
    email: 'bruno.prueba@ejemplo.test',
    password: PASSWORD_PRUEBA,
    direccionDespacho: 'Pasaje Inventado 456',
    comuna: 'Calama'
  })).id;
  tokens.clienteB = (await login('bruno.prueba@ejemplo.test')).token;

  return { tokens, ids };
}
