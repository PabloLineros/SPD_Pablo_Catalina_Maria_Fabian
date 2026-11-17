import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { API } from '../src/api.js';
import { DB } from '../src/db/repository.js';
import { MATRIZ, PERMISOS } from '../src/security/rbac.js';
import { prepararEscenario, ok, PASSWORD_PRUEBA } from '../src/dev/escenario.js';

const { tokens, ids } = await prepararEscenario();
ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[0], cantidad: 1 }] }));
const ref = ok(await API.logistica.pendientes(tokens.logistica))[0].ref_envio;

const TODOS = ['admin', 'privacidad', 'seguridad', 'soporte', 'logistica', 'catalogo', 'marketing', 'analista', 'clienteA'];

/** [descripción, llamada, roles con acceso permitido] */
const CASOS = [
  ['Gestionar roles (crear personal)', (t, i) => API.admin.crearPersonal(t, { nombre: 'Nuevo Personal', email: `n${i}@nortishop.test`, password: PASSWORD_PRUEBA, rol: 'SOPORTE' }), ['admin']],
  ['Leer auditoría', (t) => API.admin.auditoria(t), ['admin', 'privacidad', 'seguridad']],
  ['Buscar cliente (enmascarado)', (t) => API.soporte.buscarCliente(t, 'ana.prueba@ejemplo.test'), ['admin', 'soporte']],
  ['Revelar PII de un cliente', (t) => API.soporte.revelarDatosContacto(t, ids.clienteA, { ticket: 'TCK-1001', motivo: 'Cliente reporta pedido no recibido' }), ['soporte']],
  ['Listar pedidos de todos', (t) => API.pedidos.listar(t), ['admin', 'soporte']],
  ['Envíos pendientes', (t) => API.logistica.pendientes(t), ['logistica']],
  ['Generar etiqueta de despacho', (t) => API.logistica.etiqueta(t, ref), ['logistica']],
  ['Editar catálogo', (t) => API.catalogo.actualizarProducto(t, ids.productos[1], { stock: 50 }), ['catalogo']],
  ['Exportar suscriptores', (t) => API.marketing.exportarSuscriptores(t), ['marketing']],
  ['Leer analítica seudonimizada', (t) => API.analitica.compras(t), ['analista']],
  ['Reporte agregado (k-anónimo)', (t) => API.analitica.ventasPorComuna(t), ['admin', 'privacidad', 'marketing', 'analista']],
  ['Ejecutar procesos de privacidad', (t) => API.privacidad.copiaDesarrollo(t), ['privacidad']],
  ['Consultar datos propios', (t) => API.cliente.verPerfil(t, ids.clienteA), ['clienteA']],
  ['Crear pedido', (t) => API.cliente.crearPedido(t, { items: [{ productoId: ids.productos[1], cantidad: 1 }] }), ['clienteA']]
];

for (const [descripcion, llamada, permitidos] of CASOS) {
  test(`Matriz RBAC: ${descripcion}`, async () => {
    for (const [i, rol] of TODOS.entries()) {
      const r = await llamada(tokens[rol], i);
      if (permitidos.includes(rol)) {
        assert.equal(r.ok, true, `${rol} debería poder: ${r.error?.codigo}`);
      } else {
        assert.equal(r.error?.codigo, 'ACCESO_DENEGADO', `${rol} NO debería poder`);
      }
    }
  });
}

test('Sin sesión o con token inválido: NO_AUTENTICADO', async () => {
  assert.equal((await API.cliente.verPerfil(undefined, ids.clienteA)).error.codigo, 'NO_AUTENTICADO');
  assert.equal((await API.admin.auditoria('x'.repeat(43))).error.codigo, 'NO_AUTENTICADO');
});

test('Cliente no puede leer, modificar ni suprimir datos de otro cliente', async () => {
  assert.equal((await API.cliente.verPerfil(tokens.clienteB, ids.clienteA)).error.codigo, 'ACCESO_DENEGADO');
  assert.equal((await API.cliente.misPedidos(tokens.clienteB, ids.clienteA)).error.codigo, 'ACCESO_DENEGADO');
  assert.equal((await API.cliente.saldoPuntos(tokens.clienteB, ids.clienteA)).error.codigo, 'ACCESO_DENEGADO');
  assert.equal((await API.cliente.actualizarPerfil(tokens.clienteB, ids.clienteA, { comuna: 'X' })).error.codigo, 'ACCESO_DENEGADO');
  assert.equal((await API.derechos.solicitar(tokens.clienteB, ids.clienteA, { tipo: 'SUPRESION' })).error.codigo, 'ACCESO_DENEGADO');
  assert.equal((await API.consentimiento.revocar(tokens.clienteB, ids.clienteA, { finalidad: 'MARKETING_EMAIL' })).error.codigo, 'ACCESO_DENEGADO');
  assert.equal(ok(await API.cliente.verPerfil(tokens.clienteB, ids.clienteB)).id, ids.clienteB);
});

test('Las denegaciones quedan auditadas sin datos personales', () => {
  const denegados = DB.simularAccesoFisico().audit_log.filter(a => a.resultado === 'DENEGADO');
  assert.ok(denegados.length > 0);
  assert.ok(denegados.some(a => a.motivo === 'RECURSO_AJENO'));
  assert.doesNotMatch(JSON.stringify(denegados), /@ejemplo\.test|Ana Prueba/);
});

test('Soporte ve datos enmascarados por defecto; revelar exige ticket y motivo', async () => {
  const vista = ok(await API.soporte.buscarCliente(tokens.soporte, 'ana.prueba@ejemplo.test'));
  assert.equal(vista.email, 'a***@e***.test');
  assert.equal(vista.nombre, 'A. P. U.');
  assert.equal(vista.telefono, '*****2222');
  assert.equal((await API.soporte.revelarDatosContacto(tokens.soporte, ids.clienteA, { ticket: 'TCK-1', motivo: 'x' })).error.codigo, 'DATO_INVALIDO');
});

test('Logística solo recibe lo necesario para despachar', async () => {
  const etiqueta = ok(await API.logistica.etiqueta(tokens.logistica, ref));
  assert.deepEqual(Object.keys(etiqueta).sort(), ['comuna', 'destinatario', 'direccion', 'ref_envio']);
  const pendientes = ok(await API.logistica.pendientes(tokens.logistica));
  assert.doesNotMatch(JSON.stringify(pendientes), new RegExp(`${ids.clienteA}|total|email`));
});

test('Administrador no puede auto-asignarse roles ni desactivarse', async () => {
  assert.equal((await API.admin.asignarRol(tokens.admin, ids.admin, 'OFICIAL_PRIVACIDAD')).error.codigo, 'ACCESO_DENEGADO');
  assert.equal((await API.admin.desactivarPersonal(tokens.admin, ids.admin)).error.codigo, 'ACCESO_DENEGADO');
  assert.equal((await API.admin.asignarRol(tokens.admin, ids.soporte, 'CLIENTE')).error.codigo, 'DATO_INVALIDO');
  assert.ok(DB.simularAccesoFisico().audit_log.some(a => a.motivo === 'AUTO_MODIFICACION'));
});

test('Cambio y revocación de rol tienen efecto inmediato sobre sesiones abiertas', async () => {
  const { token } = ok(await API.auth.iniciarSesion({ email: 'marketing@nortishop.test', password: PASSWORD_PRUEBA }));
  assert.equal((await API.marketing.exportarSuscriptores(token)).ok, true);

  ok(await API.admin.asignarRol(tokens.admin, ids.marketing, 'ANALISTA'));
  assert.equal((await API.marketing.exportarSuscriptores(token)).error.codigo, 'ACCESO_DENEGADO');

  ok(await API.admin.desactivarPersonal(tokens.admin, ids.marketing));
  assert.equal((await API.analitica.compras(token)).error.codigo, 'NO_AUTENTICADO');
});

test('Login: mensaje único (sin enumeración) y bloqueo tras intentos fallidos', async () => {
  const inexistente = await API.auth.iniciarSesion({ email: 'nadie@ejemplo.test', password: 'cualquier-cosa' });
  const malaClave = await API.auth.iniciarSesion({ email: 'bruno.prueba@ejemplo.test', password: 'clave-incorrecta' });
  assert.deepEqual(inexistente.error, malaClave.error);

  for (let i = 0; i < 4; i++) await API.auth.iniciarSesion({ email: 'bruno.prueba@ejemplo.test', password: 'clave-incorrecta' });
  const bloqueado = await API.auth.iniciarSesion({ email: 'bruno.prueba@ejemplo.test', password: PASSWORD_PRUEBA });
  assert.equal(bloqueado.error.codigo, 'CUENTA_BLOQUEADA', 'ni con la clave correcta mientras dure el bloqueo');
});

test('Nadie tiene acceso a llaves: permiso no asignado y usarLlave solo se usa en src/crypto', () => {
  assert.ok(Object.values(MATRIZ).every(permisos => !permisos.includes(PERMISOS.LLAVES_ACCEDER)));

  const src = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src');
  const archivos = fs.readdirSync(src, { recursive: true }).filter(f => f.endsWith('.js') && !f.endsWith('keyring.js'));
  const importadores = archivos.filter(f => /\busarLlave\b/.test(fs.readFileSync(path.join(src, f), 'utf8')));
  assert.ok(importadores.length > 0);
  for (const f of importadores) {
    assert.match(f.replaceAll('\\', '/'), /^crypto\//, `${f} no debe acceder al llavero`);
  }
});
