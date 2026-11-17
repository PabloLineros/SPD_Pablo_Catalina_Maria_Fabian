import test from 'node:test';
import assert from 'node:assert/strict';
import { crearServidor } from '../src/server.js';
import { DB, ROLES_BD } from '../src/db/repository.js';
import { prepararEscenario } from '../src/dev/escenario.js';

const { tokens, ids } = await prepararEscenario();
const servidor = crearServidor().listen(0, '127.0.0.1');
await new Promise(r => servidor.once('listening', r));
const BASE = `http://127.0.0.1:${servidor.address().port}`;
test.after(() => servidor.close());

async function post(ruta, args = [], token, { tipo = 'application/json', cuerpo } = {}) {
  const r = await fetch(`${BASE}/api/${ruta}`, {
    method: 'POST',
    headers: { 'Content-Type': tipo, ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: cuerpo ?? JSON.stringify({ args })
  });
  return { estado: r.status, cuerpo: await r.json(), cabeceras: r.headers };
}

test('Sin token, ningún endpoint protegido responde datos (401)', async () => {
  for (const [ruta, args] of [
    ['consentimiento/estado', [ids.clienteA]], ['derechos/solicitar', [ids.clienteA, { tipo: 'ACCESO' }]],
    ['auditoria/consultar', []], ['seguridad/alertas', []], ['cliente/verPerfil', [ids.clienteA]]
  ]) {
    const r = await post(ruta, args);
    assert.equal(r.estado, 401, ruta);
    assert.equal(r.cuerpo.error.codigo, 'NO_AUTENTICADO');
  }
  assert.equal((await post('consentimiento/estado', [ids.clienteA], 'token-inventado-de-mas-de-cuarenta-caracteres-123')).estado, 401);
});

test('Con token de cliente no se accede a funciones del personal ni a datos de otro cliente (403)', async () => {
  for (const [ruta, args] of [
    ['auditoria/consultar', []], ['seguridad/contener', ['00000000-0000-4000-8000-000000000000', { accion: 'SUSPENDER_EXPORTACIONES' }]],
    ['derechos/gestion', []], ['consentimiento/publicarVersion', [{ finalidad: 'MARKETING_EMAIL', version: '9', texto: 'x'.repeat(50) }]],
    ['consentimiento/revocar', [ids.clienteB, { finalidad: 'MARKETING_EMAIL' }]], ['derechos/misSolicitudes', [ids.clienteB]]
  ]) {
    const r = await post(ruta, args, tokens.clienteA);
    assert.equal(r.estado, 403, ruta);
  }
});

test('Las operaciones internas no tienen ruta (404) y la API solo acepta POST JSON acotado', async () => {
  for (const ruta of ['privacy/suprimirCliente', 'consentimiento/otorgarConsentimiento', 'auditoria/verificarCadena', 'api/constructor', 'consentimiento/__proto__']) {
    assert.equal((await post(ruta, [ids.clienteA], tokens.privacidad)).estado, 404, ruta);
  }
  assert.equal((await post('consentimiento/estado', [], tokens.clienteA, { tipo: 'text/plain' })).estado, 415);
  assert.equal((await post('consentimiento/estado', [], tokens.clienteA, { cuerpo: '{no es json' })).estado, 400);
  assert.equal((await post('consentimiento/estado', [], tokens.clienteA, { cuerpo: JSON.stringify({ args: ['x'.repeat(200_000)] }) })).estado, 413);
  const get = await fetch(`${BASE}/api/consentimiento/estado`);
  assert.equal(get.status, 405);
});

test('Respuestas con cabeceras de seguridad y sin detalles internos', async () => {
  const r = await post('consentimiento/estado', [ids.clienteA], tokens.clienteA);
  assert.equal(r.estado, 200);
  assert.match(r.cabeceras.get('content-security-policy'), /default-src 'self'/);
  assert.equal(r.cabeceras.get('x-content-type-options'), 'nosniff');
  assert.equal(r.cabeceras.get('cache-control'), 'no-store');
  const error = await post('derechos/confirmar', [ids.clienteA, 'no-existe', { password: 'x' }], tokens.clienteA);
  assert.doesNotMatch(JSON.stringify(error.cuerpo), /at |\.js:|stack/);
  const pagina = await fetch(`${BASE}/`);
  assert.equal(pagina.status, 200);
  assert.match(await pagina.text(), /Centro de privacidad/);
});

test('Tampoco se eluden los controles directamente en la base de datos con la credencial de la aplicación', () => {
  const app = DB.conectar(ROLES_BD.SVC_APP);
  assert.throws(() => app.seleccionar('audit_log'), { code: 'BD_PERMISO_DENEGADO' });
  assert.throws(() => app.seleccionar('pseudo.pseudonimos'), { code: 'BD_PERMISO_DENEGADO' });
  assert.throws(() => app.actualizar('alertas', 'x', { estado: 'DESCARTADA' }), { code: 'BD_PERMISO_DENEGADO' });
  assert.throws(() => app.insertar('controles_operacion', { id: 'rol_suspendido:SEGURIDAD', activo: true, actualizado_el: new Date().toISOString() }), { code: 'BD_PERMISO_DENEGADO' });

  // Insertar con secuencia y sello falsificados: el disparador de la BD los reemplaza.
  const falsificado = app.insertar('audit_log', {
    id: crypto.randomUUID(), created_at: new Date().toISOString(), actor_id: 'x', actor_rol: 'x', accion: 'x',
    categoria: 'x', resultado: 'EXITO', secuencia: 99999, hash_previo: '0'.repeat(64), hash: 'f'.repeat(64)
  });
  assert.notEqual(falsificado.secuencia, 99999);
  assert.notEqual(falsificado.hash, 'f'.repeat(64));
  assert.notEqual(falsificado.hash_previo, '0'.repeat(64));
});
