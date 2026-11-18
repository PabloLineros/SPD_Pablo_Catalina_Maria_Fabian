import test from 'node:test';
import assert from 'node:assert/strict';
import { API } from '../src/api.js';
import { DB } from '../src/db/repository.js';
import { logger, redactar } from '../src/security/logger.js';
import { prepararEscenario, ok, PASSWORD_PRUEBA, TARJETA_VISA } from '../src/dev/escenario.js';

test('Redacción: claves sensibles y patrones en texto libre', () => {
  const r = redactar({
    email: 'a@b.cl',
    password: 'secreta',
    detalle: 'cliente ana@ejemplo.test pagó con 4111 1111 1111 1111 y token tok_norti_vault_abc',
    anidado: { direccion_envio_cifrada: 'aa', comuna: 'Calama' }
  });
  assert.equal(r.email, '[REDACTADO]');
  assert.equal(r.password, '[REDACTADO]');
  assert.equal(r.anidado.direccion_envio_cifrada, '[REDACTADO]');
  assert.equal(r.anidado.comuna, 'Calama');
  assert.equal(r.detalle, 'cliente [EMAIL_REDACTADO] pagó con [PAN_REDACTADO] y token [TOKEN_REDACTADO]');
});

test('Tras un flujo completo, los registros de actividad no contienen datos personales', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[0], cantidad: 1 }] }));
  await API.auth.iniciarSesion({ email: 'ana.prueba@ejemplo.test', password: 'incorrecta-123' });
  await API.cliente.verPerfil(tokens.clienteB, ids.clienteA);
  ok(await API.invitado.crearPedido({
    nombre: 'Invitado Prueba', email: 'invitado@ejemplo.test', direccionDespacho: 'Calle Invitada 77',
    comuna: 'Arica', items: [{ productoId: ids.productos[1], cantidad: 1 }], tarjeta: TARJETA_VISA
  }));

  const texto = JSON.stringify(logger.registros()) + JSON.stringify(DB.simularAccesoFisico().audit_log);
  assert.ok(logger.registros().length > 0);
  for (const sensible of ['@ejemplo.test', 'Ana Prueba', 'Calle Ficticia', 'Calle Invitada', PASSWORD_PRUEBA, 'incorrecta-123', '4111', '$2', 'tok_']) {
    assert.equal(texto.includes(sensible), false, `"${sensible}" no debe aparecer en logs`);
  }
});

test('Errores internos: el cliente recibe un mensaje genérico y el detalle va redactado al log', async () => {
  const { tokens, ids } = await prepararEscenario();
  // Se corrompe el criptograma del email para forzar un fallo interno de descifrado.
  const fila = DB.simularAccesoFisico().users.find(u => u.id === ids.clienteA);
  DB.manipularFilaDirecto('users', ids.clienteA, { email_cifrado: fila.nombre_cifrado });
  logger.limpiar();

  const r = await API.cliente.verPerfil(tokens.clienteA, ids.clienteA);
  assert.deepEqual(r.error, { codigo: 'ERROR_INTERNO', estado: 500, mensaje: 'Ocurrió un error interno. Intente nuevamente.' });
  const log = logger.registros().find(l => l.evento === 'error_interno');
  assert.ok(log);
  assert.equal(log.datos.codigo, 'CIFRADO_INVALIDO');
  assert.doesNotMatch(JSON.stringify(log), /[0-9a-f]{24}:[0-9a-f]{32}/);
});

test('Errores de validación no reflejan el dato ingresado', async () => {
  await prepararEscenario();
  const r = await API.auth.registrar({ nombre: 'X', email: 'no-es-un-email-secreto', password: PASSWORD_PRUEBA, direccionDespacho: 'Calle 12345', comuna: 'Arica' });
  assert.equal(r.ok, false);
  assert.doesNotMatch(r.error.mensaje, /no-es-un-email-secreto/);
});
