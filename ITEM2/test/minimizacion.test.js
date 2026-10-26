import test from 'node:test';
import assert from 'node:assert/strict';
import { API } from '../src/api.js';
import { DB, ROLES_BD } from '../src/db/repository.js';
import { prepararEscenario, ok, PASSWORD_PRUEBA, TARJETA_VISA } from '../src/dev/escenario.js';

const base = {
  nombre: 'Carla Prueba',
  email: 'carla@ejemplo.test',
  password: PASSWORD_PRUEBA,
  direccionDespacho: 'Avenida Sintética 99',
  comuna: 'Iquique'
};

test('Registro rechaza datos no necesarios (fecha de nacimiento, sexo, RUT, foto)', async () => {
  await prepararEscenario();
  for (const campo of ['fecha_nacimiento', 'sexo', 'rut', 'foto']) {
    const r = await API.auth.registrar({ ...base, [campo]: 'x' });
    assert.equal(r.ok, false);
    assert.equal(r.error.codigo, 'CAMPO_NO_PERMITIDO', `${campo} debe rechazarse`);
  }
});

test('Teléfono es opcional y la tarjeta solo se acepta si el cliente decide guardarla', async () => {
  await prepararEscenario();
  assert.equal((await API.auth.registrar(base)).ok, true, 'registro sin teléfono ni tarjeta funciona');

  const r = await API.auth.registrar({ ...base, email: 'otra@ejemplo.test', tarjeta: TARJETA_VISA });
  assert.equal(r.error.codigo, 'CAMPO_NO_PERMITIDO', 'privacidad por defecto: guardarMedioPago desmarcado');
});

test('Boleta no admite datos de facturación; factura los exige y los cifra', async () => {
  const { tokens, ids } = await prepararEscenario();
  const items = [{ productoId: ids.productos[1], cantidad: 1 }];
  const facturacion = { rut: '76.086.428-5', razonSocial: 'Empresa Ficticia SpA', direccion: 'Oficina Inventada 1' };

  const boleta = await API.cliente.crearPedido(tokens.clienteA, { items, tipoDocumento: 'BOLETA', facturacion });
  assert.equal(boleta.error.codigo, 'CAMPO_NO_PERMITIDO');

  const factura = ok(await API.cliente.crearPedido(tokens.clienteA, { items, tipoDocumento: 'FACTURA', facturacion }));
  assert.equal(factura.tipoDocumento, 'FACTURA');
  const fila = DB.simularAccesoFisico().facturacion[0];
  assert.doesNotMatch(JSON.stringify(fila), /76086428|Empresa Ficticia|Oficina Inventada/);
});

test('El monto lo calcula el servidor: un total enviado por el cliente se rechaza', async () => {
  const { tokens, ids } = await prepararEscenario();
  const r = await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[0], cantidad: 1 }], total: 1 });
  assert.equal(r.error.codigo, 'CAMPO_NO_PERMITIDO');
});

test('La capa de datos rechaza columnas fuera del esquema y texto plano en columnas protegidas', () => {
  const bd = DB.conectar(ROLES_BD.SVC_APP);
  const fila = {
    id: '00000000-0000-4000-8000-000000000001',
    nombre_cifrado: 'Texto Plano', email_cifrado: 'a@b.cl', email_hmac: 'x', direccion_despacho_cifrada: 'Calle 1',
    comuna: 'X', password_hash: 'clave', guardar_medio_pago: false, created_at: new Date().toISOString()
  };
  assert.throws(() => bd.insertar('users', { ...fila, fecha_nacimiento: '2000-01-01' }), { code: 'BD_COLUMNA_NO_PERMITIDA' });
  assert.throws(() => bd.insertar('users', fila), { code: 'BD_TIPO_INVALIDO' });
});

test('Datos en reposo: ningún dato personal, contraseña ni PAN aparece en texto plano', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[0], cantidad: 1 }] }));
  ok(await API.invitado.crearPedido({
    nombre: 'Invitado Prueba', email: 'invitado@ejemplo.test', direccionDespacho: 'Calle Invitada 77',
    comuna: 'Arica', items: [{ productoId: ids.productos[1], cantidad: 1 }], tarjeta: TARJETA_VISA
  }));

  const volcado = JSON.stringify(DB.simularAccesoFisico());
  for (const sensible of ['ana.prueba@ejemplo.test', 'Ana Prueba Uno', 'Calle Ficticia 123', '+56911112222',
    'invitado@ejemplo.test', 'Calle Invitada 77', 'Invitado Prueba', PASSWORD_PRUEBA, '4111111111111111', '************']) {
    assert.equal(volcado.includes(sensible), false, `"${sensible}" no debe estar en texto plano`);
  }

  const pedido = DB.simularAccesoFisico().orders[0];
  assert.equal('direccionDespachoDescifradaLogistica' in pedido, false);
  assert.match(pedido.direccion_envio_cifrada, /^[0-9a-f]{24}:[0-9a-f]{32}:/);
  assert.equal(pedido.tarjeta_last4, '1111');
});

test('Perfil propio no expone el token de pago ni datos no necesarios', async () => {
  const { tokens, ids } = await prepararEscenario();
  const perfil = ok(await API.cliente.verPerfil(tokens.clienteA, ids.clienteA));
  assert.deepEqual(Object.keys(perfil).sort(), ['comuna', 'direccionDespacho', 'email', 'id', 'medioPago', 'nombre', 'telefono']);
  assert.deepEqual(perfil.medioPago, { marca: 'VISA', last4: '1111' });

  ok(await API.cliente.actualizarPerfil(tokens.clienteA, ids.clienteA, { telefono: null, guardarMedioPago: false }));
  const despues = ok(await API.cliente.verPerfil(tokens.clienteA, ids.clienteA));
  assert.equal(despues.telefono, null, 'el titular puede eliminar un dato opcional');
  assert.equal(despues.medioPago, null);
  assert.equal(DB.simularAccesoFisico().users.find(u => u.id === ids.clienteA).token_pago, null);
});
