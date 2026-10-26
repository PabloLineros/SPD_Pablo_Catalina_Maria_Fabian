import test from 'node:test';
import assert from 'node:assert/strict';
import { API } from '../src/api.js';
import { DB, ROLES_BD } from '../src/db/repository.js';
import { seudonimo } from '../src/crypto/pseudonymization.js';
import { prepararEscenario, ok, PASSWORD_PRUEBA, TARJETA_VISA } from '../src/dev/escenario.js';

test('Reseñas: autor seudonimizado; la vista pública solo muestra alias', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await API.cliente.publicarResena(tokens.clienteA, { productoId: ids.productos[0], calificacion: 5, alias: 'ana_p', comentario: '<script>alert(1)</script> Excelente' }));

  const publicas = ok(await API.catalogo.resenas(ids.productos[0]));
  assert.deepEqual(Object.keys(publicas[0]).sort(), ['alias_publico', 'calificacion', 'comentario', 'fecha', 'producto_id']);
  assert.doesNotMatch(publicas[0].comentario, /<script>/, 'comentario sanitizado (XSS)');

  const fila = DB.simularAccesoFisico().resenas[0];
  assert.equal('user_id' in fila, false);
  assert.equal(fila.autor_pseudo, seudonimo('resenas', ids.clienteA));
  assert.notEqual(fila.autor_pseudo, seudonimo('analitica', ids.clienteA));
});

test('Tabla de equivalencias: solo svc_privacidad puede leerla', () => {
  for (const rol of [ROLES_BD.SVC_APP, ROLES_BD.SVC_ETL, ROLES_BD.ROL_ANALISTA, ROLES_BD.ROL_MARKETING, ROLES_BD.ROL_PUBLICO]) {
    assert.throws(() => DB.conectar(rol).seleccionar('pseudo.pseudonimos'), { code: 'BD_PERMISO_DENEGADO' }, rol);
  }
  assert.doesNotThrow(() => DB.conectar(ROLES_BD.SVC_PRIVACIDAD).seleccionar('pseudo.pseudonimos'));
});

test('Reidentificación: solo OFICIAL_PRIVACIDAD, con motivo, y queda auditada', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await API.cliente.publicarResena(tokens.clienteA, { productoId: ids.productos[0], calificacion: 1, alias: 'ana_p' }));
  const pseudoId = DB.simularAccesoFisico().resenas[0].autor_pseudo;
  const entrada = { pseudoId, finalidad: 'resenas', motivo: 'Requerimiento judicial causa ficticia 123' };

  for (const rol of ['admin', 'soporte', 'analista', 'marketing', 'clienteA']) {
    assert.equal((await API.privacidad.revertirSeudonimo(tokens[rol], entrada)).error.codigo, 'ACCESO_DENEGADO', rol);
  }
  assert.equal((await API.privacidad.revertirSeudonimo(tokens.privacidad, { ...entrada, motivo: 'porque sí' })).error.codigo, 'DATO_INVALIDO');
  assert.equal(ok(await API.privacidad.revertirSeudonimo(tokens.privacidad, entrada)).userId, ids.clienteA);
  assert.ok(DB.simularAccesoFisico().audit_log.some(a => a.accion === 'seudonimos:revertir' && a.resultado === 'PERMITIDO'));
});

test('Analítica: datos seudonimizados y generalizados, sin identificadores directos', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[2], cantidad: 1 }] }));
  ok(await API.privacidad.ejecutarEtl(tokens.privacidad));

  const filas = ok(await API.analitica.compras(tokens.analista));
  assert.equal(filas.length, 1);
  assert.deepEqual(Object.keys(filas[0]).sort(), ['categoria_producto', 'cliente_pseudo', 'comuna', 'id', 'mes_compra', 'rango_monto']);
  assert.match(filas[0].mes_compra, /^\d{4}-\d{2}-01$/, 'fecha generalizada al mes');
  assert.equal(filas[0].rango_monto, '50-100k', 'monto generalizado a rango');
  assert.equal(filas[0].cliente_pseudo, seudonimo('analitica', ids.clienteA));
  assert.notEqual(filas[0].cliente_pseudo, ids.clienteA);

  assert.throws(() => DB.conectar(ROLES_BD.ROL_ANALISTA).seleccionar('orders'), { code: 'BD_PERMISO_DENEGADO' });
  assert.throws(() => DB.conectar(ROLES_BD.ROL_ANALISTA).seleccionar('users'), { code: 'BD_PERMISO_DENEGADO' });
});

test('Anonimización k=5: grupos con menos de 5 clientes se suprimen del reporte', async () => {
  const { tokens, ids } = await prepararEscenario();
  for (let i = 0; i < 5; i++) {
    const email = `k${i}@ejemplo.test`;
    ok(await API.auth.registrar({ nombre: `Cliente K ${i}`, email, password: PASSWORD_PRUEBA, direccionDespacho: `Calle K ${i}`, comuna: 'Antofagasta' }));
    const { token } = ok(await API.auth.iniciarSesion({ email, password: PASSWORD_PRUEBA }));
    ok(await API.cliente.crearPedido(token, { items: [{ productoId: ids.productos[1], cantidad: 1 }], tarjeta: TARJETA_VISA }));
  }
  // Un único cliente en Calama: su grupo debe quedar oculto.
  ok(await API.cliente.crearPedido(tokens.clienteB, { items: [{ productoId: ids.productos[1], cantidad: 1 }], tarjeta: TARJETA_VISA }));
  ok(await API.privacidad.ejecutarEtl(tokens.privacidad));

  const reporte = ok(await API.analitica.ventasPorComuna(tokens.analista));
  assert.equal(reporte.length, 1);
  assert.equal(reporte[0].comuna, 'Antofagasta');
  assert.equal(reporte[0].clientes, 5);
  assert.equal(reporte.some(r => r.comuna === 'Calama'), false);
  assert.equal('cliente_pseudo' in reporte[0], false);
});

test('Invitados: contacto anonimizado al vencer el plazo de conservación', async () => {
  const { tokens, ids } = await prepararEscenario();
  const { tokenSeguimiento } = ok(await API.invitado.crearPedido({
    nombre: 'Invitado Prueba', email: 'invitado@ejemplo.test', telefono: '+56 9 3333 4444', direccionDespacho: 'Calle Invitada 77',
    comuna: 'Arica', items: [{ productoId: ids.productos[0], cantidad: 1 }], tarjeta: TARJETA_VISA
  }));
  const seguimiento = ok(await API.invitado.consultarPedido(tokenSeguimiento));
  assert.deepEqual(Object.keys(seguimiento).sort(), ['comuna_envio', 'estado', 'fecha', 'total_clp']);

  const ref = ok(await API.logistica.pendientes(tokens.logistica))[0].ref_envio;
  ok(await API.logistica.actualizarEstado(tokens.logistica, ref, 'EN_RUTA'));
  ok(await API.logistica.actualizarEstado(tokens.logistica, ref, 'ENTREGADO'));

  assert.equal(ok(await API.privacidad.anonimizarInvitados(tokens.privacidad, new Date())).anonimizados, 0, 'antes del plazo no se anonimiza');
  const en91dias = new Date(Date.now() + 91 * 86_400_000);
  assert.equal(ok(await API.privacidad.anonimizarInvitados(tokens.privacidad, en91dias)).anonimizados, 1);

  const fila = DB.simularAccesoFisico().orders_invitado[0];
  for (const c of ['nombre_invitado_cifrado', 'email_invitado_cifrado', 'telefono_invitado_cifrado', 'direccion_envio_cifrada']) {
    assert.equal(fila[c], null, c);
  }
  assert.ok(fila.total_clp > 0, 'se conserva el dato contable');
});

test('Supresión: elimina PII y equivalencias, bloquea facturación y conserva pedidos sin datos personales', async () => {
  const { tokens, ids } = await prepararEscenario();
  const { id: orderId } = ok(await API.cliente.crearPedido(tokens.clienteA, {
    items: [{ productoId: ids.productos[0], cantidad: 1 }], tipoDocumento: 'FACTURA',
    facturacion: { rut: '76.086.428-5', razonSocial: 'Empresa Ficticia SpA', direccion: 'Oficina Inventada 1' }
  }));
  ok(await API.cliente.publicarResena(tokens.clienteA, { productoId: ids.productos[0], calificacion: 4, alias: 'ana_p' }));

  assert.equal((await API.cliente.suprimirCuenta(tokens.clienteA, ids.clienteA)).error.codigo, 'CONFLICTO', 'pedido en curso');
  const ref = ok(await API.logistica.pendientes(tokens.logistica))[0].ref_envio;
  ok(await API.logistica.actualizarEstado(tokens.logistica, ref, 'EN_RUTA'));
  ok(await API.logistica.actualizarEstado(tokens.logistica, ref, 'ENTREGADO'));
  ok(await API.cliente.suprimirCuenta(tokens.clienteA, ids.clienteA));

  const bd = DB.simularAccesoFisico();
  assert.equal(bd.users.some(u => u.id === ids.clienteA), false);
  assert.equal(bd['pseudo.pseudonimos'].some(p => p.user_id === ids.clienteA), false);
  assert.equal(bd.suscripciones_marketing.length, 0);
  assert.equal(bd.facturacion[0].bloqueado, true);
  assert.equal(bd.orders.find(o => o.id === orderId).direccion_envio_cifrada, null);
  assert.equal((await API.cliente.verPerfil(tokens.clienteA, ids.clienteA)).error.codigo, 'NO_AUTENTICADO', 'sesiones invalidadas');
});

test('Copia para desarrollo: sin datos reales, hashes, tokens ni identificadores de producción', async () => {
  const { tokens, ids } = await prepararEscenario();
  const copia = ok(await API.privacidad.copiaDesarrollo(tokens.privacidad));
  const texto = JSON.stringify(copia);
  assert.doesNotMatch(texto, /ana\.prueba|Ana Prueba|Calle Ficticia|\$2[aby]\$|tok_/);
  assert.equal(texto.includes(ids.clienteA), false);
  assert.ok(copia.usuarios.every(u => u.email.endsWith('@ejemplo.test')));
});

test('NortiPuntos: detecta manipulación del saldo y restauración de una fila antigua firmada', async () => {
  const { tokens, ids } = await prepararEscenario();
  const antigua = DB.simularAccesoFisico().loyalty_accounts.find(a => a.user_id === ids.clienteA);
  ok(await API.cliente.canjearPuntos(tokens.clienteA, ids.clienteA, 150));
  assert.equal(ok(await API.cliente.saldoPuntos(tokens.clienteA, ids.clienteA)).saldo, 350);

  // Ataque de repetición: se restaura saldo=500 con su firma válida (versión 1).
  DB.manipularFilaDirecto('loyalty_accounts', ids.clienteA, antigua);
  assert.equal((await API.cliente.saldoPuntos(tokens.clienteA, ids.clienteA)).error.codigo, 'INTEGRIDAD_COMPROMETIDA');

  // Manipulación directa del saldo sin firma.
  DB.manipularFilaDirecto('loyalty_accounts', ids.clienteA, { saldo_puntos: 999999, version: 2 });
  assert.equal((await API.cliente.canjearPuntos(tokens.clienteA, ids.clienteA, 1000)).error.codigo, 'INTEGRIDAD_COMPROMETIDA');
});
