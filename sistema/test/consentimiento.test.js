import test from 'node:test';
import assert from 'node:assert/strict';
import { API } from '../src/api.js';
import { DB, ROLES_BD } from '../src/db/repository.js';
import { PaymentVault } from '../src/crypto/tokenization.js';
import { prepararEscenario, ok, PASSWORD_PRUEBA, TARJETA_VISA } from '../src/dev/escenario.js';

const estadoDe = async (token, userId, finalidad) =>
  ok(await API.consentimiento.estado(token, userId)).requierenConsentimiento.find(c => c.finalidad === finalidad);

const registro = (extra) => API.auth.registrar({
  nombre: 'Carla Prueba', email: 'carla@ejemplo.test', password: PASSWORD_PRUEBA,
  direccionDespacho: 'Avenida Sintética 99', comuna: 'Iquique', declaraMayorDeEdad: true, ...extra
});

test('Cada finalidad se decide por separado: aceptar una no activa las demás', async () => {
  await prepararEscenario();
  const { id } = ok(await registro({ aceptaMarketing: true, aceptaAnalitica: 'true' }));
  const { token } = ok(await API.auth.iniciarSesion({ email: 'carla@ejemplo.test', password: PASSWORD_PRUEBA }));
  const estado = ok(await API.consentimiento.estado(token, id)).requierenConsentimiento;
  assert.deepEqual(Object.fromEntries(estado.map(c => [c.finalidad, c.estado])), {
    MARKETING_EMAIL: 'OTORGADO',
    GUARDAR_MEDIO_PAGO: 'NUNCA_OTORGADO',
    ANALITICA_COMPRAS: 'NUNCA_OTORGADO' // 'true' como texto no cuenta: solo el booleano true
  });
});

test('Se registra fecha y hora, finalidad, versión y estado; el historial no guarda datos personales', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await API.consentimiento.revocar(tokens.clienteA, ids.clienteA, { finalidad: 'MARKETING_EMAIL' }));
  ok(await API.consentimiento.otorgar(tokens.clienteA, ids.clienteA, { finalidad: 'MARKETING_EMAIL', version: '2.0' }));

  const historial = ok(await API.consentimiento.historial(tokens.clienteA, ids.clienteA)).filter(h => h.finalidad === 'MARKETING_EMAIL');
  assert.deepEqual(historial.map(h => [h.accion, h.canal, h.version_texto]), [
    ['OTORGADO', 'REGISTRO', '2.0'], ['REVOCADO', 'CENTRO_PRIVACIDAD', '2.0'], ['OTORGADO', 'CENTRO_PRIVACIDAD', '2.0']]);
  assert.ok(historial.every(h => !Number.isNaN(Date.parse(h.ocurrido_el))));

  const filas = DB.simularAccesoFisico();
  const actual = filas.consentimientos.find(c => c.user_id === ids.clienteA && c.finalidad === 'MARKETING_EMAIL');
  assert.equal(actual.estado, 'OTORGADO');
  assert.ok(actual.otorgado_el && actual.revocado_el === null);
  assert.doesNotMatch(JSON.stringify(filas.consentimientos_historial), /@ejemplo\.test|Ana Prueba|Calle/);
  assert.deepEqual(Object.keys(filas.consentimientos_historial[0]).sort(), ['accion', 'canal', 'finalidad', 'id', 'ocurrido_el', 'user_id', 'version_texto']);
});

test('Revocar MARKETING_EMAIL lo saca de la exportación sin tocar otros consentimientos', async () => {
  const { tokens, ids } = await prepararEscenario();
  assert.equal(ok(await API.marketing.exportarSuscriptores(tokens.marketing)).length, 1);
  const r = ok(await API.consentimiento.revocar(tokens.clienteA, ids.clienteA, { finalidad: 'MARKETING_EMAIL' }));
  assert.ok(r.revocado_el);
  assert.equal(ok(await API.marketing.exportarSuscriptores(tokens.marketing)).length, 0);
  assert.equal(DB.simularAccesoFisico().suscripciones_marketing.length, 0, 'la lista de envío se elimina');
  assert.equal((await estadoDe(tokens.clienteA, ids.clienteA, 'GUARDAR_MEDIO_PAGO')).estado, 'OTORGADO');
  assert.equal((await estadoDe(tokens.clienteA, ids.clienteA, 'ANALITICA_COMPRAS')).estado, 'OTORGADO');
});

test('Revocar GUARDAR_MEDIO_PAGO invalida el token y exige la tarjeta en la próxima compra', async () => {
  const { tokens, ids } = await prepararEscenario();
  const token = DB.simularAccesoFisico().users.find(u => u.id === ids.clienteA).token_pago;
  ok(await API.consentimiento.revocar(tokens.clienteA, ids.clienteA, { finalidad: 'GUARDAR_MEDIO_PAGO' }));

  assert.equal(PaymentVault.vault.has(token), false, 'token revocado en la pasarela');
  assert.equal(ok(await API.cliente.verPerfil(tokens.clienteA, ids.clienteA)).medioPago, null);
  const sinTarjeta = await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[1], cantidad: 1 }] });
  assert.equal(sinTarjeta.error.codigo, 'DATO_INVALIDO');
  ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[1], cantidad: 1 }], tarjeta: TARJETA_VISA }));

  ok(await API.consentimiento.otorgar(tokens.clienteA, ids.clienteA, { finalidad: 'GUARDAR_MEDIO_PAGO', version: '1.0', tarjeta: TARJETA_VISA }));
  assert.equal(ok(await API.cliente.verPerfil(tokens.clienteA, ids.clienteA)).medioPago.last4, '1111');
});

test('Revocar ANALITICA_COMPRAS borra sus filas analíticas y el ETL deja de incluirlo', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[0], cantidad: 1 }] }));
  ok(await API.privacidad.ejecutarEtl(tokens.privacidad));
  assert.equal(ok(await API.analitica.compras(tokens.analista)).length, 1);

  ok(await API.consentimiento.revocar(tokens.clienteA, ids.clienteA, { finalidad: 'ANALITICA_COMPRAS' }));
  assert.equal(ok(await API.analitica.compras(tokens.analista)).length, 0, 'efecto inmediato');
  ok(await API.privacidad.ejecutarEtl(tokens.privacidad));
  assert.equal(ok(await API.analitica.compras(tokens.analista)).length, 0, 'el ETL respeta la revocación');
});

test('Un texto nuevo deja el consentimiento en REQUIERE_RENOVACION y los procesos dejan de usarlo', async () => {
  const { tokens, ids } = await prepararEscenario();
  const nuevo = { finalidad: 'MARKETING_EMAIL', version: '3.0', texto: 'Autorizo a NortiShop a enviarme ofertas por correo y por notificaciones de la aplicación.' };
  assert.equal((await API.consentimiento.publicarVersion(tokens.clienteA, nuevo)).error.codigo, 'ACCESO_DENEGADO');
  assert.equal((await API.consentimiento.publicarVersion(tokens.admin, nuevo)).error.codigo, 'ACCESO_DENEGADO');
  assert.equal(ok(await API.consentimiento.publicarVersion(tokens.privacidad, nuevo)).consentimientosARenovar, 1);

  const c = await estadoDe(tokens.clienteA, ids.clienteA, 'MARKETING_EMAIL');
  assert.equal(c.estado, 'REQUIERE_RENOVACION');
  assert.equal(c.habilita_tratamiento, false);
  assert.equal(ok(await API.marketing.exportarSuscriptores(tokens.marketing)).length, 0, 'no se envía con un consentimiento desactualizado');

  const conVersionVieja = await API.consentimiento.otorgar(tokens.clienteA, ids.clienteA, { finalidad: 'MARKETING_EMAIL', version: '2.0' });
  assert.equal(conVersionVieja.error.codigo, 'CONFLICTO', 'debe aceptar el texto que realmente se le mostró');
  ok(await API.consentimiento.otorgar(tokens.clienteA, ids.clienteA, { finalidad: 'MARKETING_EMAIL', version: '3.0' }));
  assert.equal(ok(await API.marketing.exportarSuscriptores(tokens.marketing)).length, 1);
  assert.ok(ok(await API.consentimiento.historial(tokens.clienteA, ids.clienteA)).some(h => h.accion === 'RENOVADO' && h.version_texto === '3.0'));
});

test('Baja con un clic desde el correo: revoca con canal ENLACE_CORREO y no revela tokens válidos', async () => {
  const { tokens, ids } = await prepararEscenario();
  const { token_desuscripcion } = ok(await API.marketing.exportarSuscriptores(tokens.marketing))[0];
  assert.deepEqual(ok(await API.consentimiento.desuscribir('00000000-0000-4000-8000-000000000000')), { suscrito: false });
  assert.deepEqual(ok(await API.consentimiento.desuscribir(token_desuscripcion)), { suscrito: false });
  const h = ok(await API.consentimiento.historial(tokens.clienteA, ids.clienteA));
  assert.equal(h[h.length - 1].canal, 'ENLACE_CORREO');
  assert.equal((await estadoDe(tokens.clienteA, ids.clienteA, 'MARKETING_EMAIL')).estado, 'REVOCADO');
});

test('Solo se piden consentimientos para finalidades que dependen de él', async () => {
  const { tokens, ids } = await prepararEscenario();
  const r = await API.consentimiento.otorgar(tokens.clienteA, ids.clienteA, { finalidad: 'CUENTA_Y_COMPRAS', version: '1.0' });
  assert.equal(r.error.codigo, 'DATO_INVALIDO');
  const { otrasBases } = ok(await API.consentimiento.estado(tokens.clienteA, ids.clienteA));
  assert.ok(otrasBases.some(o => o.codigo === 'FACTURACION' && o.base === 'OBLIGACION_LEGAL'));
});

test('Menores: sin declaración de mayoría de edad no hay cuenta; solo se guarda la fecha de la declaración', async () => {
  await prepararEscenario();
  assert.equal((await registro({ declaraMayorDeEdad: false })).error.codigo, 'DATO_INVALIDO');
  assert.equal((await registro({ fecha_nacimiento: '2012-01-01' })).error.codigo, 'CAMPO_NO_PERMITIDO');
  const { id } = ok(await registro({}));
  const fila = DB.simularAccesoFisico().users.find(u => u.id === id);
  assert.ok(fila.mayor_edad_declarado_el);
  assert.equal('fecha_nacimiento' in fila, false);
});

test('El historial de consentimientos es de solo inserción para la aplicación', async () => {
  const { ids } = await prepararEscenario();
  const bd = DB.conectar(ROLES_BD.SVC_APP);
  const fila = bd.seleccionar('consentimientos_historial', h => h.user_id === ids.clienteA)[0];
  assert.throws(() => bd.actualizar('consentimientos_historial', fila.id, { accion: 'REVOCADO' }), { code: 'BD_PERMISO_DENEGADO' });
  assert.throws(() => bd.eliminar('consentimientos_historial', fila.id), { code: 'BD_PERMISO_DENEGADO' });
});
