import test from 'node:test';
import assert from 'node:assert/strict';
import { API } from '../src/api.js';
import { DB, ROLES_BD } from '../src/db/repository.js';
import { decryptField, contexto } from '../src/crypto/cipher.js';
import { huellaSupresion } from '../src/crypto/pseudonymization.js';
import { bandejaDe, ultimoCodigoPara } from '../src/infra/correo.js';
import { prepararEscenario, ok, ejercerDerecho, PASSWORD_PRUEBA, TARJETA_VISA } from '../src/dev/escenario.js';

const EMAIL_ANA = 'ana.prueba@ejemplo.test';

test('Acceso: exige contraseña y código, entrega una copia estructurada y deja trazado el flujo', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[0], cantidad: 1 }] }));
  ok(await API.cliente.crearPedido(tokens.clienteB, { items: [{ productoId: ids.productos[1], cantidad: 1 }], tarjeta: TARJETA_VISA }));

  const s = ok(await API.derechos.solicitar(tokens.clienteA, ids.clienteA, { tipo: 'ACCESO' }));
  assert.equal(s.estado, 'RECIBIDA');
  assert.deepEqual(s.verificacion, { requiereContrasena: true, requiereCodigo: true, codigoEnviadoA: 'a***@e***.test' });
  const dias = (Date.parse(s.plazo_vence_el) - Date.parse(s.recibida_el)) / 86_400_000;
  assert.equal(dias, 30, 'plazo legal de respuesta');

  const sinCodigo = await API.derechos.confirmar(tokens.clienteA, ids.clienteA, s.id, { password: PASSWORD_PRUEBA });
  assert.equal(sinCodigo.error.codigo, 'CREDENCIALES_INVALIDAS');
  const r = ok(await API.derechos.confirmar(tokens.clienteA, ids.clienteA, s.id, { password: PASSWORD_PRUEBA, codigo: ultimoCodigoPara(EMAIL_ANA) }));

  assert.equal(r.solicitud.estado, 'CERRADA');
  assert.equal(r.solicitud.resultado, 'EJECUTADA');
  for (const f of ['recibida_el', 'verificada_el', 'evaluada_el', 'resuelta_el', 'cerrada_el']) assert.ok(r.solicitud[f], f);
  assert.equal(r.datos.formato, 'nortishop.export.v1');
  assert.equal(r.datos.datos_personales.email, EMAIL_ANA);
  assert.equal(r.datos.pedidos.length, 1);
  assert.ok(r.datos.informacion_del_tratamiento.destinatarios.length > 0);

  const texto = JSON.stringify(r.datos);
  assert.doesNotMatch(texto, /\$2[aby]\$|tok_norti|email_hmac|pseudo|tx_auth_|ref_envio/, 'sin información interna');
  assert.doesNotMatch(texto, /Bruno|bruno\.prueba|Pasaje Inventado/, 'sin datos de terceros');
});

test('Portabilidad: JSON legible por máquinas con los datos aportados, sin información interna de tratamiento', async () => {
  const { tokens, ids } = await prepararEscenario();
  const r = ok(await ejercerDerecho(tokens.clienteA, ids.clienteA, { tipo: 'PORTABILIDAD' }, { emailCodigo: EMAIL_ANA }));
  const copia = JSON.parse(JSON.stringify(r.datos));
  assert.equal(copia.tipo, 'PORTABILIDAD');
  assert.deepEqual(Object.keys(copia).sort(), ['datos_facturacion', 'datos_personales', 'formato', 'generado_el', 'nortipuntos', 'pedidos', 'resenas', 'tipo', 'titular_id']);
  assert.equal(copia.nortipuntos.saldo, 500);
});

test('Verificación: 5 intentos fallidos o un código vencido anulan la solicitud', async () => {
  const { tokens, ids } = await prepararEscenario();
  const s = ok(await API.derechos.solicitar(tokens.clienteA, ids.clienteA, { tipo: 'SUPRESION' }));
  for (let i = 0; i < 5; i++) {
    assert.equal((await API.derechos.confirmar(tokens.clienteA, ids.clienteA, s.id, { password: PASSWORD_PRUEBA, codigo: '000000' })).error.codigo, 'CREDENCIALES_INVALIDAS');
  }
  const anulada = ok(await API.derechos.misSolicitudes(tokens.clienteA, ids.clienteA)).find(x => x.id === s.id);
  assert.equal(anulada.estado, 'ANULADA');
  assert.ok(ok(await API.cliente.verPerfil(tokens.clienteA, ids.clienteA)), 'la cuenta sigue existiendo');

  const s2 = ok(await API.derechos.solicitar(tokens.clienteA, ids.clienteA, { tipo: 'ACCESO' }));
  const verif = DB.simularAccesoFisico().verificaciones.find(v => v.solicitud_id === s2.id);
  DB.manipularFilaDirecto('verificaciones', verif.id, { expira_el: new Date(Date.now() - 1000).toISOString() });
  const vencida = await API.derechos.confirmar(tokens.clienteA, ids.clienteA, s2.id, { password: PASSWORD_PRUEBA, codigo: ultimoCodigoPara(EMAIL_ANA) });
  assert.equal(vencida.error.codigo, 'DATO_INVALIDO');
  assert.equal(ok(await API.derechos.misSolicitudes(tokens.clienteA, ids.clienteA)).find(x => x.id === s2.id).estado, 'ANULADA');
});

test('Rectificación: valida antes de aceptar, propaga a pedidos no despachados y no conserva los valores', async () => {
  const { tokens, ids } = await prepararEscenario();
  const { id: orderId } = ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[0], cantidad: 1 }] }));

  const invalida = await API.derechos.solicitar(tokens.clienteA, ids.clienteA, { tipo: 'RECTIFICACION', cambios: { telefono: '123' } });
  assert.equal(invalida.error.codigo, 'DATO_INVALIDO', 'reglas del sistema antes de registrar la solicitud');
  const extra = await API.derechos.solicitar(tokens.clienteA, ids.clienteA, { tipo: 'RECTIFICACION', cambios: { rut: '1-9' } });
  assert.equal(extra.error.codigo, 'CAMPO_NO_PERMITIDO');

  const s = ok(await API.derechos.solicitar(tokens.clienteA, ids.clienteA, { tipo: 'RECTIFICACION', cambios: { direccionDespacho: 'Nueva Calle Ficticia 777', comuna: 'Mejillones' } }));
  assert.deepEqual(s.verificacion, { requiereContrasena: true, requiereCodigo: false, codigoEnviadoA: null }, 'riesgo bajo: basta la contraseña');
  const r = ok(await API.derechos.confirmar(tokens.clienteA, ids.clienteA, s.id, { password: PASSWORD_PRUEBA }));
  assert.equal(r.solicitud.resultado, 'EJECUTADA');
  assert.deepEqual(r.solicitud.campos_solicitados, ['direccionDespacho', 'comuna']);

  const perfil = ok(await API.cliente.verPerfil(tokens.clienteA, ids.clienteA));
  assert.equal(perfil.direccionDespacho, 'Nueva Calle Ficticia 777');
  const pedido = DB.simularAccesoFisico().orders.find(o => o.id === orderId);
  assert.equal(decryptField(pedido.direccion_envio_cifrada, contexto('orders', 'direccion_envio_cifrada', orderId)), 'Nueva Calle Ficticia 777');
  assert.equal(pedido.comuna_envio, 'Mejillones');

  const bd = DB.simularAccesoFisico();
  assert.equal(bd.solicitudes_derechos.find(x => x.id === s.id).cambios_cifrados, null, 'los valores propuestos se borran al ejecutar');
  assert.doesNotMatch(JSON.stringify(bd.audit_log), /Nueva Calle|Mejillones/, 'la auditoría registra campos, no valores');
  assert.ok(bd.audit_log.some(a => a.accion === 'derechos:rectificacion:ejecutada' && /campos=direccionDespacho,comuna/.test(a.motivo)));
});

test('Rectificación del correo: el código va al correo nuevo y se avisa al anterior', async () => {
  const { tokens, ids } = await prepararEscenario();
  const nuevo = 'ana.nueva@ejemplo.test';
  const s = ok(await API.derechos.solicitar(tokens.clienteA, ids.clienteA, { tipo: 'RECTIFICACION', cambios: { email: nuevo } }));
  assert.equal(s.verificacion.codigoEnviadoA, 'a***@e***.test');
  assert.ok(bandejaDe(EMAIL_ANA).some(m => /cambiar el correo/.test(m.cuerpo)), 'aviso al correo actual');
  assert.equal(ultimoCodigoPara(EMAIL_ANA), null, 'el código no se envía al correo antiguo');

  ok(await API.derechos.confirmar(tokens.clienteA, ids.clienteA, s.id, { password: PASSWORD_PRUEBA, codigo: ultimoCodigoPara(nuevo) }));
  assert.ok(ok(await API.auth.iniciarSesion({ email: nuevo, password: PASSWORD_PRUEBA })).token, 'el login usa el nuevo índice ciego');
  assert.equal(ok(await API.marketing.exportarSuscriptores(tokens.marketing))[0].email, nuevo, 'propagado a la lista de envío');
});

test('Supresión: rechazo fundamentado con pedidos en curso; luego elimina, deja lápida y no revive tras restaurar', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[0], cantidad: 1 }] }));
  const respaldo = DB.simularAccesoFisico().users.find(u => u.id === ids.clienteA); // "respaldo" previo

  const rechazada = ok(await ejercerDerecho(tokens.clienteA, ids.clienteA, { tipo: 'SUPRESION' }, { emailCodigo: EMAIL_ANA }));
  assert.equal(rechazada.solicitud.resultado, 'RECHAZADA');
  assert.match(rechazada.solicitud.fundamento, /en curso/);

  const ref = ok(await API.logistica.pendientes(tokens.logistica))[0].ref_envio;
  ok(await API.logistica.actualizarEstado(tokens.logistica, ref, 'EN_RUTA'));
  ok(await API.logistica.actualizarEstado(tokens.logistica, ref, 'ENTREGADO'));
  const ejecutada = ok(await ejercerDerecho(tokens.clienteA, ids.clienteA, { tipo: 'SUPRESION' }, { emailCodigo: EMAIL_ANA }));
  assert.equal(ejecutada.solicitud.resultado, 'EJECUTADA');
  assert.match(ejecutada.solicitud.fundamento, /obligación legal/);

  let bd = DB.simularAccesoFisico();
  assert.equal(bd.users.some(u => u.id === ids.clienteA), false);
  assert.ok(bd.supresiones.some(s => s.id === huellaSupresion(ids.clienteA)), 'lápida sin datos personales');
  assert.ok(bd.consentimientos.filter(c => c.user_id === ids.clienteA).every(c => c.estado === 'REVOCADO'));
  assert.ok(bd.solicitudes_derechos.some(s => s.user_id === ids.clienteA && s.resultado === 'EJECUTADA'), 'la solicitud queda como constancia');

  // Se restaura un respaldo anterior: el titular "revive" hasta que se reaplican las supresiones.
  DB.conectar(ROLES_BD.SVC_APP).insertar('users', respaldo);
  assert.equal(ok(await API.privacidad.reaplicarSupresiones(tokens.privacidad)).reaplicadas, 1);
  bd = DB.simularAccesoFisico();
  assert.equal(bd.users.some(u => u.id === ids.clienteA), false);

  ok(await API.privacidad.ejecutarEtl(tokens.privacidad));
  assert.equal(ok(await API.analitica.compras(tokens.analista)).length, 0, 'el ETL no vuelve a usar sus datos');
});

test('Control de acceso: nadie gestiona solicitudes ajenas; el seguimiento es solo del Oficial de Privacidad', async () => {
  const { tokens, ids } = await prepararEscenario();
  const s = ok(await API.derechos.solicitar(tokens.clienteA, ids.clienteA, { tipo: 'ACCESO' }));
  assert.equal((await API.derechos.confirmar(tokens.clienteB, ids.clienteB, s.id, { password: PASSWORD_PRUEBA, codigo: ultimoCodigoPara(EMAIL_ANA) })).error.codigo, 'NO_ENCONTRADO');
  assert.equal((await API.derechos.confirmar(tokens.clienteB, ids.clienteA, s.id, { password: PASSWORD_PRUEBA })).error.codigo, 'ACCESO_DENEGADO');
  assert.equal((await API.derechos.solicitar(tokens.clienteA, ids.clienteA, { tipo: 'ACCESO' })).error.codigo, 'CONFLICTO', 'una solicitud abierta por tipo');

  for (const rol of ['admin', 'soporte', 'seguridad', 'clienteA']) {
    assert.equal((await API.derechos.gestion(tokens[rol])).error.codigo, 'ACCESO_DENEGADO', rol);
  }
  const gestion = ok(await API.derechos.gestion(tokens.privacidad));
  assert.equal(gestion.length, 1);
  assert.equal(gestion[0].vencida, false);
  assert.doesNotMatch(JSON.stringify(gestion), /@ejemplo\.test|Ana Prueba|Calle/);
});
