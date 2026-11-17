import test from 'node:test';
import assert from 'node:assert/strict';
import { API } from '../src/api.js';
import { DB } from '../src/db/repository.js';
import { decryptField, contexto } from '../src/crypto/cipher.js';
import { bandejaDe, ultimoCodigoPara } from '../src/infra/correo.js';
import { prepararEscenario, ok, ejercerDerecho, PASSWORD_PRUEBA, TARJETA_VISA } from '../src/dev/escenario.js';

// Pruebas de la actividad "Mecanismos técnicos para el ejercicio de derechos" (PR-05):
// una solicitud concreta por mecanismo, incluida una de un solicitante NO verificado.

const EMAIL_ANA = 'ana.prueba@ejemplo.test';
const EMAIL_INVITADO = 'invitada@ejemplo.test';
const encuestasDe = (email) => bandejaDe(email).filter(m => /cómo fue tu compra/.test(m.asunto));

async function entregar(tokens, indice = 0) {
  const ref = ok(await API.logistica.pendientes(tokens.logistica))[indice].ref_envio;
  ok(await API.logistica.actualizarEstado(tokens.logistica, ref, 'EN_RUTA'));
  ok(await API.logistica.actualizarEstado(tokens.logistica, ref, 'ENTREGADO'));
}

const pedidoInvitado = (ids) => API.invitado.crearPedido({
  nombre: 'Invitada Prueba', email: EMAIL_INVITADO, direccionDespacho: 'Calle Invitada 77', comuna: 'Arica',
  items: [{ productoId: ids.productos[1], cantidad: 1 }], tarjeta: TARJETA_VISA
});

test('1. Canal y modelo: cada solicitud tiene folio, canal, quién la presentó, estado y fecha límite', async () => {
  const { tokens, ids } = await prepararEscenario();
  const s = ok(await API.derechos.solicitar(tokens.clienteA, ids.clienteA, { tipo: 'OPOSICION', tratamiento: 'ENCUESTAS_SATISFACCION' }));
  assert.match(s.folio, /^DER-\d{4}-000001$/);
  assert.equal(s.canal, 'CENTRO_PRIVACIDAD');
  assert.equal(s.presentada_por, 'TITULAR');
  assert.equal(s.estado, 'RECIBIDA');
  assert.equal((Date.parse(s.plazo_vence_el) - Date.parse(s.recibida_el)) / 86_400_000, 30);
  const sinCuenta = ok(await API.derechos.solicitarSinCuenta({ email: 'ex.cliente@ejemplo.test', tipo: 'ACCESO' }));
  assert.equal(sinCuenta.canal, 'FORMULARIO_SIN_CUENTA', 'disponible para quien no tiene cuenta activa');
  assert.match(sinCuenta.folio, /000002$/);
});

test('2. Solicitante NO verificado: ningún mecanismo entrega ni modifica datos', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[0], cantidad: 1 }] }));
  const antes = JSON.stringify(DB.simularAccesoFisico().users);
  for (const entrada of [
    { tipo: 'ACCESO' }, { tipo: 'PORTABILIDAD' }, { tipo: 'SUPRESION' },
    { tipo: 'RECTIFICACION', cambios: { nombre: 'Nombre Falso' } },
    { tipo: 'OPOSICION', tratamiento: 'ENCUESTAS_SATISFACCION' }, { tipo: 'BLOQUEO', motivo: 'VIGENCIA_DUDOSA' }
  ]) {
    const s = ok(await API.derechos.solicitar(tokens.clienteA, ids.clienteA, entrada));
    const r = await API.derechos.confirmar(tokens.clienteA, ids.clienteA, s.id, { password: 'clave-equivocada-123', codigo: '000000' });
    assert.equal(r.error.codigo, 'CREDENCIALES_INVALIDAS', entrada.tipo);
    assert.equal(ok(await API.derechos.misSolicitudes(tokens.clienteA, ids.clienteA)).find(x => x.id === s.id).estado, 'RECIBIDA');
  }
  const bd = DB.simularAccesoFisico();
  assert.equal(JSON.stringify(bd.users), antes, 'nada se modificó');
  assert.equal(bd.descargas.length + bd.oposiciones.length + bd.bloqueos.length + bd.rectificaciones.length, 0);
  // Sin cuenta: código incorrecto
  const sc = ok(await API.derechos.solicitarSinCuenta({ email: EMAIL_INVITADO, tipo: 'ACCESO' }));
  assert.equal((await API.derechos.confirmarSinCuenta({ solicitudId: sc.id, codigo: '000000' })).error.codigo, 'CREDENCIALES_INVALIDAS');
});

test('2b. Sin cuenta: el invitado verifica su correo y recibe solo sus pedidos; cuentas activas van al Centro de privacidad', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await pedidoInvitado(ids));
  const s = ok(await API.derechos.solicitarSinCuenta({ email: EMAIL_INVITADO, tipo: 'ACCESO' }));
  const r = ok(await API.derechos.confirmarSinCuenta({ solicitudId: s.id, codigo: ultimoCodigoPara(EMAIL_INVITADO) }));
  assert.equal(r.solicitud.resultado, 'EJECUTADA');
  const copia = ok(await API.derechos.descargarSinCuenta(r.descarga.token));
  assert.equal(copia.pedidos_como_invitado.length, 1);
  assert.equal(copia.pedidos_como_invitado[0].email, EMAIL_INVITADO);
  assert.doesNotMatch(JSON.stringify(copia), /Ana Prueba|ana\.prueba/, 'sin datos de otras personas');
  assert.equal((await API.derechos.descargarSinCuenta(r.descarga.token)).error.codigo, 'NO_ENCONTRADO', 'un solo uso');

  const conCuenta = ok(await API.derechos.solicitarSinCuenta({ email: EMAIL_ANA, tipo: 'ACCESO' }));
  const rc = ok(await API.derechos.confirmarSinCuenta({ solicitudId: conCuenta.id, codigo: ultimoCodigoPara(EMAIL_ANA) }));
  assert.equal(rc.solicitud.resultado, 'RECHAZADA');
  assert.equal(rc.descarga, null, 'una cuenta activa exige también la contraseña');

  const sinDatos = ok(await API.derechos.solicitarSinCuenta({ email: 'nadie@ejemplo.test', tipo: 'ACCESO' }));
  const rn = ok(await API.derechos.confirmarSinCuenta({ solicitudId: sinDatos.id, codigo: ultimoCodigoPara('nadie@ejemplo.test') }));
  assert.match(rn.solicitud.fundamento, /No encontramos datos/);
  assert.ok(tokens);
});

test('3. Acceso: datos de todas las fuentes, con origen, finalidad, destinatarios y plazos', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[0], cantidad: 1 }] }));
  ok(await API.cliente.publicarResena(tokens.clienteA, { productoId: ids.productos[0], calificacion: 5, alias: 'ana_p' }));
  const r = ok(await ejercerDerecho(tokens.clienteA, ids.clienteA, { tipo: 'ACCESO' }, { emailCodigo: EMAIL_ANA }));
  const datos = ok(await API.derechos.descargar(tokens.clienteA, r.descarga.token));
  const lugares = datos.informacion_del_tratamiento.donde_se_encontraron_sus_datos.map(u => u.descripcion);
  for (const l of ['Cuenta y datos de contacto', 'Pedidos', 'Movimientos de NortiPuntos', 'Reseñas publicadas (con alias)', 'Historial de sus consentimientos']) {
    assert.ok(lugares.includes(l), l);
  }
  assert.equal(datos.resenas.length, 1);
  assert.ok(datos.origen_y_finalidad.pedidos.finalidad);
  assert.ok(datos.informacion_del_tratamiento.plazos_de_conservacion.respaldos);
  assert.equal(datos.informacion_del_tratamiento.destinatarios.length, 3);
});

test('4. Rectificación: registra valor anterior, nuevo, quién y cuándo, y avisa a terceros', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[0], cantidad: 1 }] }));
  const r = ok(await ejercerDerecho(tokens.clienteA, ids.clienteA, { tipo: 'RECTIFICACION', cambios: { direccionDespacho: 'Nueva Calle Ficticia 777' } }));
  assert.match(r.solicitud.fundamento, /OPERADOR_LOGISTICO/);

  const bd = DB.simularAccesoFisico();
  const rec = bd.rectificaciones[0];
  assert.equal(rec.campo, 'direccionDespacho');
  assert.equal(rec.actor_id, ids.clienteA);
  assert.ok(rec.created_at);
  assert.equal(decryptField(rec.valor_anterior_cifrado, contexto('rectificaciones', 'valor_anterior_cifrado', rec.id)), 'Calle Ficticia 123, Depto 4');
  assert.equal(decryptField(rec.valor_nuevo_cifrado, contexto('rectificaciones', 'valor_nuevo_cifrado', rec.id)), 'Nueva Calle Ficticia 777');
  assert.doesNotMatch(JSON.stringify(bd.rectificaciones), /Nueva Calle|Calle Ficticia/, 'cifrado en reposo');
  assert.ok(bd.comunicaciones_terceros.some(c => c.tercero === 'OPERADOR_LOGISTICO' && c.tipo === 'RECTIFICACION'));
  assert.doesNotMatch(JSON.stringify(bd.audit_log), /Nueva Calle/, 'la auditoría no guarda valores');

  const acceso = ok(await ejercerDerecho(tokens.clienteA, ids.clienteA, { tipo: 'ACCESO' }, { emailCodigo: EMAIL_ANA }));
  const copia = ok(await API.derechos.descargar(tokens.clienteA, acceso.descarga.token));
  assert.deepEqual(copia.rectificaciones.map(x => [x.campo, x.valor_anterior, x.valor_nuevo]), [['direccionDespacho', 'Calle Ficticia 123, Depto 4', 'Nueva Calle Ficticia 777']]);
});

test('5. Supresión: elimina, bloquea lo exigido por ley con fecha de término y luego lo elimina', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await API.cliente.crearPedido(tokens.clienteA, {
    items: [{ productoId: ids.productos[0], cantidad: 1 }], tipoDocumento: 'FACTURA',
    facturacion: { rut: '76.086.428-5', razonSocial: 'Empresa Ficticia SpA', direccion: 'Oficina Inventada 1' }
  }));
  await entregar(tokens);
  const acceso = ok(await ejercerDerecho(tokens.clienteA, ids.clienteA, { tipo: 'ACCESO' }, { emailCodigo: EMAIL_ANA }));
  assert.equal(DB.simularAccesoFisico().descargas.length, 1, 'copia exportada pendiente');

  const r = ok(await ejercerDerecho(tokens.clienteA, ids.clienteA, { tipo: 'SUPRESION' }, { emailCodigo: EMAIL_ANA }));
  assert.equal(r.solicitud.resultado, 'PARCIAL');
  assert.match(r.solicitud.fundamento, /BLOQUEADOS 1 documento\(s\) tributario\(s\).*hasta el \d{4}-\d{2}-\d{2}/);
  assert.match(r.solicitud.fundamento, /respaldos se sobrescriben/);
  let bd = DB.simularAccesoFisico();
  assert.equal(bd.descargas.length, 0, 'la supresión alcanza a las copias exportadas');
  assert.equal((await API.derechos.descargarSinCuenta(acceso.descarga.token)).error.codigo, 'NO_ENCONTRADO');
  const factura = bd.facturacion[0];
  assert.equal(factura.bloqueado, true);
  assert.equal(new Date(factura.bloqueado_hasta).getFullYear(), new Date(factura.created_at).getFullYear() + 6);

  assert.equal(ok(await API.privacidad.eliminarBloqueadosVencidos(tokens.privacidad)).eliminados, 0, 'antes del plazo legal se conserva');
  const en7anios = new Date(Date.now() + 7 * 366 * 86_400_000).toISOString();
  assert.equal(ok(await API.privacidad.eliminarBloqueadosVencidos(tokens.privacidad, en7anios)).eliminados, 1);
  bd = DB.simularAccesoFisico();
  assert.equal(bd.facturacion.length, 0);
  assert.equal(bd.orders[0].facturacion_id, null);
});

test('5b. Supresión sin cuenta: el invitado elimina su contacto; se conservan montos sin datos personales', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await pedidoInvitado(ids));
  const pendiente = ok(await API.derechos.solicitarSinCuenta({ email: EMAIL_INVITADO, tipo: 'SUPRESION' }));
  const rp = ok(await API.derechos.confirmarSinCuenta({ solicitudId: pendiente.id, codigo: ultimoCodigoPara(EMAIL_INVITADO) }));
  assert.equal(rp.solicitud.resultado, 'RECHAZADA', 'pedido en curso');

  await entregar(tokens);
  const s = ok(await API.derechos.solicitarSinCuenta({ email: EMAIL_INVITADO, tipo: 'SUPRESION' }));
  const r = ok(await API.derechos.confirmarSinCuenta({ solicitudId: s.id, codigo: ultimoCodigoPara(EMAIL_INVITADO) }));
  assert.equal(r.solicitud.resultado, 'PARCIAL');
  const fila = DB.simularAccesoFisico().orders_invitado[0];
  for (const c of ['email_hmac', 'nombre_invitado_cifrado', 'email_invitado_cifrado', 'direccion_envio_cifrada']) assert.equal(fila[c], null, c);
  assert.ok(fila.total_clp > 0);
});

test('6a. Oposición: excluye al titular de la encuesta (base: interés legítimo) sin afectar el resto', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[0], cantidad: 1 }] }));
  ok(await API.cliente.crearPedido(tokens.clienteB, { items: [{ productoId: ids.productos[1], cantidad: 1 }], tarjeta: TARJETA_VISA }));
  const r = ok(await ejercerDerecho(tokens.clienteA, ids.clienteA, { tipo: 'OPOSICION', tratamiento: 'ENCUESTAS_SATISFACCION' }));
  assert.equal(r.solicitud.resultado, 'EJECUTADA');

  await entregar(tokens, 0);
  await entregar(tokens, 0);
  assert.equal(encuestasDe(EMAIL_ANA).length, 0, 'Ana se opuso');
  assert.equal(encuestasDe('bruno.prueba@ejemplo.test').length, 1, 'Bruno sí recibe la encuesta');
  assert.ok(DB.simularAccesoFisico().audit_log.some(a => a.accion === 'tratamiento:encuesta_satisfaccion' && a.motivo === 'OPOSICION_ACTIVA'));
  assert.equal(ok(await API.marketing.exportarSuscriptores(tokens.marketing)).length, 1, 'el marketing consentido no se ve afectado');

  ok(await API.derechos.retirarOposicion(tokens.clienteA, ids.clienteA, { tratamiento: 'ENCUESTAS_SATISFACCION' }));
  ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[2], cantidad: 1 }] }));
  await entregar(tokens, 0);
  assert.equal(encuestasDe(EMAIL_ANA).length, 1, 'al retirar la oposición vuelve a aplicarse');
});

test('6b. Bloqueo: los datos se conservan pero no se usan; se levanta al rectificar', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[0], cantidad: 1 }] }));
  const r = ok(await ejercerDerecho(tokens.clienteA, ids.clienteA, { tipo: 'BLOQUEO', motivo: 'EXACTITUD_EN_DISPUTA' }));
  assert.equal(r.solicitud.resultado, 'EJECUTADA');
  assert.deepEqual(ok(await API.derechos.misRestricciones(tokens.clienteA, ids.clienteA)).bloqueo.motivo, 'EXACTITUD_EN_DISPUTA');

  assert.equal(ok(await API.marketing.exportarSuscriptores(tokens.marketing)).length, 0, 'fuera del marketing aunque consintió');
  ok(await API.privacidad.ejecutarEtl(tokens.privacidad));
  assert.equal(ok(await API.analitica.compras(tokens.analista)).length, 0, 'fuera de la analítica');
  await entregar(tokens);
  assert.equal(encuestasDe(EMAIL_ANA).length, 0, 'sin encuestas');
  assert.ok(ok(await API.cliente.verPerfil(tokens.clienteA, ids.clienteA)).nombre, 'los datos se conservan');
  assert.ok(DB.simularAccesoFisico().comunicaciones_terceros.some(c => c.tercero === 'PLATAFORMA_CORREO' && c.tipo === 'BLOQUEO'));

  ok(await ejercerDerecho(tokens.clienteA, ids.clienteA, { tipo: 'RECTIFICACION', cambios: { nombre: 'Ana Corregida Uno' } }));
  assert.equal(ok(await API.derechos.misRestricciones(tokens.clienteA, ids.clienteA)).bloqueo, null, 'la causa desapareció');
  assert.equal(ok(await API.marketing.exportarSuscriptores(tokens.marketing)).length, 1);
});

test('7. Plazos: se avisa al equipo de privacidad cuando una solicitud está por vencer', async () => {
  const { tokens, ids } = await prepararEscenario();
  const s = ok(await API.derechos.solicitar(tokens.clienteA, ids.clienteA, { tipo: 'ACCESO' }));
  assert.deepEqual(ok(await API.derechos.revisarPlazos(tokens.privacidad)), []);
  const en27dias = new Date(Date.now() + 27 * 86_400_000).toISOString();
  const aviso = ok(await API.derechos.revisarPlazos(tokens.privacidad, en27dias));
  assert.equal(aviso[0].folio, s.folio);
  assert.ok(aviso[0].dias_restantes <= 5);
  assert.ok(bandejaDe('privacidad@nortishop.test').some(m => m.cuerpo.includes(s.folio)));
  const en31dias = new Date(Date.now() + 31 * 86_400_000).toISOString();
  assert.equal(ok(await API.derechos.revisarPlazos(tokens.privacidad, en31dias))[0].vencida, true);
  assert.equal((await API.derechos.revisarPlazos(tokens.admin)).error.codigo, 'ACCESO_DENEGADO');
});

test('Localizar los datos de un titular: mapa sin contenido, solo para el Oficial de Privacidad', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[0], cantidad: 1 }] }));
  const mapa = ok(await API.derechos.localizar(tokens.privacidad, ids.clienteA));
  assert.ok(mapa.ubicaciones.some(u => u.ubicacion === 'orders' && u.registros === 1));
  assert.ok(mapa.terceros.some(t => t.tercero === 'Operador logístico'));
  assert.doesNotMatch(JSON.stringify(mapa), /@ejemplo\.test|Ana Prueba|Calle Ficticia/);
  for (const rol of ['admin', 'soporte', 'clienteA']) assert.equal((await API.derechos.localizar(tokens[rol], ids.clienteA)).error.codigo, 'ACCESO_DENEGADO', rol);
});
