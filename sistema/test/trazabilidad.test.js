import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { API } from '../src/api.js';
import { DB, ESQUEMA } from '../src/db/repository.js';
import { logger } from '../src/security/logger.js';
import { conOrigen } from '../src/security/contexto.js';
import { CAMPOS_REGISTRO, CAMPOS_DATOS } from '../src/security/catalogoAuditoria.js';
import { fueraDeHorario, REGLAS } from '../src/security/detection.js';
import { ejecutarSimulacro, compararConVerdad } from '../src/dev/simulacro.js';
import { ultimoCodigoPara } from '../src/infra/correo.js';
import { prepararEscenario, ok, ejercerDerecho, PASSWORD_PRUEBA, TARJETA_VISA } from '../src/dev/escenario.js';
import { severidadMinima } from '../src/services/incidentService.js';

const auditoria = () => DB.simularAccesoFisico().audit_log;
const alertasDe = async (tokens, regla) => ok(await API.seguridad.alertas(tokens.seguridad)).filter(a => a.regla === regla);
const DIA = 86_400_000;

/** Recorre casi todas las operaciones del sistema para comprobar que todo evento está catalogado. */
async function flujoAmplio() {
  const filas = [];
  const { tokens, ids } = await prepararEscenario();
  const t = tokens;
  ok(await API.cliente.verPerfil(t.clienteA, ids.clienteA));
  await API.cliente.verPerfil(t.clienteB, ids.clienteA); // denegado: recurso ajeno
  ok(await API.cliente.misPedidos(t.clienteA, ids.clienteA));
  ok(await API.cliente.actualizarPerfil(t.clienteA, ids.clienteA, { telefono: '+56 9 3333 4444' }));
  ok(await API.cliente.crearPedido(t.clienteA, { items: [{ productoId: ids.productos[0], cantidad: 1 }] }));
  const inv = ok(await API.invitado.crearPedido({ nombre: 'Invitada Prueba', email: 'invitada@ejemplo.test', direccionDespacho: 'Calle Invitada 77', comuna: 'Arica', items: [{ productoId: ids.productos[1], cantidad: 1 }], tarjeta: TARJETA_VISA }));
  ok(await API.invitado.consultarPedido(inv.tokenSeguimiento));
  ok(await API.cliente.saldoPuntos(t.clienteA, ids.clienteA));
  ok(await API.cliente.canjearPuntos(t.clienteA, ids.clienteA, 100));
  ok(await API.cliente.publicarResena(t.clienteA, { productoId: ids.productos[0], calificacion: 5, alias: 'AnaCompra' }));
  const [envio] = ok(await API.logistica.pendientes(t.logistica));
  ok(await API.logistica.etiqueta(t.logistica, envio.ref_envio));
  ok(await API.logistica.actualizarEstado(t.logistica, envio.ref_envio, 'EN_RUTA'));
  ok(await API.soporte.buscarCliente(t.soporte, 'ana.prueba@ejemplo.test'));
  ok(await API.soporte.revelarDatosContacto(t.soporte, ids.clienteA, { ticket: 'TCK-1001', motivo: 'Cliente pide confirmar su dirección' }));
  ok(await API.consentimiento.revocar(t.clienteA, ids.clienteA, { finalidad: 'ANALITICA_COMPRAS' }));
  ok(await API.marketing.exportarSuscriptores(t.marketing));
  ok(await API.privacidad.ejecutarEtl(t.privacidad));
  ok(await API.privacidad.anonimizarInvitados(t.privacidad));
  ok(await API.privacidad.copiaDesarrollo(t.privacidad));
  ok(await ejercerDerecho(t.clienteA, ids.clienteA, { tipo: 'RECTIFICACION', cambios: { telefono: '+56 9 5555 6666' } }));
  ok(await ejercerDerecho(t.clienteA, ids.clienteA, { tipo: 'ACCESO' }, { emailCodigo: 'ana.prueba@ejemplo.test' }));
  ok(await ejercerDerecho(t.clienteA, ids.clienteA, { tipo: 'OPOSICION', tratamiento: 'ENCUESTAS_SATISFACCION' }));
  ok(await API.derechos.retirarOposicion(t.clienteA, ids.clienteA, { tratamiento: 'ENCUESTAS_SATISFACCION' }));
  ok(await ejercerDerecho(t.clienteA, ids.clienteA, { tipo: 'BLOQUEO', motivo: 'VIGENCIA_DUDOSA' }));
  ok(await API.derechos.levantarBloqueo(t.clienteA, ids.clienteA));
  const sc = ok(await API.derechos.solicitarSinCuenta({ email: 'invitada@ejemplo.test', tipo: 'ACCESO' }));
  const r = ok(await API.derechos.confirmarSinCuenta({ solicitudId: sc.id, codigo: ultimoCodigoPara('invitada@ejemplo.test') }));
  if (r.descarga) ok(await API.derechos.descargarSinCuenta(r.descarga.token));
  ok(await API.derechos.revisarPlazos(t.privacidad));
  ok(await API.derechos.localizar(t.privacidad, ids.clienteB));
  ok(await ejercerDerecho(t.clienteB, ids.clienteB, { tipo: 'SUPRESION' }, { emailCodigo: 'bruno.prueba@ejemplo.test' }));
  ok(await API.privacidad.reaplicarSupresiones(t.privacidad));
  ok(await API.privacidad.eliminarBloqueadosVencidos(t.privacidad));
  ok(await API.admin.desactivarPersonal(t.admin, ids.analista));
  ok(await API.auditoria.consultar(t.admin, {}));
  ok(await API.auditoria.verificar(t.seguridad));
  ok(await API.auditoria.reconstruir(t.seguridad, { titularRef: ids.clienteA, motivo: 'Revisión de prueba del catálogo' }));
  ok(await API.auditoria.purgarVencidos(t.privacidad));
  ok(await API.auth.cerrarSesion(t.clienteA));
  filas.push(...auditoria());
  // Fases de incidente
  await ejecutarSimulacro();
  filas.push(...auditoria());
  return filas;
}

// ---------------------------------------------------------------- 1. Qué se audita y con qué campos
test('1. Cada registro tiene los campos definidos en el catálogo, y todo evento emitido está catalogado', async () => {
  assert.deepEqual(CAMPOS_REGISTRO.map(([c]) => c), Object.keys(ESQUEMA.audit_log.columnas), 'catálogo de campos = esquema de audit_log');
  const filas = await flujoAmplio();
  const noCatalogados = filas.filter(f => f.categoria === 'NO_CATALOGADO').map(f => f.accion);
  assert.deepEqual([...new Set(noCatalogados)], [], 'eventos sin entrada en el catálogo');
  assert.equal(logger.registros().some(r => r.evento === 'evento_no_catalogado'), false);
  for (const f of filas) {
    for (const c of ['secuencia', 'id', 'created_at', 'actor_id', 'actor_rol', 'accion', 'categoria', 'resultado', 'hash_previo', 'hash']) assert.ok(f[c] !== null && f[c] !== undefined, `${c} en ${f.accion}`);
    for (const d of (f.datos ?? '').split(',').filter(Boolean)) assert.ok(d in CAMPOS_DATOS, `"${d}" no es un nombre de campo del vocabulario`);
  }
  const categorias = new Set(filas.map(f => f.categoria));
  for (const c of ['AUTENTICACION', 'ACCESO_DATOS', 'ACCESO_SENSIBLE', 'MODIFICACION', 'TRANSACCION', 'EXPORTACION', 'SUPRESION', 'DERECHOS', 'CONSENTIMIENTO', 'CONTROL_ACCESO', 'ADMINISTRACION', 'PROCESO_PRIVACIDAD', 'SEGURIDAD', 'AUDITORIA']) {
    assert.ok(categorias.has(c), `falta la categoría ${c}`);
  }
});

// ---------------------------------------------------------------- 2. Accesos y operaciones, sin los datos
test('2. Los accesos y operaciones sobre datos personales registran titular y campos, nunca los valores', async () => {
  const { tokens, ids } = await prepararEscenario();
  const sesion = ok(await conOrigen('198.51.100.23', () => API.auth.iniciarSesion({ email: 'ana.prueba@ejemplo.test', password: PASSWORD_PRUEBA })));
  await conOrigen('198.51.100.23', async () => {
    ok(await API.cliente.verPerfil(sesion.token, ids.clienteA));
    ok(await API.cliente.actualizarPerfil(sesion.token, ids.clienteA, { direccionDespacho: 'Avenida Nueva 500' }));
    ok(await API.cliente.crearPedido(sesion.token, { items: [{ productoId: ids.productos[0], cantidad: 1 }] }));
  });
  const [envio] = ok(await API.logistica.pendientes(tokens.logistica));
  ok(await API.logistica.etiqueta(tokens.logistica, envio.ref_envio));
  ok(await API.soporte.revelarDatosContacto(tokens.soporte, ids.clienteA, { ticket: 'TCK-2002', motivo: 'Confirmación de dirección por reclamo' }));
  ok(await ejercerDerecho(tokens.clienteA, ids.clienteA, { tipo: 'RECTIFICACION', cambios: { nombre: 'Ana Rectificada Uno' } }, {}));
  ok(await API.cliente.saldoPuntos(tokens.clienteA, ids.clienteA));
  ok(await API.cliente.canjearPuntos(tokens.clienteA, ids.clienteA, 50));
  ok(await API.cliente.publicarResena(tokens.clienteA, { productoId: ids.productos[0], calificacion: 4, alias: 'AnaOpina', comentario: 'Comentario sintético de prueba' }));

  const log = auditoria();
  const de = (accion) => log.filter(f => f.accion === accion).at(-1);
  const esperado = {
    'perfil:propio:leer': 'nombre,email,direccion,telefono,medio_pago',
    'perfil:propio:editar': 'direccion',
    'pedido:crear': 'direccion,pedidos,medio_pago',
    'envios:etiqueta': 'nombre,direccion',
    'clientes:pii:revelar': 'nombre,email,telefono,direccion',
    'derechos:rectificacion:ejecutada': 'nombre',
    'puntos:consultar': 'puntos',
    'puntos:canjear': 'puntos',
    'resena:publicar': 'resena'
  };
  for (const [accion, datos] of Object.entries(esperado)) {
    const f = de(accion);
    assert.ok(f, `falta ${accion}`);
    assert.equal(f.titular_ref, ids.clienteA, `titular en ${accion}`);
    assert.equal(f.datos, datos, `datos en ${accion}`);
  }
  // Las acciones de Ana desde su sesión llevan sesión, origen seudonimizado y correlación
  for (const a of ['perfil:propio:leer', 'perfil:propio:editar', 'pedido:crear']) {
    assert.match(de(a).sesion_ref, /^ses:[0-9a-f]{16}$/);
    assert.match(de(a).origen_ref, /^org:[0-9a-f]{16}$/);
    assert.ok(de(a).correlacion_id);
  }
  assert.notEqual(de('perfil:propio:leer').correlacion_id, de('pedido:crear').correlacion_id, 'una correlación por solicitud');
  assert.equal(de('pedido:crear').sesion_ref, log.find(f => f.accion === 'auth:login' && f.origen_ref === de('pedido:crear').origen_ref).sesion_ref, 'la sesión une login y acciones');

  const texto = JSON.stringify(log);
  for (const valor of ['Avenida Nueva', 'Ana Rectificada', 'AnaOpina', 'Comentario sintético', 'Ana Prueba', 'Calle Ficticia', 'ana.prueba@ejemplo.test', '198.51.100.23', sesion.token, '1111 2222', '4111']) {
    assert.equal(texto.includes(valor), false, `"${valor}" no debe quedar en la auditoría`);
  }
});

test('2b. Cada campo del inventario (Tarea 2) implementado en el prototipo tiene al menos un evento que lo audita', async () => {
  const { EVENTOS } = await import('../src/security/catalogoAuditoria.js');
  const cubiertos = new Set(EVENTOS.flatMap(e => e.datos));
  for (const c of ['nombre', 'email', 'telefono', 'direccion', 'credenciales', 'facturacion', 'medio_pago', 'pedidos', 'puntos', 'resena']) {
    assert.ok(cubiertos.has(c), `el campo ${c} no tiene evento en el catálogo`);
  }
});

// ---------------------------------------------------------------- 3. Protección: acceso y conservación
test('3a. Reconstrucción: solo SEGURIDAD y OFICIAL_PRIVACIDAD, con motivo y pivote, y queda auditada', async () => {
  const { tokens, ids } = await prepararEscenario();
  for (const rol of ['admin', 'soporte', 'logistica', 'clienteA']) {
    assert.equal((await API.auditoria.reconstruir(tokens[rol], { titularRef: ids.clienteA, motivo: 'Revisión de un reclamo' })).error.codigo, 'ACCESO_DENEGADO', rol);
  }
  assert.equal((await API.auditoria.reconstruir(tokens.seguridad, { titularRef: ids.clienteA, motivo: 'x' })).error.codigo, 'DATO_INVALIDO', 'motivo obligatorio');
  assert.equal((await API.auditoria.reconstruir(tokens.seguridad, { motivo: 'Sin ningún pivote indicado' })).error.codigo, 'DATO_INVALIDO', 'pivote obligatorio');
  ok(await API.auditoria.reconstruir(tokens.privacidad, { titularRef: ids.clienteA, motivo: 'Reclamo del titular por un acceso' }));
  const registro = auditoria().find(f => f.accion === 'auditoria:reconstruccion');
  assert.equal(registro.actor_id, ids.privacidad);
  assert.match(registro.motivo, /pivotes=titularRef/);
});

test('3b. El sello cubre los campos nuevos: cambiar titular, datos u origen rompe la cadena', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await API.cliente.verPerfil(tokens.clienteA, ids.clienteA));
  const fila = auditoria().find(f => f.accion === 'perfil:propio:leer');
  for (const cambio of [{ titular_ref: ids.clienteB }, { datos: 'nombre' }, { origen_ref: 'org:0000000000000000' }, { sesion_ref: null }]) {
    const original = auditoria().find(f => f.secuencia === fila.secuencia);
    DB.manipularFilaDirecto('audit_log', fila.secuencia, cambio);
    const r = ok(await API.auditoria.verificar(tokens.seguridad));
    assert.ok(r.problemas.some(p => p.secuencia === fila.secuencia && /modificado/.test(p.problema)), JSON.stringify(cambio));
    DB.manipularFilaDirecto('audit_log', fila.secuencia, original);
  }
});

test('3c. Conservación: con un incidente abierto no se purga (retención extendida); al cerrarse, se aplican los plazos', async () => {
  const { tokens } = await prepararEscenario();
  const inc = ok(await API.seguridad.abrirIncidente(tokens.seguridad, { titulo: 'Incidente abierto de prueba', severidad: 'MEDIA' }));
  const en25meses = new Date(Date.now() + 760 * DIA).toISOString();
  const retenida = ok(await API.auditoria.purgarVencidos(tokens.privacidad, en25meses));
  assert.equal(retenida.purgados, 0);
  assert.equal(retenida.logsAplicacion, 0, 'los logs de aplicación también se retienen');
  assert.ok(retenida.retencionExtendidaDesde);

  ok(await API.seguridad.analizar(tokens.seguridad, inc.id, { confirmado: false })); // se cierra (descartado)
  const purga = ok(await API.auditoria.purgarVencidos(tokens.privacidad, en25meses));
  assert.ok(purga.purgados > 0 && purga.logsAplicacion > 0);
  assert.equal(purga.retencionExtendidaDesde, null);
  assert.equal(ok(await API.auditoria.verificar(tokens.seguridad)).integra, true, 'la cadena sigue verificable tras purgar');
});

test('3d. Conservación de alertas (24 meses, solo resueltas) y evidencias (5 años desde el cierre)', async () => {
  const s = await ejecutarSimulacro();
  const { tokens } = s.esc;
  const antes = DB.simularAccesoFisico();
  assert.ok(antes.alertas.length >= 2 && antes.evidencias.length === 1);
  const r24 = ok(await API.auditoria.purgarVencidos(tokens.privacidad, new Date(Date.now() + 740 * DIA).toISOString()));
  assert.equal(r24.alertas, antes.alertas.length, 'alertas escaladas a un incidente cerrado');
  assert.equal(r24.evidencias, 0, 'la evidencia se conserva 5 años');
  const r5 = ok(await API.auditoria.purgarVencidos(tokens.privacidad, new Date(Date.now() + 1830 * DIA).toISOString()));
  assert.equal(r5.evidencias, 1);
  assert.equal(DB.simularAccesoFisico().incidentes.length, 1, 'el incidente (sin datos personales) se conserva');
});

// ---------------------------------------------------------------- 4. Alertas propias de NortiShop
test('4a. TOMA_DE_CUENTA: origen nuevo + cambio de dirección en la misma sesión; no salta con el origen habitual', async () => {
  const { tokens, ids } = await prepararEscenario();
  const entrar = (ip) => conOrigen(ip, () => API.auth.iniciarSesion({ email: 'ana.prueba@ejemplo.test', password: PASSWORD_PRUEBA }));
  const casa = ok(await entrar('198.51.100.23'));
  ok(await conOrigen('198.51.100.23', () => API.cliente.actualizarPerfil(casa.token, ids.clienteA, { direccionDespacho: 'Mudanza Legítima 10' })));
  assert.equal((await alertasDe(tokens, 'TOMA_DE_CUENTA')).length, 0, 'origen habitual');

  const otro = ok(await entrar('203.0.113.99'));
  ok(await conOrigen('203.0.113.99', () => API.cliente.verPerfil(otro.token, ids.clienteA)));
  assert.equal((await alertasDe(tokens, 'TOMA_DE_CUENTA')).length, 0, 'solo mirar desde un origen nuevo no basta');
  ok(await conOrigen('203.0.113.99', () => API.cliente.crearPedido(otro.token, { items: [{ productoId: ids.productos[0], cantidad: 1 }] })));
  const [alerta] = await alertasDe(tokens, 'TOMA_DE_CUENTA');
  assert.equal(alerta.sujeto, ids.clienteA);
  assert.equal(alerta.severidad, 'ALTA');
  assert.match(alerta.detalle, /accion=pedido:crear/);
});

test('4b. ETIQUETAS_ANOMALAS: etiqueta de un envío ya entregado, o 15 etiquetas en una hora', async () => {
  const { tokens, ids } = await prepararEscenario();
  ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[0], cantidad: 1 }] }));
  const [envio] = ok(await API.logistica.pendientes(tokens.logistica));
  ok(await API.logistica.etiqueta(tokens.logistica, envio.ref_envio));
  assert.equal((await alertasDe(tokens, 'ETIQUETAS_ANOMALAS')).length, 0, 'uso normal');
  ok(await API.logistica.actualizarEstado(tokens.logistica, envio.ref_envio, 'EN_RUTA'));
  ok(await API.logistica.actualizarEstado(tokens.logistica, envio.ref_envio, 'ENTREGADO'));
  ok(await API.logistica.etiqueta(tokens.logistica, envio.ref_envio));
  const [a1] = await alertasDe(tokens, 'ETIQUETAS_ANOMALAS');
  assert.match(a1.detalle, /ENTREGADO/);
  assert.equal(a1.sujeto, ids.logistica);

  const esc2 = await prepararEscenario();
  ok(await API.cliente.crearPedido(esc2.tokens.clienteA, { items: [{ productoId: esc2.ids.productos[0], cantidad: 1 }] }));
  const [pendiente] = ok(await API.logistica.pendientes(esc2.tokens.logistica));
  for (let i = 0; i < REGLAS.ETIQUETAS_ANOMALAS.umbral - 1; i++) ok(await API.logistica.etiqueta(esc2.tokens.logistica, pendiente.ref_envio));
  assert.equal((await alertasDe(esc2.tokens, 'ETIQUETAS_ANOMALAS')).length, 0);
  ok(await API.logistica.etiqueta(esc2.tokens.logistica, pendiente.ref_envio));
  assert.equal((await alertasDe(esc2.tokens, 'ETIQUETAS_ANOMALAS')).length, 1);
});

test('4c. TICKET_REUTILIZADO: un ticket usado para revelar a 3 clientes distintos', async () => {
  const { tokens, ids } = await prepararEscenario();
  const carla = ok(await API.auth.registrar({ nombre: 'Carla Prueba Tres', email: 'carla.prueba@ejemplo.test', password: PASSWORD_PRUEBA, direccionDespacho: 'Calle Tres 3', comuna: 'Iquique', declaraMayorDeEdad: true })).id;
  const revelar = (id, ticket) => API.soporte.revelarDatosContacto(tokens.soporte, id, { ticket, motivo: 'Consulta por un despacho atrasado' });
  ok(await revelar(ids.clienteA, 'TCK-5001'));
  ok(await revelar(ids.clienteA, 'TCK-5001')); // mismo cliente: no cuenta dos veces
  ok(await revelar(ids.clienteB, 'TCK-5001'));
  assert.equal((await alertasDe(tokens, 'TICKET_REUTILIZADO')).length, 0);
  ok(await revelar(carla, 'TCK-5002')); // otro ticket
  assert.equal((await alertasDe(tokens, 'TICKET_REUTILIZADO')).length, 0);
  ok(await revelar(carla, 'TCK-5001'));
  const [a] = await alertasDe(tokens, 'TICKET_REUTILIZADO');
  assert.equal(a.sujeto, ids.soporte);
  assert.match(a.detalle, /ticket=TCK-5001/);
});

test('4d. ACCESO_FUERA_DE_HORARIO: revelar datos de madrugada alerta; en horario laboral, no', async () => {
  assert.equal(fueraDeHorario(Date.parse('2026-11-10T15:00:00Z')), false, 'martes 12:00 en Chile');
  assert.equal(fueraDeHorario(Date.parse('2026-11-10T06:30:00Z')), true, 'martes 03:30 en Chile');
  assert.equal(fueraDeHorario(Date.parse('2026-11-08T15:00:00Z')), true, 'domingo');
  assert.equal(fueraDeHorario(Date.parse('2026-11-11T00:30:00Z')), true, 'martes 21:30 en Chile');

  const { tokens, ids } = await prepararEscenario();
  const revelar = () => API.soporte.revelarDatosContacto(tokens.soporte, ids.clienteA, { ticket: 'TCK-6001', motivo: 'Consulta por un despacho atrasado' });
  mock.timers.enable({ apis: ['Date'], now: new Date('2026-11-10T15:00:00Z') });
  try {
    ok(await revelar());
    assert.equal((await alertasDe(tokens, 'ACCESO_FUERA_DE_HORARIO')).length, 0);
    mock.timers.setTime(Date.parse('2026-11-10T06:30:00Z'));
    ok(await revelar());
  } finally {
    mock.timers.reset();
  }
  const [a] = await alertasDe(tokens, 'ACCESO_FUERA_DE_HORARIO');
  assert.equal(a.sujeto, ids.soporte);
  assert.match(a.detalle, /clientes:pii:revelar/);
});

test('5. Severidad mínima: el análisis no puede dejar un incidente por debajo de los criterios del plan', async () => {
  assert.equal(severidadMinima(['FINANCIEROS'], 1), 'CRITICA');
  assert.equal(severidadMinima(['DIRECCION'], 1), 'ALTA');
  assert.equal(severidadMinima(['CONTACTO'], 1), 'MEDIA');
  assert.equal(severidadMinima(['CONTACTO'], 150), 'ALTA');
  assert.equal(severidadMinima([], 0), 'BAJA');
  const { tokens } = await prepararEscenario();
  const inc = ok(await API.seguridad.abrirIncidente(tokens.seguridad, { titulo: 'Uso de tarjeta guardada', severidad: 'BAJA' }));
  const r = ok(await API.seguridad.analizar(tokens.seguridad, inc.id, { confirmado: true, tiposDatos: ['FINANCIEROS'], titularesAfectados: 1, severidad: 'MEDIA' }));
  assert.equal(r.severidad, 'CRITICA');
  const alta = ok(await API.seguridad.abrirIncidente(tokens.seguridad, { titulo: 'Exposición de contacto', severidad: 'ALTA' }));
  assert.equal(ok(await API.seguridad.analizar(tokens.seguridad, alta.id, { confirmado: true, tiposDatos: ['CONTACTO'], titularesAfectados: 2 })).severidad, 'ALTA', 'se puede subir, no bajar');
});

// ---------------------------------------------------------------- 5 y 6. Plan de respuesta y simulacro
test('5-6. Simulacro: la auditoría reconstruye exactamente lo que hizo el atacante y el plan se ejecuta completo', async () => {
  const s = await ejecutarSimulacro();
  for (const c of compararConVerdad(s)) assert.ok(c.ok, `${c.control}: ${c.detalle}`);

  const { respuesta } = s;
  assert.deepEqual(respuesta.alertas.map(a => a.regla).sort(), ['RELLENO_CREDENCIALES', 'TOMA_DE_CUENTA']);
  assert.equal(respuesta.purgaDuranteIncidente.purgados, 0);
  assert.ok(respuesta.sesionAtacanteRevocada);
  assert.equal(respuesta.pedidoCancelado.estado, 'CANCELADO');
  assert.equal(respuesta.evaluacion.notificarAgencia, true);
  assert.equal(respuesta.evaluacion.notificarTitulares, true, 'datos financieros: se comunica a la titular');
  assert.equal(respuesta.detalle.severidad, 'CRITICA', 'datos financieros: severidad crítica según los criterios del plan');
  assert.ok(respuesta.detalle.acciones.some(a => /elevada desde ALTA/.test(a.detalle ?? '')), 'el ajuste queda en la bitácora');
  const medidas = respuesta.notificacion.borrador.medidas_adoptadas.join(' ');
  for (const m of ['sesiones', 'pedido no autorizado', 'contraseña']) assert.match(medidas, new RegExp(m), `medida "${m}" en la notificación`);
  for (const campo of ['descripcion', 'fecha_deteccion', 'periodo', 'datos_afectados', 'posibles_consecuencias', 'medidas_adoptadas', 'recomendaciones', 'contacto']) {
    assert.ok(respuesta.notificacion.borrador[campo]?.length, campo);
  }
  assert.equal(respuesta.cierre.estado, 'CERRADO');
  const fases = new Set(respuesta.detalle.acciones.map(a => a.fase));
  for (const f of ['DETECCION', 'ANALISIS', 'CONTENCION', 'ERRADICACION', 'RECUPERACION', 'NOTIFICACION', 'CIERRE']) assert.ok(fases.has(f), f);
});
