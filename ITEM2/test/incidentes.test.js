import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { API } from '../src/api.js';
import { DB } from '../src/db/repository.js';
import { prepararEscenario, ok, PASSWORD_PRUEBA } from '../src/dev/escenario.js';

const alertasDe = async (tokens, regla) => ok(await API.seguridad.alertas(tokens.seguridad)).filter(a => a.regla === regla);

test('Detección: fuerza bruta (alerta) y relleno de credenciales (evento sospechoso)', async () => {
  const { tokens } = await prepararEscenario();
  for (let i = 0; i < 5; i++) await API.auth.iniciarSesion({ email: 'ana.prueba@ejemplo.test', password: `mala-${i}-xxxxxxx` });
  const [fb] = await alertasDe(tokens, 'FUERZA_BRUTA');
  assert.equal(fb.nivel, 'ALERTA');
  assert.match(fb.sujeto, /^cuenta:[0-9a-f]{12}$/, 'la cuenta se identifica por prefijo de índice ciego');

  for (let i = 0; i < 10; i++) await API.auth.iniciarSesion({ email: `x${i}@ejemplo.test`, password: 'no-importa-1234' });
  const [rc] = await alertasDe(tokens, 'RELLENO_CREDENCIALES');
  assert.equal(rc.nivel, 'EVENTO_SOSPECHOSO');
  assert.equal(rc.severidad, 'ALTA');
  assert.doesNotMatch(JSON.stringify(DB.simularAccesoFisico().alertas), /@ejemplo\.test/);
});

test('Detección: revelaciones de PII, denegaciones repetidas y manipulación de puntos', async () => {
  const { tokens, ids } = await prepararEscenario();
  for (let i = 0; i < 5; i++) ok(await API.soporte.revelarDatosContacto(tokens.soporte, ids.clienteA, { ticket: `TCK-${3000 + i}`, motivo: 'Consulta sobre un pedido extraviado' }));
  assert.equal((await alertasDe(tokens, 'REVELACIONES_PII_ANOMALAS')).length, 1);

  for (let i = 0; i < 5; i++) await API.cliente.verPerfil(tokens.clienteB, ids.clienteA);
  const [den] = await alertasDe(tokens, 'DENEGACIONES_REPETIDAS');
  assert.equal(den.sujeto, ids.clienteB);

  DB.manipularFilaDirecto('loyalty_accounts', ids.clienteA, { saldo_puntos: 999999 });
  await API.cliente.saldoPuntos(tokens.clienteA, ids.clienteA);
  const [integ] = await alertasDe(tokens, 'INTEGRIDAD_COMPROMETIDA');
  assert.equal(integ.severidad, 'CRITICA');
});

test('Respuesta completa: evidencia antes de contener, contención efectiva, recuperación con comprobaciones, notificación y cierre', async () => {
  const { tokens, ids } = await prepararEscenario();
  for (let i = 0; i < 5; i++) ok(await API.soporte.revelarDatosContacto(tokens.soporte, ids.clienteA, { ticket: `TCK-${4000 + i}`, motivo: 'Consulta sobre un pedido extraviado' }));
  const [alerta] = await alertasDe(tokens, 'REVELACIONES_PII_ANOMALAS');

  // Detección y análisis
  assert.equal((await API.seguridad.abrirIncidente(tokens.soporte, { titulo: 'x', severidad: 'ALTA' })).error.codigo, 'ACCESO_DENEGADO');
  const inc = ok(await API.seguridad.abrirIncidente(tokens.seguridad, { titulo: 'Revelación masiva de datos por cuenta de soporte', severidad: 'ALTA', alertas: [alerta.id] }));
  assert.equal(DB.simularAccesoFisico().alertas.find(a => a.id === alerta.id).estado, 'ESCALADA');
  ok(await API.seguridad.analizar(tokens.seguridad, inc.id, {
    confirmado: true, ocurridoDesde: new Date(Date.now() - 3_600_000).toISOString(),
    tiposDatos: ['IDENTIFICACION', 'CONTACTO', 'DIRECCION'], titularesAfectados: 1
  }));

  // Contención: exige evidencia preservada
  assert.equal((await API.seguridad.contener(tokens.seguridad, inc.id, { accion: 'SUSPENDER_ROL', objetivo: 'SOPORTE' })).error.codigo, 'CONFLICTO');
  const ev = ok(await API.seguridad.preservarEvidencia(tokens.seguridad, inc.id));
  const guardada = DB.simularAccesoFisico().evidencias[0];
  assert.equal(crypto.createHash('sha256').update(guardada.contenido).digest('hex'), ev.sha256, 'evidencia íntegra');
  assert.ok(ev.eventos > 0 && ev.cadenaIntegra);

  ok(await API.seguridad.contener(tokens.seguridad, inc.id, { accion: 'SUSPENDER_ROL', objetivo: 'SOPORTE' }));
  assert.equal((await API.soporte.buscarCliente(tokens.soporte, 'ana.prueba@ejemplo.test')).error.codigo, 'ACCESO_DENEGADO', 'rol suspendido');
  ok(await API.seguridad.contener(tokens.seguridad, inc.id, { accion: 'DESHABILITAR_CUENTA_PERSONAL', objetivo: ids.soporte }));
  assert.equal((await API.soporte.buscarCliente(tokens.soporte, 'ana.prueba@ejemplo.test')).error.codigo, 'NO_AUTENTICADO', 'sesiones revocadas');
  ok(await API.seguridad.contener(tokens.seguridad, inc.id, { accion: 'SUSPENDER_EXPORTACIONES' }));
  assert.equal((await API.marketing.exportarSuscriptores(tokens.marketing)).error.codigo, 'ACCESO_DENEGADO');
  assert.equal((await API.seguridad.contener(tokens.seguridad, inc.id, { accion: 'SUSPENDER_ROL', objetivo: 'SEGURIDAD' })).error.codigo, 'DATO_INVALIDO');
  assert.ok(DB.simularAccesoFisico().personal.some(p => p.id === ids.soporte), 'la cuenta se deshabilita, no se borra (evidencia)');

  // Erradicación y recuperación
  ok(await API.seguridad.erradicar(tokens.seguridad, inc.id, { causaRaiz: 'Credenciales de soporte reutilizadas en un servicio filtrado', medidas: 'Cambio de credenciales y MFA obligatorio para soporte' }));
  assert.equal((await API.seguridad.recuperar(tokens.seguridad, inc.id)).error.codigo, 'ACCESO_DENEGADO', 'recupera el ADMINISTRADOR');
  DB.manipularFilaDirecto('loyalty_accounts', ids.clienteB, { saldo_puntos: 1 });
  const bloqueada = await API.seguridad.recuperar(tokens.admin, inc.id);
  assert.equal(bloqueada.error.codigo, 'CONFLICTO');
  assert.match(bloqueada.error.mensaje, /NortiPuntos/);
  DB.manipularFilaDirecto('loyalty_accounts', ids.clienteB, { saldo_puntos: 500 });
  for (const a of ok(await API.seguridad.alertas(tokens.seguridad, { estado: 'ABIERTA' }))) {
    ok(await API.seguridad.descartarAlerta(tokens.seguridad, a.id, { motivo: 'Revisada: generada por la prueba de recuperación' }));
  }
  const rec = ok(await API.seguridad.recuperar(tokens.admin, inc.id));
  assert.ok(rec.comprobaciones.every(c => c.ok));
  ok(await API.admin.crearPersonal(tokens.admin, { nombre: 'Soporte Nuevo', email: 'soporte2@nortishop.test', password: PASSWORD_PRUEBA, rol: 'SOPORTE' }));
  const { token: soporte2 } = ok(await API.auth.iniciarSesion({ email: 'soporte2@nortishop.test', password: PASSWORD_PRUEBA }));
  assert.equal((await API.soporte.buscarCliente(soporte2, 'ana.prueba@ejemplo.test')).ok, true, 'controles levantados');
  assert.equal((await API.marketing.exportarSuscriptores(tokens.marketing)).ok, true);

  // Notificación
  assert.equal((await API.seguridad.evaluarNotificacion(tokens.seguridad, inc.id)).error.codigo, 'ACCESO_DENEGADO');
  const evaluacion = ok(await API.seguridad.evaluarNotificacion(tokens.privacidad, inc.id));
  assert.equal(evaluacion.notificarAgencia, true);
  assert.equal(evaluacion.notificarTitulares, false, 'sin datos sensibles, de menores ni financieros');
  assert.equal((await API.seguridad.cerrar(tokens.seguridad, inc.id, { lecciones: 'x'.repeat(40), medidasPreventivas: 'Revisión trimestral de accesos' })).error.codigo, 'CONFLICTO', 'falta la decisión de notificación');
  const { borrador } = ok(await API.seguridad.autorizarNotificacion(tokens.privacidad, inc.id, { agencia: true, titulares: true, justificacion: 'Se comunica también al titular por exposición de su dirección' }));
  for (const campo of ['descripcion', 'fecha_deteccion', 'periodo', 'datos_afectados', 'posibles_consecuencias', 'medidas_adoptadas', 'recomendaciones', 'contacto']) {
    assert.ok(borrador[campo] && borrador[campo].length !== 0, campo);
  }

  // Cierre
  assert.equal((await API.seguridad.cerrar(tokens.seguridad, inc.id, { lecciones: 'corta', medidasPreventivas: 'x'.repeat(20) })).error.codigo, 'DATO_INVALIDO');
  const cerrado = ok(await API.seguridad.cerrar(tokens.seguridad, inc.id, {
    lecciones: 'El umbral de revelaciones detectó el abuso en menos de una hora; faltaba MFA en soporte.',
    medidasPreventivas: 'MFA obligatorio y revisión trimestral de accesos del personal'
  }));
  assert.equal(cerrado.estado, 'CERRADO');
  const fases = new Set(ok(await API.seguridad.detalle(tokens.admin, inc.id)).acciones.map(a => a.fase));
  for (const f of ['DETECCION', 'ANALISIS', 'CONTENCION', 'ERRADICACION', 'RECUPERACION', 'NOTIFICACION', 'CIERRE']) assert.ok(fases.has(f), f);
});

test('Criterios de notificación: datos financieros obligan a comunicar a los titulares', async () => {
  const { tokens } = await prepararEscenario();
  const inc = ok(await API.seguridad.abrirIncidente(tokens.seguridad, { titulo: 'Exposición de tokens de pago', severidad: 'CRITICA' }));
  ok(await API.seguridad.analizar(tokens.seguridad, inc.id, { confirmado: true, tiposDatos: ['FINANCIEROS'], titularesAfectados: 40 }));
  const e = ok(await API.seguridad.evaluarNotificacion(tokens.privacidad, inc.id));
  assert.equal(e.notificarAgencia, true);
  assert.equal(e.notificarTitulares, true);
  assert.ok(e.fundamentos.some(f => /pasarela/.test(f)));
});

test('Falso positivo: el análisis puede descartar el incidente', async () => {
  const { tokens } = await prepararEscenario();
  const inc = ok(await API.seguridad.abrirIncidente(tokens.seguridad, { titulo: 'Picos de login fallido', severidad: 'MEDIA' }));
  assert.equal(ok(await API.seguridad.analizar(tokens.seguridad, inc.id, { confirmado: false })).estado, 'DESCARTADO');
  assert.equal((await API.seguridad.preservarEvidencia(tokens.seguridad, inc.id)).error.codigo, 'CONFLICTO');
});
