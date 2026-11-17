import test from 'node:test';
import assert from 'node:assert/strict';
import { API } from '../src/api.js';
import { DB, ROLES_BD } from '../src/db/repository.js';
import { anclarAuditoria } from '../src/services/auditService.js';
import { ultimoCodigoPara } from '../src/infra/correo.js';
import { prepararEscenario, ok, ejercerDerecho, PASSWORD_PRUEBA } from '../src/dev/escenario.js';

async function flujoCompleto() {
  const esc = await prepararEscenario();
  const { tokens, ids } = esc;
  await API.auth.iniciarSesion({ email: 'bruno.prueba@ejemplo.test', password: 'Clave-Incorrecta-1' });
  ok(await API.consentimiento.revocar(tokens.clienteA, ids.clienteA, { finalidad: 'MARKETING_EMAIL' }));
  ok(await ejercerDerecho(tokens.clienteA, ids.clienteA, { tipo: 'RECTIFICACION', cambios: { telefono: '+56 9 7777 8888' } }));
  ok(await ejercerDerecho(tokens.clienteA, ids.clienteA, { tipo: 'PORTABILIDAD' }, { emailCodigo: 'ana.prueba@ejemplo.test' }));
  ok(await API.soporte.revelarDatosContacto(tokens.soporte, ids.clienteA, { ticket: 'TCK-2001', motivo: 'Cliente reporta pedido no recibido' }));
  await API.cliente.verPerfil(tokens.clienteB, ids.clienteA);
  ok(await ejercerDerecho(tokens.clienteB, ids.clienteB, { tipo: 'SUPRESION' }, { emailCodigo: 'bruno.prueba@ejemplo.test' }));
  return esc;
}

test('Se generan eventos para las operaciones relevantes, con todos sus atributos', async () => {
  await flujoCompleto();
  const log = DB.simularAccesoFisico().audit_log;
  const categorias = new Set(log.map(a => a.categoria));
  for (const c of ['AUTENTICACION', 'CONSENTIMIENTO', 'MODIFICACION', 'EXPORTACION', 'SUPRESION', 'ACCESO_SENSIBLE', 'ADMINISTRACION', 'CONTROL_ACCESO']) {
    assert.ok(categorias.has(c), `falta la categoría ${c}`);
  }
  for (const a of log) {
    for (const campo of ['secuencia', 'id', 'created_at', 'actor_id', 'actor_rol', 'accion', 'categoria', 'resultado', 'hash_previo', 'hash']) {
      assert.ok(a[campo] !== undefined && a[campo] !== null, `${campo} en ${a.accion}`);
    }
  }
  assert.ok(log.some(a => a.accion === 'derechos:portabilidad:ejecutada'));
  assert.ok(log.some(a => a.accion === 'auth:login' && a.resultado === 'FALLIDO' && a.actor_id.startsWith('cuenta:')));
});

test('No se registran contraseñas, códigos, tokens, llaves ni datos personales', async () => {
  const { ids } = await flujoCompleto();
  const texto = JSON.stringify(DB.simularAccesoFisico().audit_log);
  for (const prohibido of [PASSWORD_PRUEBA, 'Clave-Incorrecta-1', '@ejemplo.test', 'Ana Prueba', 'Bruno', 'Calle Ficticia', '77778888', 'tok_norti', '$2a$']) {
    assert.equal(texto.includes(prohibido), false, `"${prohibido}" no debe estar en la auditoría`);
  }
  assert.doesNotMatch(texto, /codigo=\d{6}/);
  assert.ok(texto.includes(ids.clienteA), 'se usan identificadores internos');
});

test('Solo ADMINISTRADOR, OFICIAL_PRIVACIDAD y SEGURIDAD consultan; la aplicación no puede leer, modificar ni borrar', async () => {
  const { tokens } = await prepararEscenario();
  for (const rol of ['admin', 'privacidad', 'seguridad']) assert.equal((await API.auditoria.consultar(tokens[rol], { categoria: 'ADMINISTRACION' })).ok, true, rol);
  for (const rol of ['soporte', 'analista', 'marketing', 'clienteA']) assert.equal((await API.auditoria.consultar(tokens[rol])).error.codigo, 'ACCESO_DENEGADO', rol);

  const app = DB.conectar(ROLES_BD.SVC_APP);
  const auditor = DB.conectar(ROLES_BD.ROL_AUDITOR);
  assert.throws(() => app.seleccionar('audit_log'), { code: 'BD_PERMISO_DENEGADO' });
  assert.throws(() => app.actualizar('audit_log', 1, { resultado: 'EXITO' }), { code: 'BD_PERMISO_DENEGADO' });
  assert.throws(() => app.eliminar('audit_log', 1), { code: 'BD_PERMISO_DENEGADO' });
  assert.throws(() => auditor.actualizar('audit_log', 1, { resultado: 'EXITO' }), { code: 'BD_PERMISO_DENEGADO' });
  assert.throws(() => DB.conectar(ROLES_BD.SVC_RETENCION).seleccionar('audit_log'), { code: 'BD_PERMISO_DENEGADO' });

  const consulta = ok(await API.auditoria.consultar(tokens.admin, { accion: 'auditoria:consulta' }));
  assert.ok(consulta.length >= 1, 'cada consulta queda auditada');
});

test('La cadena de sellos detecta modificación, eliminación y truncamiento, y genera una alerta crítica', async () => {
  const { tokens } = await flujoCompleto();
  assert.equal(ok(await API.auditoria.verificar(tokens.seguridad)).integra, true);

  DB.manipularFilaDirecto('audit_log', 3, { resultado: 'PERMITIDO' });
  let r = ok(await API.auditoria.verificar(tokens.seguridad));
  assert.equal(r.integra, false);
  assert.ok(r.problemas.some(p => p.secuencia === 3 && /modificado/.test(p.problema)));
  assert.ok(ok(await API.seguridad.alertas(tokens.seguridad)).some(a => a.regla === 'INTEGRIDAD_COMPROMETIDA' && a.severidad === 'CRITICA'));

  const esc = await flujoCompleto();
  DB.eliminarFilaDirecto('audit_log', 5);
  r = ok(await API.auditoria.verificar(esc.tokens.seguridad));
  assert.ok(r.problemas.some(p => /Falta el registro 5/.test(p.problema)));

  const esc2 = await flujoCompleto();
  const ancla = anclarAuditoria();
  DB.eliminarFilaDirecto('audit_log', ancla.secuencia);
  DB.eliminarFilaDirecto('audit_log', ancla.secuencia - 1);
  r = ok(await API.auditoria.verificar(esc2.tokens.seguridad));
  assert.ok(r.problemas.some(p => /truncamiento/.test(p.problema)));
});

test('Retención: la purga borra solo el tramo vencido, deja constancia y la cadena sigue verificable', async () => {
  const { tokens } = await flujoCompleto();
  const antes = DB.simularAccesoFisico().audit_log.length;
  assert.equal((await API.auditoria.purgarVencidos(tokens.admin)).error.codigo, 'ACCESO_DENEGADO');
  assert.equal(ok(await API.auditoria.purgarVencidos(tokens.privacidad)).purgados, 0, 'nada tiene más de 24 meses');

  const en25meses = new Date(Date.now() + 760 * 86_400_000).toISOString();
  const r = ok(await API.auditoria.purgarVencidos(tokens.privacidad, en25meses));
  assert.ok(r.purgados > 0 && r.purgados < antes + 5);
  const bd = DB.simularAccesoFisico();
  assert.equal(bd.auditoria_purgas.length, 1);
  assert.ok(bd.audit_log.some(a => a.accion === 'auditoria:purga'));
  assert.equal(ok(await API.auditoria.verificar(tokens.seguridad)).integra, true);
});
