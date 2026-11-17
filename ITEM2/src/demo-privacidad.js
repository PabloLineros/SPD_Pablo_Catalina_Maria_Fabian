import { API } from './api.js';
import { DB, ROLES_BD } from './db/repository.js';
import { ultimoCodigoPara, bandejaDe } from './infra/correo.js';
import { prepararEscenario, ok, PASSWORD_PRUEBA, TARJETA_VISA } from './dev/escenario.js';

/**
 * Demostración: consentimiento, ejercicio de derechos, auditoría y respuesta a incidentes.
 * Todos los datos son SINTÉTICOS (src/dev/escenario.js). La salida sirve como evidencia.
 */

const C = { B: '\x1b[1m', R: '\x1b[0m', CY: '\x1b[36m', G: '\x1b[32m', Y: '\x1b[33m', RD: '\x1b[31m', D: '\x1b[2m' };
const titulo = (t) => console.log(`\n${C.CY}${C.B}${'═'.repeat(80)}\n ${t}\n${'═'.repeat(80)}${C.R}`);
const sub = (t) => console.log(`\n${C.Y}${C.B}▶ ${t}${C.R}`);
const json = (o) => console.log(C.D + JSON.stringify(o, null, 2) + C.R);
const hora = (iso) => (iso ? iso.replace('T', ' ').slice(0, 19) : '—');

function resultado(etiqueta, r) {
  if (r.ok) console.log(`  ${C.G}✔ PERMITIDO${C.R}  ${etiqueta}`);
  else console.log(`  ${C.RD}⛔ ${r.error.codigo.padEnd(24)}${C.R} ${etiqueta} ${C.D}— ${r.error.mensaje}${C.R}`);
  return r;
}

const EMAIL_ANA = 'ana.prueba@ejemplo.test';

async function main() {
  console.log(`${C.B}NortiShop — Consentimiento, derechos, auditoría e incidentes (datos sintéticos)${C.R}`);
  console.log('Integrantes: Catalina Toledo | María Gerónimo | Pablo Lineros | Fabián Salinas');
  const { tokens, ids } = await prepararEscenario();
  const A = ids.clienteA;
  const estadoTabla = async () => console.table(ok(await API.consentimiento.estado(tokens.clienteA, A)).requierenConsentimiento
    .map(c => ({ finalidad: c.finalidad, estado: c.estado, version_vigente: c.version_vigente, version_aceptada: c.version_aceptada, otorgado: hora(c.otorgado_el), revocado: hora(c.revocado_el) })));

  // ---------------------------------------------------------------------------
  titulo('1. Módulo de consentimiento');
  sub('Estado por finalidad (Ana aceptó las tres en el registro, cada una por separado)');
  await estadoTabla();

  sub('Ana revoca MARKETING_EMAIL: efecto inmediato y solo sobre esa finalidad');
  console.log(`  Suscriptores exportables antes: ${ok(await API.marketing.exportarSuscriptores(tokens.marketing)).length}`);
  json(ok(await API.consentimiento.revocar(tokens.clienteA, A, { finalidad: 'MARKETING_EMAIL' })));
  console.log(`  Suscriptores exportables después: ${ok(await API.marketing.exportarSuscriptores(tokens.marketing)).length}`);
  await estadoTabla();

  sub('El Oficial de Privacidad publica una nueva versión del texto de ANALITICA_COMPRAS');
  resultado('ADMINISTRADOR intenta publicar un texto', await API.consentimiento.publicarVersion(tokens.admin, { finalidad: 'ANALITICA_COMPRAS', version: '2.0', texto: 'x'.repeat(50) }));
  json(ok(await API.consentimiento.publicarVersion(tokens.privacidad, {
    finalidad: 'ANALITICA_COMPRAS', version: '2.0',
    texto: 'Autorizo a NortiShop a incluir mi historial de compras, seudonimizado y generalizado, en análisis de negocio y en recomendaciones de productos.'
  })));
  await estadoTabla();
  resultado('Ana intenta aceptar con la versión antigua (1.0)', await API.consentimiento.otorgar(tokens.clienteA, A, { finalidad: 'ANALITICA_COMPRAS', version: '1.0' }));
  resultado('Ana acepta la versión vigente (2.0)', await API.consentimiento.otorgar(tokens.clienteA, A, { finalidad: 'ANALITICA_COMPRAS', version: '2.0' }));

  sub('Historial de consentimientos de Ana (solo inserción, sin datos personales)');
  console.table(ok(await API.consentimiento.historial(tokens.clienteA, A)).map(h => ({ ...h, ocurrido_el: hora(h.ocurrido_el) })));

  sub('Menores de edad: NortiShop no ofrece cuentas a menores');
  resultado('Registro sin declarar mayoría de edad', await API.auth.registrar({ nombre: 'Persona Menor', email: 'menor@ejemplo.test', password: PASSWORD_PRUEBA, direccionDespacho: 'Calle Ficticia 1', comuna: 'Arica', declaraMayorDeEdad: false }));
  resultado('Registro enviando fecha de nacimiento', await API.auth.registrar({ nombre: 'Persona Menor', email: 'menor@ejemplo.test', password: PASSWORD_PRUEBA, direccionDespacho: 'Calle Ficticia 1', comuna: 'Arica', declaraMayorDeEdad: true, fecha_nacimiento: '2012-05-01' }));

  // ---------------------------------------------------------------------------
  titulo('2. Ejercicio de derechos (actividad PR-05: puntos 1 a 7)');
  ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[0], cantidad: 1 }] }));
  ok(await API.cliente.crearPedido(tokens.clienteB, {
    items: [{ productoId: ids.productos[1], cantidad: 1 }], tipoDocumento: 'FACTURA', tarjeta: TARJETA_VISA,
    facturacion: { rut: '76.086.428-5', razonSocial: 'Empresa Ficticia SpA', direccion: 'Oficina Inventada 1' }
  }));
  ok(await API.invitado.crearPedido({ nombre: 'Invitada Prueba', email: 'invitada@ejemplo.test', direccionDespacho: 'Calle Invitada 77', comuna: 'Arica', items: [{ productoId: ids.productos[1], cantidad: 1 }], tarjeta: TARJETA_VISA }));

  sub('1-2. Canal con folio + verificación: un solicitante NO verificado no obtiene nada');
  const s = ok(await API.derechos.solicitar(tokens.clienteA, A, { tipo: 'ACCESO' }));
  json({ folio: s.folio, canal: s.canal, presentada_por: s.presentada_por, estado: s.estado, recibida_el: s.recibida_el, plazo_vence_el: s.plazo_vence_el, verificacion: s.verificacion });
  console.log(`  Correo recibido (simulado): "${bandejaDe(EMAIL_ANA).at(-1).cuerpo}"`);
  resultado('Confirmar con contraseña y código incorrectos (no verificado)', await API.derechos.confirmar(tokens.clienteA, A, s.id, { password: 'clave-equivocada-1', codigo: '000000' }));
  resultado('Otro cliente intenta confirmar la solicitud de Ana', await API.derechos.confirmar(tokens.clienteB, A, s.id, { password: PASSWORD_PRUEBA }));

  sub('3. Acceso: enlace de descarga temporal y de un solo uso; datos de todas las fuentes, con origen y finalidad');
  const acceso = ok(await API.derechos.confirmar(tokens.clienteA, A, s.id, { password: PASSWORD_PRUEBA, codigo: ultimoCodigoPara(EMAIL_ANA) }));
  json({ solicitud: { folio: acceso.solicitud.folio, estado: acceso.solicitud.estado, resultado: acceso.solicitud.resultado, fundamento: acceso.solicitud.fundamento }, descarga: { ...acceso.descarga, token: `${acceso.descarga.token.slice(0, 8)}…` } });
  const copia = ok(await API.derechos.descargar(tokens.clienteA, acceso.descarga.token));
  resultado('Segunda descarga con el mismo enlace', await API.derechos.descargar(tokens.clienteA, acceso.descarga.token));
  console.log('  Secciones de la copia:', Object.keys(copia).join(', '));
  console.table(copia.informacion_del_tratamiento.donde_se_encontraron_sus_datos);
  json({ origen_y_finalidad: copia.origen_y_finalidad, destinatarios: copia.informacion_del_tratamiento.destinatarios });

  sub('4. Rectificación: valor anterior y nuevo (cifrados), quién y cuándo; aviso a terceros');
  resultado('Solicitar teléfono con formato inválido', await API.derechos.solicitar(tokens.clienteA, A, { tipo: 'RECTIFICACION', cambios: { telefono: '123' } }));
  const rect = ok(await API.derechos.solicitar(tokens.clienteA, A, { tipo: 'RECTIFICACION', cambios: { direccionDespacho: 'Nueva Calle Ficticia 777' } }));
  json(ok(await API.derechos.confirmar(tokens.clienteA, A, rect.id, { password: PASSWORD_PRUEBA })).solicitud.fundamento);
  const r1 = DB.simularAccesoFisico().rectificaciones[0];
  console.log('  Fila guardada en rectificaciones (lo que ve un atacante con acceso a la BD):');
  json({ campo: r1.campo, valor_anterior_cifrado: `${r1.valor_anterior_cifrado.slice(0, 40)}…`, valor_nuevo_cifrado: `${r1.valor_nuevo_cifrado.slice(0, 40)}…`, actor_id: r1.actor_id, actor_rol: r1.actor_rol, created_at: r1.created_at });
  const acceso2 = ok(await API.derechos.solicitar(tokens.clienteA, A, { tipo: 'ACCESO' }));
  const conf2 = ok(await API.derechos.confirmar(tokens.clienteA, A, acceso2.id, { password: PASSWORD_PRUEBA, codigo: ultimoCodigoPara(EMAIL_ANA) }));
  console.log('  Lo que el titular ve en su copia de acceso:');
  json(ok(await API.derechos.descargar(tokens.clienteA, conf2.descarga.token)).rectificaciones);

  sub('5. Supresión: qué se elimina, qué se bloquea por ley y hasta cuándo, y a quién se propaga');
  const supA = ok(await API.derechos.solicitar(tokens.clienteA, A, { tipo: 'SUPRESION' }));
  json(ok(await API.derechos.confirmar(tokens.clienteA, A, supA.id, { password: PASSWORD_PRUEBA, codigo: ultimoCodigoPara(EMAIL_ANA) })).solicitud.fundamento);
  const refB = ok(await API.logistica.pendientes(tokens.logistica)).find(e => e.comuna === 'Calama').ref_envio;
  ok(await API.logistica.actualizarEstado(tokens.logistica, refB, 'EN_RUTA'));
  ok(await API.logistica.actualizarEstado(tokens.logistica, refB, 'ENTREGADO'));
  // Bruno guarda su tarjeta y se suscribe: la supresión deberá propagarse a la pasarela y a la plataforma de correo.
  ok(await API.consentimiento.otorgar(tokens.clienteB, ids.clienteB, { finalidad: 'GUARDAR_MEDIO_PAGO', version: '1.0', tarjeta: TARJETA_VISA }));
  ok(await API.consentimiento.otorgar(tokens.clienteB, ids.clienteB, { finalidad: 'MARKETING_EMAIL', version: '2.0' }));
  const supB = ok(await API.derechos.solicitar(tokens.clienteB, ids.clienteB, { tipo: 'SUPRESION' }));
  const rB = ok(await API.derechos.confirmar(tokens.clienteB, ids.clienteB, supB.id, { password: PASSWORD_PRUEBA, codigo: ultimoCodigoPara('bruno.prueba@ejemplo.test') })).solicitud;
  json({ folio: rB.folio, resultado: rB.resultado, fundamento: rB.fundamento });
  const bd = DB.simularAccesoFisico();
  console.table(bd.comunicaciones_terceros.map(({ tercero, tipo, referencia }) => ({ tercero, tipo, referencia: referencia.slice(0, 50) })));
  console.log(`  Factura de Bruno: bloqueado=${bd.facturacion[0].bloqueado}, bloqueado_hasta=${bd.facturacion[0].bloqueado_hasta.slice(0, 10)}`);
  const en7 = new Date(Date.now() + 7 * 366 * 86_400_000).toISOString();
  console.log(`  Job de eliminación al cumplirse el plazo legal (simulando +7 años): ${JSON.stringify(ok(await API.privacidad.eliminarBloqueadosVencidos(tokens.privacidad, en7)))}`);

  sub('2. Canal sin cuenta: la invitada verifica su correo y recibe solo sus datos');
  const sc = ok(await API.derechos.solicitarSinCuenta({ email: 'invitada@ejemplo.test', tipo: 'ACCESO' }));
  console.log(`  ${sc.folio}: ${sc.mensaje}`);
  resultado('Confirmar con un código incorrecto', await API.derechos.confirmarSinCuenta({ solicitudId: sc.id, codigo: '000000' }));
  const rsc = ok(await API.derechos.confirmarSinCuenta({ solicitudId: sc.id, codigo: ultimoCodigoPara('invitada@ejemplo.test') }));
  console.log(`  ${rsc.solicitud.resultado}: ${rsc.solicitud.fundamento}`);
  json(ok(await API.derechos.descargarSinCuenta(rsc.descarga.token)).pedidos_como_invitado);

  // Se recrea un escenario limpio para oposición y bloqueo.
  await prepararEscenario().then(({ tokens: t, ids: i }) => { Object.assign(tokens, t); Object.assign(ids, i); });
  const A2 = ids.clienteA;
  const entregar = async () => {
    const ref = ok(await API.logistica.pendientes(tokens.logistica))[0].ref_envio;
    ok(await API.logistica.actualizarEstado(tokens.logistica, ref, 'EN_RUTA'));
    ok(await API.logistica.actualizarEstado(tokens.logistica, ref, 'ENTREGADO'));
  };
  const encuestas = () => bandejaDe(EMAIL_ANA).filter(m => /cómo fue tu compra/.test(m.asunto)).length;

  sub('6a. Oposición: Ana se opone a la encuesta de satisfacción (base: interés legítimo)');
  ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[0], cantidad: 1 }] }));
  const op = ok(await API.derechos.solicitar(tokens.clienteA, A2, { tipo: 'OPOSICION', tratamiento: 'ENCUESTAS_SATISFACCION' }));
  resultado('Confirmar con contraseña incorrecta', await API.derechos.confirmar(tokens.clienteA, A2, op.id, { password: 'clave-equivocada-1' }));
  json(ok(await API.derechos.confirmar(tokens.clienteA, A2, op.id, { password: PASSWORD_PRUEBA })).solicitud.fundamento);
  await entregar();
  console.log(`  Pedido entregado → encuestas recibidas por Ana: ${encuestas()} (el sistema consultó la oposición antes de enviar)`);

  sub('6b. Bloqueo: Ana discute la exactitud de sus datos; se conservan pero no se usan');
  const bl = ok(await API.derechos.solicitar(tokens.clienteA, A2, { tipo: 'BLOQUEO', motivo: 'EXACTITUD_EN_DISPUTA' }));
  json(ok(await API.derechos.confirmar(tokens.clienteA, A2, bl.id, { password: PASSWORD_PRUEBA })).solicitud.fundamento);
  console.log(`  Suscriptores exportables a marketing: ${ok(await API.marketing.exportarSuscriptores(tokens.marketing)).length} (Ana tenía consentimiento, pero está bloqueada)`);
  ok(await API.derechos.confirmar(tokens.clienteA, A2, ok(await API.derechos.solicitar(tokens.clienteA, A2, { tipo: 'RECTIFICACION', cambios: { nombre: 'Ana Corregida Uno' } })).id, { password: PASSWORD_PRUEBA }));
  console.log(`  Tras rectificar: bloqueo=${JSON.stringify(ok(await API.derechos.misRestricciones(tokens.clienteA, A2)).bloqueo)}; exportables=${ok(await API.marketing.exportarSuscriptores(tokens.marketing)).length}`);

  sub('Plazos: aviso al equipo de privacidad cuando una solicitud está por vencer');
  ok(await API.derechos.solicitar(tokens.clienteA, A2, { tipo: 'ACCESO' }));
  console.log('  Revisión simulando 27 días después:');
  console.table(ok(await API.derechos.revisarPlazos(tokens.privacidad, new Date(Date.now() + 27 * 86_400_000).toISOString())));
  resultado('ADMINISTRADOR intenta ver las solicitudes', await API.derechos.gestion(tokens.admin));
  console.table(ok(await API.derechos.gestion(tokens.privacidad)).map(x => ({ folio: x.folio, tipo: x.tipo, estado: x.estado, resultado: x.resultado, recibida: hora(x.recibida_el), cerrada: hora(x.cerrada_el), dias_restantes: x.dias_restantes })));

  // ---------------------------------------------------------------------------
  titulo('3. Registro de auditoría');
  sub('Últimos eventos (identificadores internos, sin datos personales, encadenados con HMAC)');
  console.table(ok(await API.auditoria.consultar(tokens.seguridad, { limite: 12 })).map(a => ({
    sec: a.secuencia, categoria: a.categoria, accion: a.accion, rol: a.actor_rol, recurso: (a.recurso ?? '').slice(0, 30), resultado: a.resultado, motivo: (a.motivo ?? '').slice(0, 34), hash: a.hash.slice(0, 10)
  })));
  resultado('CLIENTE intenta consultar la auditoría', await API.auditoria.consultar(tokens.clienteA));
  try {
    DB.conectar(ROLES_BD.SVC_APP).eliminar('audit_log', 1);
  } catch (e) {
    console.log(`  ${C.RD}⛔ ${e.code}${C.R} La aplicación intenta borrar un registro: ${e.message}`);
  }
  sub('Verificación de la cadena: íntegra → un atacante modifica el registro 4 → detectado');
  json(ok(await API.auditoria.verificar(tokens.seguridad)));
  DB.manipularFilaDirecto('audit_log', 4, { resultado: 'DENEGADO' });
  json(ok(await API.auditoria.verificar(tokens.seguridad)));

  // ---------------------------------------------------------------------------
  titulo('4. Detección y respuesta a incidentes');
  sub('Detección: un agente de soporte revela datos completos 5 veces en una hora');
  await prepararEscenario().then(async ({ tokens: t, ids: i }) => {
    Object.assign(tokens, t);
    Object.assign(ids, i);
  });
  for (let k = 0; k < 5; k++) ok(await API.soporte.revelarDatosContacto(tokens.soporte, ids.clienteA, { ticket: `TCK-${5000 + k}`, motivo: 'Consulta sobre un pedido extraviado' }));
  for (let k = 0; k < 5; k++) await API.auth.iniciarSesion({ email: EMAIL_ANA, password: `incorrecta-${k}-xxxx` });
  console.table(ok(await API.seguridad.alertas(tokens.seguridad)).map(a => ({ regla: a.regla, nivel: a.nivel, severidad: a.severidad, sujeto: a.sujeto.slice(0, 20), estado: a.estado })));

  const alerta = ok(await API.seguridad.alertas(tokens.seguridad)).find(a => a.regla === 'REVELACIONES_PII_ANOMALAS');
  sub('Análisis → evidencia → contención');
  const inc = ok(await API.seguridad.abrirIncidente(tokens.seguridad, { titulo: 'Revelación masiva de datos por cuenta de soporte', severidad: 'ALTA', alertas: [alerta.id] }));
  ok(await API.seguridad.analizar(tokens.seguridad, inc.id, { confirmado: true, ocurridoDesde: new Date(Date.now() - 3_600_000).toISOString(), tiposDatos: ['IDENTIFICACION', 'CONTACTO', 'DIRECCION'], titularesAfectados: 1 }));
  resultado('Contener sin preservar evidencia', await API.seguridad.contener(tokens.seguridad, inc.id, { accion: 'SUSPENDER_ROL', objetivo: 'SOPORTE' }));
  json(ok(await API.seguridad.preservarEvidencia(tokens.seguridad, inc.id)));
  resultado('Suspender el rol SOPORTE', await API.seguridad.contener(tokens.seguridad, inc.id, { accion: 'SUSPENDER_ROL', objetivo: 'SOPORTE' }));
  resultado('Deshabilitar la cuenta de soporte comprometida', await API.seguridad.contener(tokens.seguridad, inc.id, { accion: 'DESHABILITAR_CUENTA_PERSONAL', objetivo: ids.soporte }));
  resultado('Soporte intenta seguir buscando clientes', await API.soporte.buscarCliente(tokens.soporte, EMAIL_ANA));

  sub('Erradicación → recuperación (con comprobaciones) → notificación → cierre');
  ok(await API.seguridad.erradicar(tokens.seguridad, inc.id, { causaRaiz: 'Credenciales de soporte reutilizadas en un servicio filtrado', medidas: 'Cambio de credenciales y MFA obligatorio para soporte' }));
  resultado('SEGURIDAD intenta restablecer la operación', await API.seguridad.recuperar(tokens.seguridad, inc.id));
  resultado('ADMINISTRADOR intenta restablecer con una alerta crítica abierta', await (async () => {
    DB.manipularFilaDirecto('loyalty_accounts', ids.clienteB, { saldo_puntos: 1 });
    await API.cliente.saldoPuntos(tokens.clienteB, ids.clienteB);
    DB.manipularFilaDirecto('loyalty_accounts', ids.clienteB, { saldo_puntos: 500 });
    return API.seguridad.recuperar(tokens.admin, inc.id);
  })());
  for (const a of ok(await API.seguridad.alertas(tokens.seguridad, { estado: 'ABIERTA' }))) {
    ok(await API.seguridad.descartarAlerta(tokens.seguridad, a.id, { motivo: 'Revisada y documentada en el incidente' }));
  }
  json(ok(await API.seguridad.recuperar(tokens.admin, inc.id)).comprobaciones);
  json(ok(await API.seguridad.evaluarNotificacion(tokens.privacidad, inc.id)));
  json(ok(await API.seguridad.autorizarNotificacion(tokens.privacidad, inc.id, { agencia: true, titulares: true, justificacion: 'Se informa a la Agencia y al titular por exposición de su dirección' })).borrador);
  ok(await API.seguridad.cerrar(tokens.seguridad, inc.id, { lecciones: 'El umbral de revelaciones detectó el abuso en menos de una hora; faltaba MFA en soporte.', medidasPreventivas: 'MFA obligatorio y revisión trimestral de accesos del personal' }));
  console.table(ok(await API.seguridad.detalle(tokens.admin, inc.id)).acciones.map(a => ({ fase: a.fase, accion: a.accion, cuando: hora(a.created_at), detalle: (a.detalle ?? '').slice(0, 50) })));

  // ---------------------------------------------------------------------------
  titulo('5. Los controles no se pueden eludir');
  resultado('Cliente llama a la contención directamente', await API.seguridad.contener(tokens.clienteA, inc.id, { accion: 'SUSPENDER_EXPORTACIONES' }));
  resultado('Cliente revoca el consentimiento de otro cliente', await API.consentimiento.revocar(tokens.clienteA, ids.clienteB, { finalidad: 'MARKETING_EMAIL' }));
  resultado('Llamada sin sesión a la exportación de derechos', await API.derechos.solicitar(undefined, ids.clienteA, { tipo: 'PORTABILIDAD' }));
  for (const [rol, accion] of [[ROLES_BD.SVC_APP, () => DB.conectar(ROLES_BD.SVC_APP).seleccionar('audit_log')], [ROLES_BD.ROL_ANALISTA, () => DB.conectar(ROLES_BD.ROL_ANALISTA).seleccionar('consentimientos')]]) {
    try { accion(); } catch (e) { console.log(`  ${C.RD}⛔ ${e.code}${C.R} Acceso directo a la BD con ${rol}: ${e.message}`); }
  }
  console.log(`\n${C.G}${C.B}Demostración finalizada.${C.R} Ejecute ${C.B}npm test${C.R} para la batería completa o ${C.B}npm run servidor${C.R} para abrir el Centro de privacidad.\n`);
}

main().catch((err) => {
  console.error('Error fatal durante la demostración:', err.message);
  process.exit(1);
});
