import { API } from '../api.js';
import { DB } from '../db/repository.js';
import { conOrigen } from '../security/contexto.js';
import { referenciaOrigen } from '../crypto/pseudonymization.js';
import { prepararEscenario, ok, PASSWORD_PRUEBA } from './escenario.js';

/**
 * SIMULACRO DE INCIDENTE (datos sintéticos): relleno de credenciales -> toma de cuenta -> compra
 * fraudulenta con la tarjeta guardada.
 *
 * Las IPs son de documentación (RFC 5737) y solo se usan para calcular el seudónimo de origen; no
 * quedan en ningún registro. El simulacro guarda por separado la VERDAD (lo que hizo el atacante,
 * anotado por el propio guion) para comprobar después que la auditoría permite reconstruirla.
 */

export const ORIGENES = Object.freeze({
  ATACANTE: '203.0.113.45',
  CASA_ANA: '198.51.100.23',
  CASA_BRUNO: '198.51.100.77',
  OFICINA: '192.0.2.10'
});

const DIRECCION_ATACANTE = 'Bodega Falsa 999, Galpón 3';

export async function ejecutarSimulacro() {
  const esc = await prepararEscenario();
  const { tokens, ids } = esc;
  const verdad = { cuentasProbadas: [], cuentaComprometida: ids.clienteA, accionesEnLaCuenta: [], pedidoFraudulento: null };
  const ataque = (fn) => conOrigen(ORIGENES.ATACANTE, fn);

  // --- 0. Actividad legítima previa (línea base y ruido) ---
  const sesionAna = ok(await conOrigen(ORIGENES.CASA_ANA, () => API.auth.iniciarSesion({ email: 'ana.prueba@ejemplo.test', password: PASSWORD_PRUEBA })));
  ok(await conOrigen(ORIGENES.CASA_ANA, () => API.cliente.misPedidos(sesionAna.token, ids.clienteA)));
  const sesionBruno = ok(await conOrigen(ORIGENES.CASA_BRUNO, () => API.auth.iniciarSesion({ email: 'bruno.prueba@ejemplo.test', password: PASSWORD_PRUEBA })));
  ok(await conOrigen(ORIGENES.CASA_BRUNO, () => API.cliente.verPerfil(sesionBruno.token, ids.clienteB)));

  // --- 1. Relleno de credenciales: el atacante prueba una lista filtrada en otro sitio ---
  const lista = [...Array.from({ length: 9 }, (_, i) => `filtrado${i + 1}@ejemplo.test`), 'bruno.prueba@ejemplo.test', 'carla.inexistente@ejemplo.test'];
  for (const email of lista) {
    await ataque(() => API.auth.iniciarSesion({ email, password: 'Verano2024!' }));
    verdad.cuentasProbadas.push(email);
  }

  // --- 2. La contraseña de Ana estaba reutilizada: el atacante entra a su cuenta ---
  const robada = ok(await ataque(() => API.auth.iniciarSesion({ email: 'ana.prueba@ejemplo.test', password: PASSWORD_PRUEBA })));
  const t = robada.token;

  // --- 3. Dentro de la cuenta ---
  ok(await ataque(() => API.cliente.verPerfil(t, ids.clienteA)));
  verdad.accionesEnLaCuenta.push('perfil:propio:leer');
  ok(await ataque(() => API.cliente.actualizarPerfil(t, ids.clienteA, { direccionDespacho: DIRECCION_ATACANTE })));
  verdad.accionesEnLaCuenta.push('perfil:propio:editar');
  const pedido = ok(await ataque(() => API.cliente.crearPedido(t, { items: [{ productoId: ids.productos[2], cantidad: 2 }] })));
  verdad.accionesEnLaCuenta.push('pedido:crear');
  verdad.pedidoFraudulento = pedido.id;
  // Intenta llevarse una copia de todos los datos: la verificación por código al correo lo frena.
  const solicitud = ok(await ataque(() => API.derechos.solicitar(t, ids.clienteA, { tipo: 'PORTABILIDAD' })));
  verdad.accionesEnLaCuenta.push('derechos:portabilidad:recibida');
  const intento = await ataque(() => API.derechos.confirmar(t, ids.clienteA, solicitud.id, { password: PASSWORD_PRUEBA, codigo: '123456' }));
  verdad.portabilidadFrenada = !intento.ok;

  // Ruido durante el ataque: soporte atiende otro caso desde la oficina.
  ok(await conOrigen(ORIGENES.OFICINA, () => API.soporte.buscarCliente(tokens.soporte, 'bruno.prueba@ejemplo.test')));

  // =================== RESPUESTA ===================
  const respuesta = {};
  // Detección
  const alertas = ok(await API.seguridad.alertas(tokens.seguridad, { estado: 'ABIERTA' }));
  const relleno = alertas.find(a => a.regla === 'RELLENO_CREDENCIALES');
  const toma = alertas.find(a => a.regla === 'TOMA_DE_CUENTA');
  respuesta.alertas = alertas.map(({ regla, nivel, severidad, sujeto }) => ({ regla, nivel, severidad, sujeto }));

  const inc = ok(await API.seguridad.abrirIncidente(tokens.seguridad, {
    titulo: 'Toma de cuenta de cliente tras relleno de credenciales', severidad: 'ALTA', alertas: [relleno.id, toma.id]
  }));

  // Análisis: reconstrucción desde el origen señalado por la alerta de relleno
  const reconstruccion = ok(await API.auditoria.reconstruir(tokens.seguridad, {
    origenRef: relleno.sujeto, motivo: `Incidente ${inc.id}: relleno de credenciales y toma de cuenta`
  }));
  const r = reconstruccion.resumen;
  ok(await API.seguridad.analizar(tokens.seguridad, inc.id, {
    confirmado: true, ocurridoDesde: r.desde, ocurridoHasta: r.hasta,
    // No se indica severidad: el sistema la eleva a CRÍTICA porque hay datos financieros (tarjeta guardada).
    tiposDatos: r.tipos_datos, titularesAfectados: r.titulares_afectados.length
  }));

  // Retención extendida: con el incidente abierto, una purga futura no borra la evidencia
  respuesta.purgaDuranteIncidente = ok(await API.auditoria.purgarVencidos(tokens.privacidad, new Date(Date.now() + 800 * 86_400_000).toISOString()));

  // Contención (evidencia primero)
  respuesta.evidencia = ok(await API.seguridad.preservarEvidencia(tokens.seguridad, inc.id));
  ok(await API.seguridad.contener(tokens.seguridad, inc.id, { accion: 'REVOCAR_SESIONES', objetivo: ids.clienteA }));
  respuesta.sesionAtacanteRevocada = (await API.cliente.verPerfil(t, ids.clienteA)).error?.codigo === 'NO_AUTENTICADO';
  const compra = r.cambios.find(c => c.accion === 'pedido:crear');
  ok(await API.seguridad.contener(tokens.seguridad, inc.id, { accion: 'CANCELAR_PEDIDO', objetivo: compra.recurso.split(':')[1] }));
  respuesta.pedidoCancelado = DB.simularAccesoFisico().orders.find(o => o.id === compra.recurso.split(':')[1]);

  // Erradicación y recuperación
  ok(await API.seguridad.erradicar(tokens.seguridad, inc.id, {
    causaRaiz: 'Contraseña reutilizada por la titular y filtrada en otro sitio; el login no exige un segundo factor ante un origen nuevo.',
    medidas: 'Cambio de contraseña forzado para la titular y bloqueo temporal del origen atacante (procedimientos manuales del ADMINISTRADOR).'
  }));
  respuesta.recuperacion = ok(await API.seguridad.recuperar(tokens.admin, inc.id));

  // Notificación
  respuesta.evaluacion = ok(await API.seguridad.evaluarNotificacion(tokens.privacidad, inc.id));
  respuesta.notificacion = ok(await API.seguridad.autorizarNotificacion(tokens.privacidad, inc.id, {
    agencia: respuesta.evaluacion.notificarAgencia, titulares: respuesta.evaluacion.notificarTitulares,
    justificacion: 'Acceso no autorizado a la cuenta con uso de la tarjeta guardada: riesgo para la titular (datos financieros).'
  }));

  // Cierre
  respuesta.cierre = ok(await API.seguridad.cerrar(tokens.seguridad, inc.id, {
    lecciones: 'La alerta de toma de cuenta llegó antes del despacho; la verificación por código frenó la portabilidad. Falta un segundo factor para compras desde un origen nuevo.',
    medidasPreventivas: 'Pendientes de implementar: segundo factor por correo al cambiar la dirección o comprar desde un origen nuevo; aviso al titular de cada inicio de sesión desde un origen nuevo; revisión de contraseñas filtradas al registrarse.'
  }));
  respuesta.detalle = ok(await API.seguridad.detalle(tokens.seguridad, inc.id));
  respuesta.verificacionFinal = ok(await API.auditoria.verificar(tokens.seguridad));

  return {
    esc, verdad, reconstruccion, respuesta, incidenteId: inc.id,
    origenAtacante: referenciaOrigen(ORIGENES.ATACANTE),
    auditoriaCompleta: DB.simularAccesoFisico().audit_log,
    datosSinteticos: ['ana.prueba@ejemplo.test', 'bruno.prueba@ejemplo.test', 'Ana Prueba', 'Calle Ficticia', DIRECCION_ATACANTE, 'Bodega Falsa', PASSWORD_PRUEBA, 'Verano2024!', '1111 2222', ...Object.values(ORIGENES), ...verdad.cuentasProbadas]
  };
}

/** Compara la reconstrucción con la verdad del guion. Devuelve una lista de comprobaciones. */
export function compararConVerdad({ verdad, reconstruccion, respuesta, origenAtacante, auditoriaCompleta, datosSinteticos, esc }) {
  const r = reconstruccion.resumen;
  const sesionAtacante = reconstruccion.linea_tiempo.find(e => e.accion === 'auth:login' && e.resultado === 'EXITO')?.sesion_ref;
  const accionesEnSesion = reconstruccion.linea_tiempo.filter(e => e.sesion_ref === sesionAtacante && e.accion !== 'auth:login').map(e => e.accion);
  const textoAuditoria = JSON.stringify(auditoriaCompleta);
  const c = (control, okc, detalle) => ({ control, ok: Boolean(okc), detalle });
  return [
    c('La cadena de auditoría está íntegra', reconstruccion.integridad.integra && respuesta.verificacionFinal.integra, `${reconstruccion.integridad.registros} registros`),
    c('Todo viene de un único origen (el del atacante)', r.origenes.length === 1 && r.origenes[0] === origenAtacante, r.origenes.join(', ')),
    c('Cuentas probadas = las del guion', r.cuentas_probadas === new Set(verdad.cuentasProbadas).size, `${r.cuentas_probadas} de ${verdad.cuentasProbadas.length}`),
    c('Cuenta real probada sin éxito identificada (Bruno)', r.cuentas_reales_probadas.length === 1 && r.cuentas_reales_probadas[0] === esc.ids.clienteB, r.cuentas_reales_probadas.join(', ')),
    c('Cuenta comprometida = la del guion (Ana)', r.cuentas_comprometidas.length === 1 && r.cuentas_comprometidas[0] === verdad.cuentaComprometida, r.cuentas_comprometidas.join(', ')),
    c('Acciones dentro de la cuenta = las del guion, en orden', JSON.stringify(accionesEnSesion.filter(a => verdad.accionesEnLaCuenta.includes(a))) === JSON.stringify(verdad.accionesEnLaCuenta), accionesEnSesion.join(' > ')),
    c('Pedido fraudulento identificado', r.cambios.some(x => x.accion === 'pedido:crear' && x.recurso === `orders:${verdad.pedidoFraudulento}` && /TOKEN_GUARDADO/.test(x.motivo)), `orders:${verdad.pedidoFraudulento}`),
    c('Intento frenado por los controles (portabilidad sin código)', verdad.portabilidadFrenada && r.frenados.some(x => x.accion === 'derechos:portabilidad:verificacion'), r.frenados.map(x => x.accion).join(', ')),
    c('Titulares afectados = 1 (Ana) con sus datos expuestos', r.titulares_afectados.length === 1 && r.titulares[verdad.cuentaComprometida]?.campos.includes('direccion') && r.titulares[verdad.cuentaComprometida]?.campos.includes('medio_pago'), r.titulares[verdad.cuentaComprometida]?.campos.join(', ')),
    c('No se mezclan eventos legítimos (Ana desde su casa, Bruno, soporte)', !reconstruccion.linea_tiempo.some(e => e.actor_rol === 'SOPORTE' || e.actor_id === esc.ids.clienteB) && reconstruccion.linea_tiempo.every(e => !e.origen_ref || e.origen_ref === origenAtacante), `${reconstruccion.linea_tiempo.length} eventos`),
    c('La auditoría no contiene datos personales, contraseñas ni IPs', datosSinteticos.every(d => !textoAuditoria.includes(d)), `${datosSinteticos.length} valores sintéticos buscados`)
  ];
}
