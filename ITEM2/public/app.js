// Centro de privacidad de NortiShop. Todo el contenido se inserta con textContent (sin innerHTML)
// y el token de sesión vive solo en memoria: al recargar la página hay que volver a ingresar.

const $ = (sel) => document.querySelector(sel);
const sesion = { token: null, usuarioId: null };
let solicitudPendiente = null;

const ETIQUETAS_ESTADO = {
  OTORGADO: 'Aceptado', REVOCADO: 'Retirado', NUNCA_OTORGADO: 'No aceptado', REQUIERE_RENOVACION: 'Texto actualizado: revisa y acepta de nuevo'
};
const CANALES = { REGISTRO: 'Registro', CENTRO_PRIVACIDAD: 'Centro de privacidad', ENLACE_CORREO: 'Enlace del correo', SUPRESION: 'Supresión de cuenta' };
const fecha = (iso) => (iso ? new Date(iso).toLocaleString('es-CL', { dateStyle: 'short', timeStyle: 'short' }) : '—');

function el(tag, props = {}, ...hijos) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') n.className = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null) n.setAttribute(k, v);
  }
  for (const h of hijos.flat()) if (h !== null && h !== undefined) n.append(h instanceof Node ? h : String(h));
  return n;
}

async function llamar(ruta, ...args) {
  const r = await fetch(`/api/${ruta}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(sesion.token ? { Authorization: `Bearer ${sesion.token}` } : {}) },
    body: JSON.stringify({ args })
  });
  const cuerpo = await r.json();
  if (!cuerpo.ok) throw Object.assign(new Error(cuerpo.error?.mensaje ?? 'Error'), { codigo: cuerpo.error?.codigo });
  return cuerpo.data;
}

function avisar(texto, mal = false) {
  const a = $('#aviso');
  a.textContent = texto;
  a.classList.toggle('mal', mal);
  a.hidden = false;
}

// ---------- Consentimientos ----------
function tarjetaConsentimiento(c) {
  const otorgado = c.estado === 'OTORGADO';
  const necesitaTarjeta = c.finalidad === 'GUARDAR_MEDIO_PAGO' && !otorgado;
  const campos = necesitaTarjeta
    ? el('div', { class: 'tarjeta-campos' },
      el('div', {}, el('label', { for: `pan-${c.finalidad}` }, 'Número de tarjeta'), el('input', { id: `pan-${c.finalidad}`, inputmode: 'numeric', value: '4111 1111 1111 1111' })),
      el('div', {}, el('label', { for: `exp-${c.finalidad}` }, 'Vencimiento (MM/AA)'), el('input', { id: `exp-${c.finalidad}`, value: '12/29' })),
      el('div', {}, el('label', { for: `cvv-${c.finalidad}` }, 'CVV'), el('input', { id: `cvv-${c.finalidad}`, inputmode: 'numeric', value: '123' })))
    : null;

  const accion = otorgado
    ? el('button', { class: 'destructivo', onclick: () => cambiar('revocar', { finalidad: c.finalidad }) }, 'Retirar consentimiento')
    : el('button', {
      class: 'primario',
      onclick: () => cambiar('otorgar', {
        finalidad: c.finalidad, version: c.version_vigente,
        ...(necesitaTarjeta ? { tarjeta: { pan: $(`#pan-${c.finalidad}`).value, expirationDate: $(`#exp-${c.finalidad}`).value, cvv: $(`#cvv-${c.finalidad}`).value } } : {})
      })
    }, c.estado === 'REQUIERE_RENOVACION' ? 'Aceptar nueva versión' : 'Aceptar');

  return el('article', { class: 'consent' },
    el('div', {}, el('h3', {}, c.nombre)),
    el('div', { class: 'acciones' }, el('span', { class: `chip ${c.estado}` }, ETIQUETAS_ESTADO[c.estado]), accion),
    el('p', { class: 'texto' }, `«${c.texto_vigente}» (versión ${c.version_vigente})`),
    campos,
    el('div', { class: 'meta' },
      el('span', {}, `Aceptado: ${fecha(c.otorgado_el)}${c.version_aceptada ? ` · v${c.version_aceptada}` : ''}`),
      el('span', {}, `Retirado: ${fecha(c.revocado_el)}`),
      el('span', {}, `Lo usa: ${c.procesos_que_dependen.join('; ')}`)));
}

async function cambiar(operacion, entrada) {
  try {
    await llamar(`consentimiento/${operacion}`, sesion.usuarioId, entrada);
    avisar(operacion === 'otorgar' ? 'Consentimiento registrado.' : 'Consentimiento retirado. Dejamos de usar tus datos para esa finalidad desde ahora.');
    await refrescar();
  } catch (e) {
    avisar(e.message, true);
  }
}

// ---------- Derechos ----------
async function solicitar(entrada) {
  try {
    const s = await llamar('derechos/solicitar', sesion.usuarioId, entrada);
    solicitudPendiente = s;
    $('#resultado').hidden = true;
    $('#verif-texto').textContent = s.verificacion.requiereCodigo
      ? `Enviamos un código a ${s.verificacion.codigoEnviadoA}. Vence en 10 minutos.`
      : 'Ingresa tu contraseña para confirmar.';
    $('#v-codigo-campo').hidden = !s.verificacion.requiereCodigo;
    $('#v-codigo').required = s.verificacion.requiereCodigo;
    $('#form-verif').hidden = false;
    $('#v-clave').focus();
    await refrescar();
  } catch (e) {
    avisar(e.message, true);
  }
}

async function confirmar(ev) {
  ev.preventDefault();
  try {
    const entrada = { password: $('#v-clave').value };
    if (solicitudPendiente.verificacion.requiereCodigo) entrada.codigo = $('#v-codigo').value.trim();
    const r = await llamar('derechos/confirmar', sesion.usuarioId, solicitudPendiente.id, entrada);
    $('#form-verif').hidden = true;
    $('#form-verif').reset();
    mostrarResultado(r);
    if (r.solicitud.tipo === 'SUPRESION' && r.solicitud.resultado === 'EJECUTADA') return salir('Tu cuenta fue eliminada.');
    await refrescar();
  } catch (e) {
    avisar(e.codigo === 'CREDENCIALES_INVALIDAS' ? 'No pudimos verificar tu identidad. Revisa la contraseña y el código.' : e.message, true);
    await refrescar();
  }
}

function mostrarResultado({ solicitud, datos }) {
  $('#resultado').hidden = false;
  $('#resultado-titulo').textContent = `${solicitud.tipo}: ${solicitud.resultado === 'EJECUTADA' ? 'realizada' : 'rechazada'}`;
  $('#resultado-texto').textContent = solicitud.fundamento ?? 'Tu solicitud fue atendida.';
  const pre = $('#resultado-json');
  const enlace = $('#resultado-descarga');
  pre.hidden = !datos;
  enlace.hidden = !datos;
  if (datos) {
    const json = JSON.stringify(datos, null, 2);
    pre.textContent = json;
    enlace.href = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
    enlace.download = `nortishop-${solicitud.tipo.toLowerCase()}-${solicitud.id.slice(0, 8)}.json`;
  }
}

// ---------- Carga de datos ----------
async function refrescar() {
  const [estado, historial, solicitudes] = await Promise.all([
    llamar('consentimiento/estado', sesion.usuarioId),
    llamar('consentimiento/historial', sesion.usuarioId),
    llamar('derechos/misSolicitudes', sesion.usuarioId)
  ]);
  $('#lista-consent').replaceChildren(...estado.requierenConsentimiento.map(tarjetaConsentimiento));
  $('#lista-otros').replaceChildren(...estado.otrasBases.map(o =>
    el('li', {}, el('strong', {}, o.nombre), el('span', { class: 'base' }, o.base.replaceAll('_', ' ').toLowerCase()))));

  const filasHist = historial.slice().reverse().map(h => el('tr', {},
    el('td', {}, fecha(h.ocurrido_el)), el('td', {}, h.finalidad), el('td', {}, h.accion), el('td', {}, `v${h.version_texto}`), el('td', {}, CANALES[h.canal] ?? h.canal)));
  $('#tabla-hist tbody').replaceChildren(...(filasHist.length ? filasHist : [el('tr', {}, el('td', { colspan: 5, class: 'vacio' }, 'Aún no hay cambios registrados.'))]));

  const filasSol = solicitudes.slice().reverse().map(s => el('tr', {},
    el('td', {}, s.tipo), el('td', {}, s.estado), el('td', {}, s.resultado ?? '—'), el('td', {}, fecha(s.recibida_el)), el('td', {}, fecha(s.plazo_vence_el)), el('td', {}, fecha(s.cerrada_el))));
  $('#tabla-sol tbody').replaceChildren(...(filasSol.length ? filasSol : [el('tr', {}, el('td', { colspan: 6, class: 'vacio' }, 'No has presentado solicitudes.'))]));

  await refrescarCorreo();
}

async function refrescarCorreo() {
  const r = await fetch('/api/dev/bandeja', { headers: { Authorization: `Bearer ${sesion.token}` } });
  const cuerpo = await r.json();
  const mensajes = cuerpo.ok ? cuerpo.data : [];
  $('#lista-correo').replaceChildren(...(mensajes.length
    ? mensajes.slice(0, 5).map(m => el('li', {}, el('strong', {}, m.asunto), el('span', {}, m.cuerpo), el('span', { class: 'cuando' }, fecha(m.enviado_el))))
    : [el('li', { class: 'tenue' }, 'Sin mensajes.')]));
}

// ---------- Sesión ----------
async function ingresar(ev) {
  ev.preventDefault();
  $('#login-error').hidden = true;
  try {
    const r = await llamar('auth/iniciarSesion', { email: $('#login-email').value, password: $('#login-clave').value });
    if (r.rol !== 'CLIENTE') throw new Error('El Centro de privacidad es para clientes.');
    Object.assign(sesion, { token: r.token, usuarioId: r.usuarioId });
    $('#vista-login').hidden = true;
    $('#vista-centro').hidden = false;
    $('#btn-salir').hidden = false;
    await refrescar();
  } catch (e) {
    $('#login-error').textContent = e.message;
    $('#login-error').hidden = false;
  }
}

async function salir(mensaje) {
  if (sesion.token) await llamar('auth/cerrarSesion', sesion.token).catch(() => {});
  Object.assign(sesion, { token: null, usuarioId: null });
  $('#vista-centro').hidden = true;
  $('#btn-salir').hidden = true;
  $('#vista-login').hidden = false;
  if (typeof mensaje === 'string') {
    $('#login-error').textContent = mensaje;
    $('#login-error').hidden = false;
  }
}

$('#form-login').addEventListener('submit', ingresar);
$('#btn-salir').addEventListener('click', () => salir());
$('#form-verif').addEventListener('submit', confirmar);
for (const b of document.querySelectorAll('.derechos button[data-tipo]')) {
  b.addEventListener('click', () => {
    if (b.dataset.tipo === 'SUPRESION' && $('#sup-confirma').value.trim() !== 'ELIMINAR') {
      return avisar('Para solicitar la supresión escribe ELIMINAR en el campo de confirmación.', true);
    }
    return solicitar({ tipo: b.dataset.tipo });
  });
}
$('#form-rect').addEventListener('submit', (ev) => {
  ev.preventDefault();
  const cambios = {};
  for (const [id, campo] of [['r-nombre', 'nombre'], ['r-telefono', 'telefono'], ['r-direccion', 'direccionDespacho'], ['r-comuna', 'comuna'], ['r-email', 'email']]) {
    const v = $(`#${id}`).value.trim();
    if (v) cambios[campo] = v;
  }
  if (!Object.keys(cambios).length) return avisar('Completa al menos un dato a corregir.', true);
  return solicitar({ tipo: 'RECTIFICACION', cambios });
});
