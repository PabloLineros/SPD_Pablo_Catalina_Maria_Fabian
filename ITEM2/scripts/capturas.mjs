// Genera las capturas de evidencia en ITEM2/evidencias/capturas/:
//  - Pantalla REAL del Centro de privacidad (Chrome o Edge en modo headless, vía DevTools Protocol).
//  - Salida REAL de `npm test` y `npm run demo:privacidad`, convertida a imagen con estilo de terminal.
// Uso (desde ITEM2): node scripts/capturas.mjs     Requiere Google Chrome o Microsoft Edge instalado.
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ITEM2 = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SALIDA = path.join(ITEM2, 'evidencias', 'capturas');
const NAVEGADORES = [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  '/usr/bin/google-chrome', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
];
const NAVEGADOR = NAVEGADORES.find(p => fs.existsSync(p));
if (!NAVEGADOR) throw new Error('No se encontró Chrome ni Edge.');
const PUERTO_CDP = 9333;
fs.mkdirSync(SALIDA, { recursive: true });
for (const f of fs.readdirSync(SALIDA)) if (f.endsWith('.png')) fs.rmSync(path.join(SALIDA, f));

const esperar = (ms) => new Promise(r => setTimeout(r, ms));

// ---------------- Navegador headless ----------------
const perfil = fs.mkdtempSync(path.join(os.tmpdir(), 'cdp-'));
const navegador = spawn(NAVEGADOR, ['--headless=new', `--remote-debugging-port=${PUERTO_CDP}`, '--remote-allow-origins=*',
  `--user-data-dir=${perfil}`, '--no-first-run', '--no-default-browser-check', '--hide-scrollbars', 'about:blank'], { stdio: 'ignore' });

let pagina;
for (let i = 0; i < 50 && !pagina; i++) {
  await esperar(200);
  try { pagina = (await (await fetch(`http://127.0.0.1:${PUERTO_CDP}/json/list`)).json()).find(t => t.type === 'page'); } catch {}
}
const ws = new WebSocket(pagina.webSocketDebuggerUrl);
await new Promise(r => ws.addEventListener('open', r, { once: true }));
let siguienteId = 1;
const pendientes = new Map();
ws.addEventListener('message', (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pendientes.has(m.id)) { pendientes.get(m.id)(m); pendientes.delete(m.id); }
});
const cdp = (method, params = {}) => new Promise((resolve, reject) => {
  const id = siguienteId++;
  pendientes.set(id, (m) => (m.error ? reject(new Error(`${method}: ${m.error.message}`)) : resolve(m.result)));
  ws.send(JSON.stringify({ id, method, params }));
});
const evaluar = async (expr) => (await cdp('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true })).result.value;
async function esperarA(expr) {
  for (let i = 0; i < 60; i++) {
    await esperar(100);
    if (await evaluar(expr)) break;
  }
  await esperar(400);
}

async function navegar(url, ancho = 1280) {
  await cdp('Emulation.setDeviceMetricsOverride', { width: ancho, height: 900, deviceScaleFactor: 1, mobile: false });
  await cdp('Page.navigate', { url });
  await esperarA(`document.readyState === 'complete'`);
}

async function capturar(nombre, selector = null) {
  const caja = await evaluar(`(() => {
    const el = ${selector ? `document.querySelector(${JSON.stringify(selector)})` : 'document.documentElement'};
    const r = el.getBoundingClientRect();
    return { x: r.left + scrollX, y: r.top + scrollY, w: Math.ceil(${selector ? 'r.width' : 'document.documentElement.scrollWidth'}), h: Math.ceil(${selector ? 'r.height' : 'document.documentElement.scrollHeight'}) };
  })()`);
  const margen = selector ? 12 : 0;
  const { data } = await cdp('Page.captureScreenshot', {
    format: 'png', captureBeyondViewport: true,
    clip: { x: Math.max(0, caja.x - margen), y: Math.max(0, caja.y - margen), width: caja.w + 2 * margen, height: caja.h + 2 * margen, scale: 1 }
  });
  fs.writeFileSync(path.join(SALIDA, `${nombre}.png`), Buffer.from(data, 'base64'));
  console.log(`  ✔ ${nombre}.png`);
}

const clic = (selector) => evaluar(`document.querySelector(${JSON.stringify(selector)}).click()`);
const escribir = (selector, valor) => evaluar(`document.querySelector(${JSON.stringify(selector)}).value = ${JSON.stringify(valor)}`);

await cdp('Page.enable');
await cdp('Runtime.enable');
await cdp('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'light' }] });

// ---------------- 1. Centro de privacidad (pantalla real) ----------------
console.log('Centro de privacidad:');
await import(pathToFileURL(path.join(ITEM2, 'scripts', 'entorno-pruebas.js')));
const { crearServidor } = await import(pathToFileURL(path.join(ITEM2, 'src', 'server.js')));
const { API } = await import(pathToFileURL(path.join(ITEM2, 'src', 'api.js')));
const { prepararEscenario, TARJETA_VISA } = await import(pathToFileURL(path.join(ITEM2, 'src', 'dev', 'escenario.js')));
const { ids } = await prepararEscenario();
await API.invitado.crearPedido({
  nombre: 'Invitada Prueba', email: 'invitada@ejemplo.test', direccionDespacho: 'Calle Invitada 77', comuna: 'Arica',
  items: [{ productoId: ids.productos[1], cantidad: 1 }], tarjeta: TARJETA_VISA
});
const servidor = crearServidor().listen(0, '127.0.0.1');
await new Promise(r => servidor.once('listening', r));
const BASE = `http://127.0.0.1:${servidor.address().port}/`;

await navegar(BASE);
await capturar('10_centro_inicio');

// Canal sin cuenta: la invitada pide una copia; el código llega a la bandeja simulada.
await clic('#form-sin-cuenta button[type=submit]');
await esperarA(`!document.querySelector('#form-sin-cuenta-codigo').hidden && document.querySelectorAll('#sc-correo li').length > 0`);
const codigoInvitada = await evaluar(`(document.querySelector('#sc-correo li span')?.textContent.match(/es (\\d{6})\\./) || [])[1]`);
await escribir('#sc-codigo', codigoInvitada);
await clic('#form-sin-cuenta-codigo button[type=submit]');
await esperarA(`!document.querySelector('#sc-resultado').hidden`);
await capturar('22_sin_cuenta_resultado', '#vista-sin-cuenta');

// Titular con cuenta
await clic('#form-login button[type=submit]');
await esperarA(`!document.querySelector('#vista-centro').hidden && document.querySelectorAll('.consent').length === 3`);
await capturar('11_centro_consentimientos_inicial', 'section[aria-labelledby="t-consent"]');
await capturar('12_centro_otras_bases', 'section[aria-labelledby="t-otros"]');

await evaluar(`[...document.querySelectorAll('.consent')].find(c => c.textContent.includes('Ofertas y novedades')).querySelector('button').click()`);
await esperarA(`!document.querySelector('#aviso').hidden`);
await capturar('13_centro_consentimiento_retirado', 'section[aria-labelledby="t-consent"]');
await capturar('14_centro_aviso_retiro', '#aviso');
await capturar('15_centro_historial', 'section[aria-labelledby="t-hist"]');

// Acceso: solicitar -> código -> confirmar -> descarga de un solo uso
await clic('.derechos button[data-tipo="ACCESO"]');
await esperarA(`!document.querySelector('#form-verif').hidden`);
await capturar('16_centro_bandeja_codigo', 'section[aria-labelledby="t-correo"]');
await capturar('17_centro_verificacion', '#form-verif');
const codigo = await evaluar(`(document.querySelector('#lista-correo li span')?.textContent.match(/es (\\d{6})\\./) || [])[1]`);
await escribir('#v-clave', 'ClaveDePrueba#2026');
await escribir('#v-codigo', codigo);
await clic('#form-verif button[type=submit]');
await esperarA(`!document.querySelector('#resultado').hidden`);
await capturar('18_centro_resultado_acceso', '#resultado');

// Oposición y bloqueo (solo contraseña)
for (const boton of ['#btn-oposicion', '#btn-bloqueo']) {
  await clic(boton);
  await esperarA(`!document.querySelector('#form-verif').hidden`);
  await escribir('#v-clave', 'ClaveDePrueba#2026');
  await clic('#form-verif button[type=submit]');
  await esperarA(`document.querySelector('#form-verif').hidden`);
}
await esperarA(`document.querySelector('#bl-estado').textContent.length > 0`);
await capturar('23_centro_oposicion_bloqueo', '.derechos');
await capturar('24_centro_resultado_bloqueo', '#resultado');
await capturar('19_centro_solicitudes', '#tabla-sol');
await capturar('20_centro_pagina_completa');

await navegar(BASE, 400);
await capturar('21_centro_movil_inicio');
servidor.close();

// ---------------- 2. Salidas de terminal reales ----------------
console.log('Terminal:');
const COLORES = { 1: 'b', 2: 'tenue', 31: 'rojo', 32: 'verde', 33: 'amarillo', 34: 'azul', 36: 'cian', 35: 'magenta', 90: 'tenue' };
const escapar = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
function ansiAHtml(texto) {
  let abiertos = 0;
  const html = escapar(texto).replace(/\x1b\[([\d;]*)m/g, (_, codigos) => {
    let r = '';
    for (const c of (codigos || '0').split(';').map(Number)) {
      if (c === 0 || c === 22 || c === 39) { r += '</span>'.repeat(abiertos); abiertos = 0; }
      else if (COLORES[c]) { r += `<span class="${COLORES[c]}">`; abiertos++; }
    }
    return r;
  });
  return html + '</span>'.repeat(abiertos);
}
const sinAnsi = (s) => s.replace(/\x1b\[[\d;]*m/g, '');
const ESTILO = `body{margin:0;background:#0c0c0c;font:13px/1.45 "Cascadia Mono",Consolas,monospace;color:#cccccc}
.ventana{width:max-content;min-width:1100px}
.barra{background:#1f1f1f;color:#cccccc;padding:6px 14px;font:12px "Segoe UI",sans-serif;border-bottom:1px solid #333}
pre{margin:0;padding:12px 16px;white-space:pre}.b{font-weight:700}.tenue{color:#8a8a8a}.rojo{color:#f14c4c}.verde{color:#23d18b}
.amarillo{color:#f5f543}.azul{color:#3b8eea}.cian{color:#29b8db}.magenta{color:#d670d6}.prompt{color:#cccccc}`;

async function terminal(nombre, titulo, comando, contenido) {
  const html = `<style>${ESTILO}</style><div class="ventana"><div class="barra">${escapar(titulo)}</div><pre><span class="prompt">PS ${escapar(ITEM2)}&gt; ${escapar(comando)}</span>\n${ansiAHtml(contenido)}</pre></div>`;
  const archivo = path.join(perfil, `${nombre}.html`);
  fs.writeFileSync(archivo, html);
  await navegar(pathToFileURL(archivo).href, 1300);
  await capturar(nombre, '.ventana');
}

const entorno = { ...process.env, FORCE_COLOR: '1' };
const pruebas = execFileSync(process.execPath, ['--import', './scripts/entorno-pruebas.js', '--test', '--test-reporter=spec'], { cwd: ITEM2, env: entorno, encoding: 'utf8' });
await terminal('01_npm_test', 'Windows PowerShell — npm test', 'node --import ./scripts/entorno-pruebas.js --test --test-reporter=spec', pruebas);

// La demo se corta por sección (título ═══) y, si una sección es larga, por subtítulo (▶).
const demo = execFileSync(process.execPath, ['src/demo-privacidad.js'], { cwd: ITEM2, env: entorno, encoding: 'utf8' });
const lineas = demo.split('\n');
const planas = lineas.map(sinAnsi);
const inicios = planas.map((l, i) => (l.startsWith('═') && planas[i + 2]?.startsWith('═') ? i : -1)).filter(i => i >= 0);
const nombres = ['02_demo_consentimiento', '03_demo_derechos', '04_demo_auditoria', '05_demo_incidentes', '06_demo_no_eludibles'];
const MAX_LINEAS = 95;
for (let k = 0; k < inicios.length; k++) {
  const desde = k === 0 ? 0 : inicios[k];
  const hasta = inicios[k + 1] ?? lineas.length;
  const base = nombres[k] ?? `0${k + 2}_demo`;
  if (hasta - desde <= MAX_LINEAS) {
    await terminal(base, 'Windows PowerShell — npm run demo:privacidad', 'npm run demo:privacidad', lineas.slice(desde, hasta).join('\n'));
    continue;
  }
  // Agrupa subtítulos consecutivos hasta MAX_LINEAS por imagen.
  const cortes = [desde, ...planas.map((l, i) => (i > desde + 3 && i < hasta && l.startsWith('▶') ? i : -1)).filter(i => i >= 0), hasta];
  let parte = 1;
  let inicio = desde;
  for (let c = 1; c < cortes.length; c++) {
    const finGrupo = cortes[c];
    const siguiente = cortes[c + 1];
    if (siguiente === undefined || siguiente - inicio > MAX_LINEAS) {
      await terminal(`${base}_${parte}`, 'Windows PowerShell — npm run demo:privacidad', 'npm run demo:privacidad', lineas.slice(inicio, finGrupo).join('\n'));
      parte++;
      inicio = finGrupo;
    }
  }
}

ws.close();
navegador.kill();
await esperar(500);
try { fs.rmSync(perfil, { recursive: true, force: true }); } catch {}
console.log(`Capturas en ${SALIDA}`);
process.exit(0);
