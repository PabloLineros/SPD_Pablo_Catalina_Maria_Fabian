// Capturas de la etapa de trazabilidad en sistema/evidencias/capturas/ (30_* a 34_*):
// salida REAL de `npm run simulacro` y de test/trazabilidad.test.js, con estilo de terminal.
// Uso (desde sistema/): node scripts/capturas-trazabilidad.mjs     Requiere Google Chrome o Microsoft Edge.
// No toca las capturas de etapas anteriores.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SISTEMA = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SALIDA = path.join(SISTEMA, 'evidencias', 'capturas');
const NAVEGADOR = [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  '/usr/bin/google-chrome', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
].find(p => fs.existsSync(p));
if (!NAVEGADOR) throw new Error('No se encontró Chrome ni Edge.');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'capt-'));

const COLORES = { 1: 'b', 2: 'tenue', 31: 'rojo', 32: 'verde', 33: 'amarillo', 36: 'cian', 90: 'tenue' };
const escapar = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
function ansiAHtml(texto) {
  let abiertos = 0;
  const html = escapar(texto).replace(/\x1b\[([\d;]*)m/g, (_, codigos) => {
    let r = '';
    for (const c of (codigos || '0').split(';').map(Number)) {
      if (c === 0 || c === 22 || c === 39) { r += '</span>'.repeat(abiertos); abiertos = 0; } else if (COLORES[c]) { r += `<span class="${COLORES[c]}">`; abiertos++; }
    }
    return r;
  });
  return html + '</span>'.repeat(abiertos);
}
const colorear = (t) => escapar(t)
  .replace(/^(=+)$/gm, '<span class="cian">$1</span>')
  .replace(/^( \d\. .*| SIMULACRO.*)$/gm, '<span class="b cian">$1</span>')
  .replace(/✔/g, '<span class="verde">✔</span>').replace(/✖/g, '<span class="rojo">✖</span>')
  .replace(/\b(FALLIDO|ALTA|DENEGADO)\b/g, '<span class="amarillo">$1</span>')
  .replace(/\b(EXITO|ÍNTEGRA|CERRADO|CANCELADO)\b/g, '<span class="verde">$1</span>');

const ESTILO = `body{margin:0;background:#0c0c0c}.ventana{display:inline-block;background:#0c0c0c;font:13px/1.45 "Cascadia Mono",Consolas,monospace;color:#cccccc}
.barra{background:#1f1f1f;color:#cccccc;padding:6px 14px;font:12px "Segoe UI",sans-serif;border-bottom:1px solid #333}
pre{margin:0;padding:12px 16px;white-space:pre}.b{font-weight:700}.tenue{color:#8a8a8a}.rojo{color:#f14c4c}.verde{color:#23d18b}
.amarillo{color:#f5f543}.cian{color:#29b8db}`;

function terminal(nombre, comando, cuerpoHtml, lineas, ancho = 1500) {
  const html = `<!doctype html><meta charset="utf-8"><style>${ESTILO}</style><div class="ventana" style="min-width:${ancho - 20}px"><div class="barra">Windows PowerShell — ${escapar(comando)}</div><pre>PS ${escapar(SISTEMA)}&gt; ${escapar(comando)}\n${cuerpoHtml}</pre></div>`;
  const archivo = path.join(tmp, `${nombre}.html`);
  fs.writeFileSync(archivo, html);
  const alto = 70 + lineas * 19;
  execFileSync(NAVEGADOR, ['--headless=new', '--disable-gpu', '--hide-scrollbars', `--user-data-dir=${path.join(tmp, 'perfil')}`,
    `--screenshot=${path.join(SALIDA, `${nombre}.png`)}`, `--window-size=${ancho},${alto}`, pathToFileURL(archivo).href], { stdio: 'ignore' });
  console.log(`  ✔ ${nombre}.png`);
}

// 1. Simulacro, cortado por secciones
const salida = execFileSync(process.execPath, ['src/simulacro-incidente.js'], { cwd: SISTEMA, encoding: 'utf8' });
const lineas = salida.replace(/^\n/, '').split('\n');
const seccion = (titulo) => lineas.findIndex(l => l.startsWith(` ${titulo}`)) - 1;
const cortes = [
  ['30_simulacro_deteccion_reconstruccion', 0, seccion('3.')],
  ['31_simulacro_respuesta', seccion('3.'), seccion('4.')],
  ['32_simulacro_notificacion', seccion('4.'), seccion('5.')],
  ['33_simulacro_comprobacion', seccion('5.'), lineas.length]
];
for (const [nombre, desde, hasta] of cortes) {
  const trozo = lineas.slice(desde, hasta).join('\n').replace(/\n+$/, '');
  terminal(nombre, 'npm run simulacro', colorear(trozo), trozo.split('\n').length + 1);
}

// 2. Pruebas de esta etapa
const pruebas = execFileSync(process.execPath, ['--import', './scripts/entorno-pruebas.js', '--test', '--test-reporter=spec', 'test/trazabilidad.test.js'],
  { cwd: SISTEMA, encoding: 'utf8', env: { ...process.env, FORCE_COLOR: '1' } }).replace(/\n+$/, '');
terminal('34_pruebas_trazabilidad', 'node --test test/trazabilidad.test.js', ansiAHtml(pruebas), pruebas.split('\n').length + 1, 1250);

fs.rmSync(tmp, { recursive: true, force: true });
console.log(`Capturas en ${SALIDA}`);
