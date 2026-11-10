// Convierte los bloques ```mermaid del informe en imágenes PNG (ITEM2/evidencias/diagramas/).
// Uso (desde ITEM2): node scripts/diagramas.mjs
// Requiere Google Chrome o Microsoft Edge e internet (carga Mermaid desde cdn.jsdelivr.net).
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ITEM2 = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const INFORME = path.join(ITEM2, '..', 'INFORME_CONSENTIMIENTO_DERECHOS_AUDITORIA.md');
const SALIDA = path.join(ITEM2, 'evidencias', 'diagramas');
const NOMBRES = ['D1_modelo_datos_consentimiento', 'D2_estados_consentimiento', 'D3_modelo_datos_derechos', 'D4_flujo_solicitud_derechos'];
const NAVEGADOR = [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  '/usr/bin/google-chrome', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
].find(p => fs.existsSync(p));
if (!NAVEGADOR) throw new Error('No se encontró Chrome ni Edge.');

const bloques = [...fs.readFileSync(INFORME, 'utf8').matchAll(/```mermaid\n([\s\S]*?)```/g)].map(m => m[1]);
if (bloques.length !== NOMBRES.length) throw new Error(`El informe tiene ${bloques.length} diagramas y hay ${NOMBRES.length} nombres.`);
fs.mkdirSync(SALIDA, { recursive: true });
for (const f of fs.readdirSync(SALIDA)) if (f.endsWith('.png')) fs.rmSync(path.join(SALIDA, f));

const esperar = (ms) => new Promise(r => setTimeout(r, ms));
const perfil = fs.mkdtempSync(path.join(os.tmpdir(), 'cdp-'));
const PUERTO = 9334;
const navegador = spawn(NAVEGADOR, ['--headless=new', `--remote-debugging-port=${PUERTO}`, '--remote-allow-origins=*',
  `--user-data-dir=${perfil}`, '--no-first-run', '--hide-scrollbars', 'about:blank'], { stdio: 'ignore' });

let pagina;
for (let i = 0; i < 50 && !pagina; i++) {
  await esperar(200);
  try { pagina = (await (await fetch(`http://127.0.0.1:${PUERTO}/json/list`)).json()).find(t => t.type === 'page'); } catch {}
}
const ws = new WebSocket(pagina.webSocketDebuggerUrl);
await new Promise(r => ws.addEventListener('open', r, { once: true }));
let id = 1;
const pend = new Map();
ws.addEventListener('message', (e) => { const m = JSON.parse(e.data); if (pend.has(m.id)) { pend.get(m.id)(m); pend.delete(m.id); } });
const cdp = (method, params = {}) => new Promise((ok, mal) => {
  const n = id++;
  pend.set(n, (m) => (m.error ? mal(new Error(m.error.message)) : ok(m.result)));
  ws.send(JSON.stringify({ id: n, method, params }));
});
const evaluar = async (e) => (await cdp('Runtime.evaluate', { expression: e, awaitPromise: true, returnByValue: true })).result.value;

await cdp('Page.enable');
await cdp('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'light' }] });

for (let k = 0; k < bloques.length; k++) {
  const html = `<!doctype html><meta charset="utf-8">
<style>body{margin:0;background:#fff;font-family:"Segoe UI",Arial,sans-serif}#lienzo{display:inline-block;padding:24px}</style>
<div id="lienzo"><pre class="mermaid">${bloques[k].replace(/&/g, '&amp;').replace(/</g, '&lt;')}</pre></div>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js"></script>
<script>
  mermaid.initialize({ startOnLoad: false, theme: 'neutral', fontFamily: 'Segoe UI, Arial, sans-serif',
    er: { useMaxWidth: false }, flowchart: { useMaxWidth: false, nodeSpacing: 60, rankSpacing: 60 } });
  window.listo = mermaid.run().then(() => 'ok').catch(e => 'error: ' + e.message);
</script>`;
  const archivo = path.join(perfil, `d${k}.html`);
  fs.writeFileSync(archivo, html);
  await cdp('Emulation.setDeviceMetricsOverride', { width: 2000, height: 1000, deviceScaleFactor: 2, mobile: false });
  await cdp('Page.navigate', { url: pathToFileURL(archivo).href });
  let estado;
  for (let i = 0; i < 100; i++) {
    await esperar(150);
    estado = await evaluar('window.listo ? window.listo : null').catch(() => null);
    if (estado) break;
  }
  if (estado !== 'ok') throw new Error(`Diagrama ${NOMBRES[k]}: ${estado ?? 'Mermaid no cargó (¿sin internet?)'}`);
  const caja = await evaluar(`(() => { const r = document.querySelector('#lienzo').getBoundingClientRect(); return { x: r.left, y: r.top, w: Math.ceil(r.width), h: Math.ceil(r.height) }; })()`);
  const { data } = await cdp('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: caja.x, y: caja.y, width: caja.w, height: caja.h, scale: 1 } });
  fs.writeFileSync(path.join(SALIDA, `${NOMBRES[k]}.png`), Buffer.from(data, 'base64'));
  console.log(`  ✔ ${NOMBRES[k]}.png (${caja.w}x${caja.h})`);
}

ws.close();
navegador.kill();
await esperar(400);
try { fs.rmSync(perfil, { recursive: true, force: true }); } catch {}
process.exit(0);
