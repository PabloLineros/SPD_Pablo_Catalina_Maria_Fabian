import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Crea o completa ITEM2/.env con llaves aleatorias (32 bytes c/u, una por finalidad).
 * - Nunca sobrescribe valores existentes: solo agrega las variables que falten.
 * - Las llaves se generan con CSPRNG (crypto.randomBytes) y no se imprimen en pantalla.
 */

const raiz = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const rutaEnv = path.join(raiz, '.env');

const VARIABLES = [
  'KEY_CIFRADO_AES256',
  'KEY_HMAC_INTEGRIDAD',
  'KEY_HMAC_INDICE',
  'KEY_HMAC_RESENAS',
  'KEY_HMAC_ANALITICA',
  'KEY_HMAC_MARKETING',
  'KEY_HMAC_AUDITORIA',
  'KEY_HMAC_VERIFICACION'
];

const existente = fs.existsSync(rutaEnv) ? fs.readFileSync(rutaEnv, 'utf8') : '';
const definidas = new Set(
  existente.split(/\r?\n/).map(l => l.match(/^\s*([A-Z0-9_]+)\s*=\s*\S/)?.[1]).filter(Boolean)
);

const nuevas = [];
if (!definidas.has('NODE_ENV')) nuevas.push('NODE_ENV=development');
if (!definidas.has('BCRYPT_SALT_ROUNDS')) nuevas.push('BCRYPT_SALT_ROUNDS=12');
if (!definidas.has('SESSION_TTL_MINUTOS')) nuevas.push('SESSION_TTL_MINUTOS=30');
for (const variable of VARIABLES) {
  if (!definidas.has(variable)) nuevas.push(`${variable}=${crypto.randomBytes(32).toString('hex')}`);
}

if (nuevas.length === 0) {
  console.log('✔ .env ya contiene todas las variables requeridas. No se modificó.');
  process.exit(0);
}

const separador = existente && !existente.endsWith('\n') ? '\n' : '';
const bloque = `${separador}\n# --- Generado por scripts/generar-env.js (${new Date().toISOString().slice(0, 10)}) ---\n${nuevas.join('\n')}\n`;
fs.writeFileSync(rutaEnv, existente + bloque, { encoding: 'utf8', mode: 0o600 });

console.log(`✔ Se agregaron ${nuevas.length} variable(s) a .env:`);
nuevas.forEach(l => console.log(`  - ${l.split('=')[0]}`));
console.log('  (Los valores no se muestran. .env está excluido de Git.)');
