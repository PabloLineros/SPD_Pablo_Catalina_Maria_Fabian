import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { CONFIG } from '../src/config/env.js';
import { describirLlavero } from '../src/crypto/keyring.js';
import { hashPassword, verifyPassword, inspectBcryptHash, validarPoliticaPassword } from '../src/crypto/hashing.js';
import { encryptField, decryptField, contexto } from '../src/crypto/cipher.js';
import { firmarSaldo, verificarFirmaSaldo } from '../src/crypto/integrity.js';
import { indiceCiegoEmail, seudonimo } from '../src/crypto/pseudonymization.js';
import { PaymentVault } from '../src/crypto/tokenization.js';

test('Llaves: una por finalidad, 256 bits, retiradas de process.env tras cargarse', () => {
  const llavero = describirLlavero();
  assert.equal(llavero.length, 8);
  assert.ok(llavero.every(l => l.bits === 256));
  for (const v of ['KEY_CIFRADO_AES256', 'KEY_HMAC_INTEGRIDAD', 'KEY_HMAC_INDICE', 'KEY_HMAC_RESENAS', 'KEY_HMAC_ANALITICA', 'KEY_HMAC_MARKETING', 'KEY_HMAC_AUDITORIA', 'KEY_HMAC_VERIFICACION']) {
    assert.equal(process.env[v], undefined, `${v} no debe quedar en process.env`);
  }
});

test('Llaves: .env.example no contiene secretos utilizables', () => {
  const ejemplo = fs.readFileSync(new URL('../.env.example', import.meta.url), 'utf8');
  assert.doesNotMatch(ejemplo, /^KEY_[A-Z0-9_]+=\S+/m, 'las llaves deben venir vacías en la plantilla');
  assert.doesNotMatch(ejemplo, /sk_live|gw_live/);
});

test('bcrypt: sal única, verificación, costo configurado y política de largo', async () => {
  const password = 'MiPasswordSeguro!2026';
  const h1 = await hashPassword(password);
  const h2 = await hashPassword(password);
  assert.notEqual(h1, h2, 'dos hashes de la misma contraseña deben diferir (sal)');
  assert.equal(await verifyPassword(password, h1), true);
  assert.equal(await verifyPassword('PasswordErronea', h1), false);
  assert.equal(await verifyPassword(password, null), false, 'sin usuario se usa hash señuelo y se rechaza');
  assert.equal(inspectBcryptHash(h1).costFactorRounds, CONFIG.BCRYPT_ROUNDS);

  assert.match(validarPoliticaPassword('corta'), /al menos 12/);
  assert.match(validarPoliticaPassword('ñ'.repeat(40)), /72 bytes/, 'bcrypt truncaría en silencio sobre 72 bytes');
  assert.equal(validarPoliticaPassword('UnaClaveLargaYValida'), null);
});

test('AES-256-GCM: IV aleatorio, AAD obligatorio y amarrado al registro', () => {
  const ctxA = contexto('users', 'email_cifrado', 'id-a');
  const ctxB = contexto('users', 'email_cifrado', 'id-b');
  const c1 = encryptField('persona@ejemplo.test', ctxA);
  const c2 = encryptField('persona@ejemplo.test', ctxA);

  assert.notEqual(c1, c2, 'mismo texto debe producir criptogramas distintos');
  assert.equal(decryptField(c1, ctxA), 'persona@ejemplo.test');
  assert.throws(() => encryptField('x'), /contexto/, 'cifrar sin AAD está prohibido');
  assert.throws(() => decryptField(c1, ctxB), /Fallo de Autenticidad/, 'copiar el criptograma a otro registro debe fallar');
  assert.throws(() => decryptField(c1, contexto('users', 'nombre_cifrado', 'id-a')), /Fallo de Autenticidad/, 'moverlo a otra columna debe fallar');

  const [iv, tag, ct] = c1.split(':');
  assert.throws(() => decryptField(`${iv}:${tag}:${ct.slice(0, -2)}${ct.endsWith('aa') ? 'bb' : 'aa'}`, ctxA), /Fallo de Autenticidad/);
  assert.throws(() => decryptField(`${iv}:${tag.slice(0, 8)}:${ct}`, ctxA), /Fallo de Autenticidad/, 'tag truncado se rechaza');
});

test('HMAC: la firma del saldo incluye la versión', () => {
  const firma = firmarSaldo('u1', 3, 750);
  assert.equal(verificarFirmaSaldo('u1', 3, 750, firma), true);
  assert.equal(verificarFirmaSaldo('u1', 3, 10000, firma), false, 'saldo alterado');
  assert.equal(verificarFirmaSaldo('u1', 2, 750, firma), false, 'versión distinta');
  assert.equal(verificarFirmaSaldo('u2', 3, 750, firma), false, 'firma de otro usuario');
});

test('Seudónimos: deterministas por finalidad y no cruzables entre finalidades', () => {
  assert.equal(seudonimo('resenas', 'u1'), seudonimo('resenas', 'u1'));
  assert.notEqual(seudonimo('resenas', 'u1'), seudonimo('analitica', 'u1'));
  assert.notEqual(seudonimo('analitica', 'u1'), seudonimo('marketing', 'u1'));
  assert.throws(() => seudonimo('integridad', 'u1'), /no permitida/);
  assert.equal(indiceCiegoEmail(' Ana@Ejemplo.TEST '), indiceCiegoEmail('ana@ejemplo.test'), 'el índice ciego normaliza el email');
});

test('Tokenización: valida Luhn/CVV, devuelve solo last4 y no conserva el PAN', () => {
  const r = PaymentVault.tokenizeCard({ pan: '4111 1111 1111 1111', expirationDate: '10/29', cvv: '912' });
  assert.match(r.token_pago, /^tok_norti_vault_[0-9a-f]{32}$/);
  assert.equal(r.last4, '1111');
  assert.equal(r.brand, 'VISA');
  assert.equal('mascara_tarjeta' in r, false, 'no se entrega máscara completa (revela el largo del PAN)');
  assert.doesNotMatch(JSON.stringify([...PaymentVault.vault.values()]), /4111111111111111/);

  assert.throws(() => PaymentVault.tokenizeCard({ pan: '4111111111111112', expirationDate: '10/29', cvv: '912' }), /inválido/);
  assert.throws(() => PaymentVault.tokenizeCard({ pan: '4111111111111111', expirationDate: '10/29', cvv: 'abc' }), /seguridad/);
  assert.throws(() => PaymentVault.chargeWithToken(r.token_pago, -5), /Monto/);
  assert.throws(() => PaymentVault.chargeWithToken('tok_inexistente', 100), (e) => !e.message.includes('tok_inexistente'));
});
