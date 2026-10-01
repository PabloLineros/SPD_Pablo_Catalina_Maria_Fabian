import test from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword, verifyPassword, inspectBcryptHash } from '../src/crypto/hashing.js';
import { encryptField, decryptField, inspectCipherPayload } from '../src/crypto/cipher.js';
import { generateHMAC, verifyHMAC } from '../src/crypto/integrity.js';
import { PaymentVault } from '../src/crypto/tokenization.js';
import { UserService } from '../src/services/userService.js';
import { LoyaltyService } from '../src/services/loyaltyService.js';
import { DB } from '../src/db/repository.js';

test('1. Hashing de Contraseñas (bcrypt) - Irreversibilidad y Salting', async (t) => {
  const password = 'MiPasswordSeguro!2026';
  const hash1 = await hashPassword(password);
  const hash2 = await hashPassword(password);

  // Verificación de salting: dos hashes de la misma contraseña deben ser diferentes
  assert.notEqual(hash1, hash2, 'Salting falló: dos hashes idénticos no deben producir el mismo valor.');

  // Verificación correcta
  const isValid = await verifyPassword(password, hash1);
  assert.equal(isValid, true, 'La validación de contraseña legítima debe retornar true.');

  // Rechazo de contraseña equivocada
  const isInvalid = await verifyPassword('PasswordErronea', hash1);
  assert.equal(isInvalid, false, 'Una contraseña incorrecta debe ser rechazada.');

  // Inspección de estructura
  const info = inspectBcryptHash(hash1);
  assert.equal(info.valid, true);
  assert.equal(info.costFactorRounds, 12);
});

test('2. Cifrado Simétrico Reversible (AES-256-GCM) - Confidencialidad y AEAD', (t) => {
  const pii = 'usuario.secreto@nortishop.cl';
  const ciphertext1 = encryptField(pii);
  const ciphertext2 = encryptField(pii);

  // Verificación de IV dinámico: dos cifrados del mismo dato deben dar criptogramas distintos
  assert.notEqual(ciphertext1, ciphertext2, 'Fallo de IV: dos textos idénticos no deben generar el mismo criptograma.');

  // Descifrado exitoso
  const decrypted = decryptField(ciphertext1);
  assert.equal(decrypted, pii, 'El texto descifrado debe coincidir con el original.');

  // Detección de alteración (Tampering / Autenticidad GCM)
  const parts = ciphertext1.split(':');
  const alteredCiphertext = `${parts[0]}:${parts[1]}:${parts[2].slice(0, -2)}aa`;
  assert.throws(() => {
    decryptField(alteredCiphertext);
  }, /Fallo de Autenticidad en Descifrado AES-256-GCM/, 'GCM debe lanzar excepción si los datos son adulterados.');
});

test('3. Tokenización de Tarjetas (PCI-DSS) - Aislamiento de PAN', (t) => {
  const cardData = {
    pan: '4532117890124582',
    cardHolder: 'PABLO LINEROS',
    expirationDate: '10/29',
    cvv: '912'
  };

  const { token_pago, mascara_tarjeta, brand } = PaymentVault.tokenizeCard(cardData);

  assert.ok(token_pago.startsWith('tok_norti_vault_'));
  assert.equal(mascara_tarjeta, '************4582');
  assert.equal(brand, 'VISA');

  // Cobro con token
  const charge = PaymentVault.chargeWithToken(token_pago, 19990);
  assert.equal(charge.success, true);
  assert.ok(charge.transactionId.startsWith('tx_auth_'));
});

test('4. Control de Integridad (HMAC-SHA256) - Detección de Modificación', (t) => {
  const userId = 'usr_test_99';
  const points = 750;
  const hmac = generateHMAC(points, userId);

  // Verificación correcta
  const isValid = verifyHMAC(points, userId, hmac);
  assert.equal(isValid, true, 'El HMAC debe ser válido para los datos legítimos.');

  // Verificación con dato adulterado (ej. cambio a 10.000 puntos)
  const isTampered = verifyHMAC(10000, userId, hmac);
  assert.equal(isTampered, false, 'El HMAC debe rechazar un saldo adulterado.');
});

test('5. Integración de Servicios NortiShop - Flujo Completo y Persistencia Cifrada', async (t) => {
  const user = await UserService.registerUser({
    nombre: 'María Gerónimo',
    email: 'maria.geronimo@nortishop.cl',
    password: 'PasswordMaria#2026',
    direccionDespacho: 'Calle Los Flamencos 123, Calama',
    tarjeta: {
      pan: '5412889012345678',
      cardHolder: 'MARIA GERONIMO',
      expirationDate: '08/27',
      cvv: '123'
    }
  });

  // Inspección de persistencia en reposo: NINGÚN dato sensible está en texto plano
  assert.notEqual(user.password_hash, 'PasswordMaria#2026');
  assert.notEqual(user.email_cifrado, 'maria.geronimo@nortishop.cl');
  assert.notEqual(user.direccion_despacho_cifrada, 'Calle Los Flamencos 123, Calama');
  assert.equal(user.mascara_tarjeta, '************5678');

  // Recuperación bajo demanda autorizada
  const profile = UserService.getUserProfile(user.id);
  assert.equal(profile.email, 'maria.geronimo@nortishop.cl');
  assert.equal(profile.direccionDespacho, 'Calle Los Flamencos 123, Calama');

  // Detección de fraude en fidelización
  DB.tamperLoyaltyPoints(user.id, 99999);
  assert.throws(() => {
    LoyaltyService.redeemPoints(user.id, 100);
  }, /Operación Bloqueada por Seguridad/);
});
