import crypto from 'node:crypto';

/**
 * Precarga para `npm test` (node --import): las pruebas usan llaves EFÍMERAS generadas en
 * cada ejecución, nunca las del .env del desarrollador ni de producción. Como dotenv no
 * sobrescribe variables ya definidas, el .env local se ignora para estas llaves.
 */
for (const variable of [
  'KEY_CIFRADO_AES256',
  'KEY_HMAC_INTEGRIDAD',
  'KEY_HMAC_INDICE',
  'KEY_HMAC_RESENAS',
  'KEY_HMAC_ANALITICA',
  'KEY_HMAC_MARKETING',
  'KEY_HMAC_AUDITORIA',
  'KEY_HMAC_VERIFICACION'
]) {
  process.env[variable] = crypto.randomBytes(32).toString('hex');
}
process.env.BCRYPT_SALT_ROUNDS = '10'; // mínimo OWASP permitido; acelera las pruebas
process.env.NODE_ENV = 'test';
process.env.LOG_A_CONSOLA = 'false';
