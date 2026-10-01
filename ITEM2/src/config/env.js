import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Cargar variables de entorno desde el archivo .env ubicado en la raíz del proyecto ITEM2
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const envPath = path.resolve(__dirname, '../../.env');

dotenv.config({ path: envPath });

/**
 * Validador estricto de variables de entorno críticas de seguridad.
 * Garantiza que la aplicación falle de forma temprana (Fail-Fast) si las llaves
 * criptográficas no cumplen con los estándares mínimos de longitud y aleatoriedad.
 */
function validateConfig() {
  const errors = [];

  // 1. Validación de Llave AES-256 (32 bytes = 256 bits = 64 caracteres hexadecimales)
  const aesKey = process.env.ENCRYPTION_KEY_AES256;
  if (!aesKey) {
    errors.push('CRÍTICO: ENCRYPTION_KEY_AES256 no está definida en las variables de entorno.');
  } else if (!/^[0-9a-fA-F]{64}$/.test(aesKey)) {
    errors.push('CRÍTICO: ENCRYPTION_KEY_AES256 debe ser una cadena hexadecimal exacta de 64 caracteres (32 bytes / 256 bits).');
  }

  // 2. Validación de Secreto HMAC
  const hmacSecret = process.env.HMAC_SECRET_KEY;
  if (!hmacSecret) {
    errors.push('CRÍTICO: HMAC_SECRET_KEY no está definida en las variables de entorno.');
  } else if (hmacSecret.length < 32) {
    errors.push('ADVERTENCIA DE SEGURIDAD: HMAC_SECRET_KEY debería tener al menos 32 caracteres de entropía.');
  }

  // 3. Validación de Salt Rounds de bcrypt
  const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10);
  if (isNaN(saltRounds) || saltRounds < 10 || saltRounds > 16) {
    errors.push('CRÍTICO: BCRYPT_SALT_ROUNDS debe ser un número entero entre 10 y 16 (recomendación OWASP).');
  }

  if (errors.length > 0) {
    console.error('\n❌ ERROR DE CONFIGURACIÓN DE SEGURIDAD:');
    errors.forEach(err => console.error(`  - ${err}`));
    throw new Error('Fallo en la validación de secretos de entorno.');
  }

  return Object.freeze({
    NODE_ENV: process.env.NODE_ENV || 'development',
    PORT: parseInt(process.env.PORT || '3000', 10),
    AES_KEY: Buffer.from(aesKey, 'hex'),
    HMAC_SECRET: hmacSecret,
    BCRYPT_ROUNDS: saltRounds,
    PAYMENT_GATEWAY_API_KEY: process.env.PAYMENT_GATEWAY_API_KEY || 'gw_default_mock_key'
  });
}

export const CONFIG = validateConfig();
