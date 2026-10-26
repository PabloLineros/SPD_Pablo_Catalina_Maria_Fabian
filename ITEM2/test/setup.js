// Secretos efímeros y exclusivos del entorno de pruebas; nunca usar en producción.
process.env.NODE_ENV ??= 'test';
process.env.ENCRYPTION_KEY_AES256 ??= '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
process.env.HMAC_SECRET_KEY ??= 'test-only-hmac-secret-not-for-production-2026';
process.env.BCRYPT_SALT_ROUNDS ??= '12';
process.env.PAYMENT_GATEWAY_API_KEY ??= 'test-only-gateway-key';