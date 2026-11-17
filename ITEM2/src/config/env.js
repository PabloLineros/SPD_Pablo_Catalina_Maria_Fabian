import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Cargar variables de entorno desde el archivo .env ubicado en la raíz del proyecto ITEM2.
// dotenv NO sobrescribe variables ya definidas en el entorno (útil para pruebas y producción).
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const envPath = path.resolve(__dirname, '../../.env');

dotenv.config({ path: envPath, quiet: true });

/**
 * Configuración NO secreta de la aplicación.
 * Las llaves criptográficas NO se exponen aquí: las administra exclusivamente
 * src/crypto/keyring.js, que las retira de process.env tras cargarlas.
 */
function validateConfig() {
  const errors = [];

  // Factor de costo de bcrypt (OWASP: >= 10)
  const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10);
  if (isNaN(saltRounds) || saltRounds < 10 || saltRounds > 16) {
    errors.push('BCRYPT_SALT_ROUNDS debe ser un número entero entre 10 y 16 (recomendación OWASP).');
  }

  const sessionTtl = parseInt(process.env.SESSION_TTL_MINUTOS || '30', 10);
  if (isNaN(sessionTtl) || sessionTtl < 1 || sessionTtl > 720) {
    errors.push('SESSION_TTL_MINUTOS debe ser un entero entre 1 y 720.');
  }

  if (errors.length > 0) {
    console.error('\n❌ ERROR DE CONFIGURACIÓN:');
    errors.forEach(err => console.error(`  - ${err}`));
    throw new Error('Fallo en la validación de la configuración de entorno.');
  }

  return Object.freeze({
    NODE_ENV: process.env.NODE_ENV || 'development',
    BCRYPT_ROUNDS: saltRounds,
    SESSION_TTL_MINUTOS: sessionTtl,
    // Política de conservación (propuestas documentadas en 01_minimizacion.sql)
    RETENCION_INVITADO_DIAS: 90,
    // Umbral de anonimización k para reportes agregados
    K_ANONIMATO: 5,
    // Intentos fallidos de login antes de bloquear temporalmente
    MAX_INTENTOS_LOGIN: 5,
    // Ejercicio de derechos: plazo de respuesta (Ley 21.719: 30 días corridos, prorrogable una vez)
    PLAZO_RESPUESTA_DERECHOS_DIAS: 30,
    // Códigos de verificación de un solo uso
    CODIGO_VERIFICACION_MINUTOS: 10,
    CODIGO_VERIFICACION_MAX_INTENTOS: 5,
    // Conservación de la auditoría: 24 meses; luego se purga por lotes con constancia
    RETENCION_AUDITORIA_DIAS: 730,
    // Conservación de los demás registros de trazabilidad (ver auditService.POLITICA_CONSERVACION)
    RETENCION_ALERTAS_DIAS: 730,
    RETENCION_EVIDENCIAS_DIAS: 1825,
    RETENCION_LOGS_APLICACION_DIAS: 90,
    // Horario laboral del personal (alerta ACCESO_FUERA_DE_HORARIO): lunes a sábado, 08:00 a 21:00
    HORARIO_LABORAL: Object.freeze({ zona: 'America/Santiago', desde: 8, hasta: 21, dias: Object.freeze([1, 2, 3, 4, 5, 6]) }),
    // Puerto del servidor HTTP de demostración
    PUERTO: parseInt(process.env.PORT || '3000', 10),
    LOG_A_CONSOLA: process.env.LOG_A_CONSOLA === 'true'
  });
}

export const CONFIG = validateConfig();
