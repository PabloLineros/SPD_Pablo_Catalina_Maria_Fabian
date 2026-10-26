import '../config/env.js';

/**
 * Llavero criptográfico (gestión segura de claves).
 *
 * - Una llave distinta POR FINALIDAD: comprometer una no compromete las demás
 *   (p. ej. la llave de analítica no permite recalcular el índice ciego del login).
 * - Las llaves se leen una sola vez desde el entorno, se validan (Fail-Fast) y se
 *   ELIMINAN de process.env, para que no aparezcan en volcados del entorno ni se
 *   hereden a procesos hijos.
 * - Solo los módulos de src/crypto/ importan este archivo. Ningún servicio, rol ni
 *   endpoint puede obtener una llave (permiso 'llaves:acceder' no asignado a nadie;
 *   ver test/rbac.test.js, que lo verifica estáticamente).
 * - En producción las llaves provendrían de un gestor de secretos / KMS.
 */

export const FINALIDADES = Object.freeze({
  CIFRADO: 'cifrado',       // AES-256-GCM de PII
  INTEGRIDAD: 'integridad', // HMAC de saldos de NortiPuntos
  INDICE: 'indice',         // Índice ciego del email (login sin descifrar)
  RESENAS: 'resenas',       // Seudónimo del autor de reseñas
  ANALITICA: 'analitica',   // Seudónimo en exportaciones analíticas
  MARKETING: 'marketing'    // Seudónimo enviado a la plataforma de correo
});

const VARIABLES = Object.freeze({
  [FINALIDADES.CIFRADO]: 'KEY_CIFRADO_AES256',
  [FINALIDADES.INTEGRIDAD]: 'KEY_HMAC_INTEGRIDAD',
  [FINALIDADES.INDICE]: 'KEY_HMAC_INDICE',
  [FINALIDADES.RESENAS]: 'KEY_HMAC_RESENAS',
  [FINALIDADES.ANALITICA]: 'KEY_HMAC_ANALITICA',
  [FINALIDADES.MARKETING]: 'KEY_HMAC_MARKETING'
});

const llaves = new Map();

function cargarLlaves() {
  const errores = [];
  const vistas = new Set();

  for (const [finalidad, variable] of Object.entries(VARIABLES)) {
    const valor = process.env[variable];
    if (!valor) {
      errores.push(`${variable} no está definida.`);
      continue;
    }
    if (!/^[0-9a-fA-F]{64}$/.test(valor)) {
      errores.push(`${variable} debe tener exactamente 64 caracteres hexadecimales (32 bytes aleatorios).`);
      continue;
    }
    const normalizado = valor.toLowerCase();
    if (vistas.has(normalizado)) {
      errores.push(`${variable} reutiliza el valor de otra llave: cada finalidad requiere una llave propia.`);
    }
    vistas.add(normalizado);
    llaves.set(finalidad, Buffer.from(normalizado, 'hex'));
    delete process.env[variable];
  }

  if (errores.length > 0) {
    console.error('\n❌ ERROR DE CONFIGURACIÓN DE LLAVES:');
    errores.forEach(err => console.error(`  - ${err}`));
    console.error('  Ejecute "npm run generar-env" para crear llaves aleatorias en .env.');
    throw new Error('Fallo en la validación de llaves criptográficas.');
  }
}

cargarLlaves();

/**
 * Entrega la llave de una finalidad a un módulo criptográfico.
 * @param {string} finalidad Una de FINALIDADES.
 * @returns {Buffer}
 */
export function usarLlave(finalidad) {
  const llave = llaves.get(finalidad);
  if (!llave) {
    throw new Error('Finalidad de llave desconocida.');
  }
  return llave;
}

/** Metadatos sin secretos (para evidencias): finalidad y largo en bits. */
export function describirLlavero() {
  return [...llaves.entries()].map(([finalidad, llave]) => ({
    finalidad,
    bits: llave.length * 8
  }));
}
