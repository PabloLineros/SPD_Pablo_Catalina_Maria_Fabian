import './entorno-pruebas.js';
const { MATRIZ, PERMISOS, ROLES } = await import('../src/security/rbac.js');

/**
 * Imprime la matriz RBAC en Markdown a partir de src/security/rbac.js,
 * para que el informe y el código nunca diverjan.
 */

const roles = Object.values(ROLES);
const propios = new Set(['perfil:propio:leer', 'perfil:propio:editar',
  'pedidos:propios:leer', 'puntos:propios', 'consentimiento:propio', 'derechos:propios:solicitar']);

console.log(`| Permiso | ${roles.join(' | ')} |`);
console.log(`|---|${roles.map(() => ':---:').join('|')}|`);
for (const permiso of Object.values(PERMISOS)) {
  const celdas = roles.map(r => (MATRIZ[r]?.includes(permiso) ? (propios.has(permiso) ? '✅ (solo propio)' : '✅') : '❌'));
  console.log(`| \`${permiso}\` | ${celdas.join(' | ')} |`);
}
