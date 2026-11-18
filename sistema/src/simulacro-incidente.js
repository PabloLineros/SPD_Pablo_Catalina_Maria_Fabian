import { ejecutarSimulacro, compararConVerdad } from './dev/simulacro.js';
import { CAMPOS_REGISTRO } from './security/catalogoAuditoria.js';

/**
 * npm run simulacro — Simulacro de incidente con datos sintéticos y reconstrucción desde la auditoría.
 * Imprime: alertas, línea de tiempo reconstruida, resumen de impacto, respuesta por fases,
 * borrador de notificación y la comparación entre lo reconstruido y lo que realmente hizo el atacante.
 */

const corto = (v) => (v ? String(v).slice(0, 12) : '-');
const hora = (iso) => iso.slice(11, 23);
const titulo = (t) => console.log(`\n${'='.repeat(100)}\n ${t}\n${'='.repeat(100)}`);

const s = await ejecutarSimulacro();
const { reconstruccion: rec, respuesta, verdad, esc } = s;
const nombres = { [esc.ids.clienteA]: 'Ana (cliente)', [esc.ids.clienteB]: 'Bruno (cliente)' };
const quien = (id) => nombres[id] ?? (id ? `${String(id).slice(0, 14)}…` : '-');

titulo('SIMULACRO: relleno de credenciales -> toma de cuenta -> compra con la tarjeta guardada (datos sintéticos)');
console.log('Guion (lo que hizo el atacante, anotado aparte de la auditoría):');
console.log(`  - Probó ${verdad.cuentasProbadas.length} correos de una lista filtrada desde un mismo origen.`);
console.log('  - Entró a la cuenta de Ana (contraseña reutilizada), vio su perfil, cambió la dirección de despacho,');
console.log('    compró con la tarjeta guardada e intentó pedir la portabilidad de sus datos (sin el código del correo).');

titulo('1. DETECCIÓN — alertas abiertas');
for (const a of respuesta.alertas) console.log(`  [${a.severidad.padEnd(5)}] ${a.regla.padEnd(22)} ${a.nivel.padEnd(18)} sujeto=${quien(a.sujeto)}`);

titulo(`2. RECONSTRUCCIÓN desde el origen de la alerta (${rec.resumen.origenes.join(', ')}) — ${rec.linea_tiempo.length} eventos`);
console.log(`  ${'sec'.padEnd(4)} ${'hora UTC'.padEnd(12)} ${'actor'.padEnd(16)} ${'acción'.padEnd(34)} ${'resultado'.padEnd(9)} ${'titular'.padEnd(16)} ${'datos'.padEnd(36)} sesión`);
for (const e of rec.linea_tiempo) {
  console.log(`  ${String(e.secuencia).padEnd(4)} ${hora(e.created_at).padEnd(12)} ${quien(e.actor_id).padEnd(16)} ${e.accion.padEnd(34)} ${e.resultado.padEnd(9)} ${quien(e.titular_ref).padEnd(16)} ${(e.datos ?? '-').slice(0, 36).padEnd(36)} ${corto(e.sesion_ref)}`);
}
const r = rec.resumen;
console.log('\n  Resumen reconstruido:');
console.log(`    Período:                 ${r.desde} a ${r.hasta}`);
console.log(`    Cuentas probadas:        ${r.cuentas_probadas} (reales: ${r.cuentas_reales_probadas.map(quien).join(', ') || 'ninguna'})`);
console.log(`    Cuentas comprometidas:   ${r.cuentas_comprometidas.map(quien).join(', ')}`);
for (const [t, v] of Object.entries(r.titulares)) console.log(`    Datos de ${quien(t)}: ${v.campos.join(', ')}  ->  tipos: ${v.tipos.join(', ')}`);
for (const c of r.cambios) console.log(`    Cambio:                  #${c.secuencia} ${c.accion} ${c.recurso} [${c.datos}] ${c.motivo ?? ''}`);
for (const f of r.frenados) console.log(`    Frenado por un control:  #${f.secuencia} ${f.accion} ${f.resultado} (${f.motivo})`);
console.log(`    Integridad de la cadena: ${rec.integridad.integra ? 'ÍNTEGRA' : 'ALTERADA'} (${rec.integridad.registros} registros)`);

titulo('3. RESPUESTA — fases registradas en la bitácora del incidente');
console.log(`  Purga intentada con el incidente abierto: ${respuesta.purgaDuranteIncidente.purgados} registros borrados (retención extendida desde ${respuesta.purgaDuranteIncidente.retencionExtendidaDesde})`);
console.log(`  Evidencia preservada: sha256=${respuesta.evidencia.sha256.slice(0, 24)}…  eventos=${respuesta.evidencia.eventos}`);
console.log(`  Sesión del atacante revocada: ${respuesta.sesionAtacanteRevocada ? 'sí' : 'no'} · Pedido fraudulento: ${respuesta.pedidoCancelado.estado} (contención CANCELAR_PEDIDO)`);
for (const a of respuesta.detalle.acciones) console.log(`  ${hora(a.created_at)}  ${a.fase.padEnd(13)} ${a.accion.padEnd(32)} ${(a.detalle ?? '').slice(0, 60)}`);
console.log(`  Estado final del incidente: ${respuesta.cierre.estado} · severidad: ${respuesta.detalle.severidad} (abierto como ALTA; sube a CRÍTICA porque se usó la tarjeta guardada)`);

titulo('4. NOTIFICACIÓN — evaluación y borrador (Oficial de Privacidad)');
console.log(`  Agencia: ${respuesta.evaluacion.notificarAgencia ? 'SÍ' : 'NO'} · Titulares: ${respuesta.evaluacion.notificarTitulares ? 'SÍ' : 'NO'}`);
for (const f of respuesta.evaluacion.fundamentos) console.log(`   - ${f}`);
console.log(JSON.stringify(respuesta.notificacion.borrador, null, 2).split('\n').map(l => `  ${l}`).join('\n'));

titulo('5. COMPROBACIÓN — ¿la auditoría permite reconstruir lo que realmente ocurrió?');
const checks = compararConVerdad(s);
for (const c of checks) console.log(`  ${c.ok ? '✔' : '✖'} ${c.control.padEnd(68)} ${c.detalle}`);
console.log(`\n  ${checks.filter(c => c.ok).length}/${checks.length} comprobaciones correctas. Campos de cada registro: ${CAMPOS_REGISTRO.map(([c]) => c).join(', ')}.`);
if (checks.some(c => !c.ok)) process.exitCode = 1;
