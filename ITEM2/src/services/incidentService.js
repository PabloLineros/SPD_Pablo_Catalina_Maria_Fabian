import crypto from 'node:crypto';
import { DB, ROLES_BD } from '../db/repository.js';
import { autorizar, PERMISOS, ROLES, ROLES_PERSONAL } from '../security/rbac.js';
import { registrarAuditoria } from '../security/audit.js';
import { redactarTexto } from '../security/logger.js';
import { errores, AppError } from '../security/errors.js';
import { soloCampos, validar } from '../security/validation.js';
import { verificarCadena, anclarAuditoria, eventosEntre } from './auditService.js';
import { cuentasConIntegridadRota } from './loyaltyService.js';
import { cerrarTodasLasSesiones } from './authService.js';

/**
 * Respuesta a incidentes (implementa los procedimientos técnicos del plan PLAN_RESPUESTA_INCIDENTES.md).
 *
 *  Detección:     alertas automáticas (security/detection.js) -> SEGURIDAD decide si abrir incidente.
 *  Análisis:      alcance, período, tipos de datos y titulares afectados; o descarte (falso positivo).
 *  Evidencia:     copia de los eventos de auditoría + verificación de la cadena + ancla, con SHA-256.
 *                 Es OBLIGATORIA antes de contener, para no destruir evidencia al revocar o deshabilitar.
 *  Contención:    revocar sesiones, deshabilitar cuentas del personal, suspender un rol, suspender exportaciones.
 *  Erradicación:  causa raíz y medidas documentadas.
 *  Recuperación:  ADMINISTRADOR, solo si pasan las comprobaciones (auditoría íntegra, puntos íntegros,
 *                 sin alertas críticas abiertas); levanta los controles de contención.
 *  Notificación:  OFICIAL_PRIVACIDAD evalúa criterios (Ley 21.719) y autoriza; se genera el borrador.
 *  Cierre:        requiere recuperación, decisión de notificación y lecciones aprendidas.
 */

const bdSeg = DB.conectar(ROLES_BD.SVC_SEGURIDAD);
const bdApp = DB.conectar(ROLES_BD.SVC_APP);

const SEVERIDADES = ['BAJA', 'MEDIA', 'ALTA', 'CRITICA'];
export const TIPOS_DATOS = Object.freeze({
  IDENTIFICACION: 'nombre e identificador de cuenta',
  CONTACTO: 'correo electrónico y teléfono',
  DIRECCION: 'dirección de despacho',
  CREDENCIALES: 'credenciales de acceso (hash de contraseña o sesiones)',
  FINANCIEROS: 'datos de medios de pago o transacciones',
  HISTORIAL_COMPRAS: 'historial de compras y puntos',
  SENSIBLES: 'datos personales sensibles',
  MENORES: 'datos de niños, niñas o adolescentes'
});
const CONSECUENCIAS = {
  IDENTIFICACION: 'suplantación de identidad o correos fraudulentos dirigidos (phishing)',
  CONTACTO: 'correos o llamadas fraudulentas que usen el nombre de NortiShop',
  DIRECCION: 'exposición del domicilio',
  CREDENCIALES: 'acceso no autorizado a la cuenta',
  FINANCIEROS: 'intentos de fraude con medios de pago',
  HISTORIAL_COMPRAS: 'exposición de hábitos de consumo',
  SENSIBLES: 'discriminación o daño a la vida privada',
  MENORES: 'riesgos agravados para niños, niñas o adolescentes'
};
const RECOMENDACIONES = {
  CONTACTO: 'Desconfíe de mensajes que pidan datos o pagos a nombre de NortiShop.',
  CREDENCIALES: 'Cambie su contraseña de NortiShop y la de otros servicios donde use la misma.',
  FINANCIEROS: 'Revise los movimientos de su tarjeta y avise a su banco ante cargos desconocidos.',
  IDENTIFICACION: 'Desconfíe de mensajes que pidan datos o pagos a nombre de NortiShop.'
};

const ahoraIso = () => new Date().toISOString();
const texto = (v, nombre, min = 10, max = 1000) => {
  const t = String(v ?? '').trim();
  if (t.length < min || t.length > max) throw errores.datoInvalido(`${nombre} debe tener entre ${min} y ${max} caracteres.`);
  return redactarTexto(t); // texto libre del personal: se redacta por si incluye datos personales
};

function obtener(id) {
  const inc = bdSeg.obtener('incidentes', validar.uuid(id, 'incidenteId'));
  if (!inc) throw errores.noEncontrado('Incidente');
  return inc;
}

function exigirEstado(inc, estados) {
  if (!estados.includes(inc.estado)) throw errores.conflicto(`El incidente está ${inc.estado}; esta acción requiere: ${estados.join(' o ')}.`);
}

function registrarAccion(sesion, inc, fase, accion, detalle = null) {
  bdSeg.insertar('incidente_acciones', {
    id: crypto.randomUUID(), incidente_id: inc.id, fase, accion, detalle, actor_id: sesion.usuarioId, created_at: ahoraIso()
  });
  registrarAuditoria({ sesion, accion: `incidente:${accion}`, recurso: `incidente:${inc.id}`, resultado: 'EXITO', motivo: detalle });
}

function activarControl(id, incidenteId, activo) {
  const fila = { activo, incidente_id: incidenteId, actualizado_el: ahoraIso() };
  if (bdSeg.obtener('controles_operacion', id)) bdSeg.actualizar('controles_operacion', id, fila);
  else bdSeg.insertar('controles_operacion', { id, ...fila });
}

export class IncidentService {
  static listarAlertas(sesion, { estado } = {}) {
    autorizar(sesion, PERMISOS.ALERTAS_GESTIONAR, { recurso: 'alertas' });
    return bdSeg.seleccionar('alertas', a => !estado || a.estado === estado);
  }

  static descartarAlerta(sesion, alertaId, entrada) {
    autorizar(sesion, PERMISOS.ALERTAS_GESTIONAR, { recurso: `alerta:${alertaId}` });
    soloCampos(entrada, { obligatorios: ['motivo'] });
    const a = bdSeg.obtener('alertas', validar.uuid(alertaId, 'alertaId'));
    if (!a) throw errores.noEncontrado('Alerta');
    bdSeg.actualizar('alertas', a.id, { estado: 'DESCARTADA' });
    registrarAuditoria({ sesion, accion: 'seguridad:alerta_descartada', recurso: `alerta:${a.id}`, resultado: 'EXITO', motivo: texto(entrada.motivo, 'motivo') });
    return { id: a.id, estado: 'DESCARTADA' };
  }

  /** Detección -> el responsable de seguridad declara el incidente a partir de alertas. */
  static abrir(sesion, entrada) {
    autorizar(sesion, PERMISOS.INCIDENTES_GESTIONAR, { recurso: 'incidentes' });
    soloCampos(entrada, { obligatorios: ['titulo', 'severidad'], opcionales: ['alertas'] });
    if (!SEVERIDADES.includes(entrada.severidad)) throw errores.datoInvalido(`severidad debe ser: ${SEVERIDADES.join(', ')}.`);
    const inc = bdSeg.insertar('incidentes', {
      id: crypto.randomUUID(), titulo: texto(entrada.titulo, 'titulo', 5, 120), severidad: entrada.severidad,
      estado: 'EN_ANALISIS', detectado_el: ahoraIso(), evidencia_preservada: false, responsable_id: sesion.usuarioId
    });
    for (const alertaId of entrada.alertas ?? []) {
      const a = bdSeg.obtener('alertas', validar.uuid(alertaId, 'alertaId'));
      if (a) bdSeg.actualizar('alertas', a.id, { estado: 'ESCALADA', incidente_id: inc.id });
    }
    registrarAccion(sesion, inc, 'DETECCION', 'abierto', `severidad=${inc.severidad}; alertas=${(entrada.alertas ?? []).length}`);
    return inc;
  }

  /** Análisis: alcance e impacto, o descarte como falso positivo. */
  static analizar(sesion, id, entrada) {
    autorizar(sesion, PERMISOS.INCIDENTES_GESTIONAR, { recurso: `incidente:${id}` });
    soloCampos(entrada, { obligatorios: ['confirmado'], opcionales: ['ocurridoDesde', 'ocurridoHasta', 'tiposDatos', 'titularesAfectados', 'severidad'] });
    const inc = obtener(id);
    exigirEstado(inc, ['EN_ANALISIS']);
    if (entrada.confirmado !== true) {
      bdSeg.actualizar('incidentes', inc.id, { estado: 'DESCARTADO', cerrado_el: ahoraIso() });
      registrarAccion(sesion, inc, 'ANALISIS', 'descartado', 'Falso positivo tras el análisis');
      return { id: inc.id, estado: 'DESCARTADO' };
    }
    const tipos = entrada.tiposDatos ?? [];
    if (!Array.isArray(tipos) || tipos.some(t => !(t in TIPOS_DATOS))) {
      throw errores.datoInvalido(`tiposDatos admite: ${Object.keys(TIPOS_DATOS).join(', ')}.`);
    }
    if (entrada.severidad && !SEVERIDADES.includes(entrada.severidad)) throw errores.datoInvalido('severidad inválida.');
    const cambios = {
      ocurrido_desde: entrada.ocurridoDesde ?? null,
      ocurrido_hasta: entrada.ocurridoHasta ?? null,
      tipos_datos: tipos.join(','),
      titulares_afectados: Number.isInteger(entrada.titularesAfectados) ? entrada.titularesAfectados : 0,
      severidad: entrada.severidad ?? inc.severidad
    };
    bdSeg.actualizar('incidentes', inc.id, cambios);
    registrarAccion(sesion, inc, 'ANALISIS', 'alcance_evaluado', `tipos=${cambios.tipos_datos || 'ninguno'}; titulares=${cambios.titulares_afectados}; severidad=${cambios.severidad}`);
    return obtener(inc.id);
  }

  /** Preserva la evidencia ANTES de contener: eventos, verificación de la cadena y ancla. */
  static preservarEvidencia(sesion, id) {
    autorizar(sesion, PERMISOS.INCIDENTES_GESTIONAR, { recurso: `incidente:${id}` });
    const inc = obtener(id);
    exigirEstado(inc, ['EN_ANALISIS', 'CONTENIDO']);
    const desde = inc.ocurrido_desde ?? new Date(Date.parse(inc.detectado_el) - 24 * 3_600_000).toISOString();
    const verificacion = verificarCadena();
    const ancla = anclarAuditoria();
    const contenido = JSON.stringify({ verificacion, ancla, eventos: eventosEntre(desde, ahoraIso()) });
    const sha256 = crypto.createHash('sha256').update(contenido).digest('hex');
    bdSeg.insertar('evidencias', { id: crypto.randomUUID(), incidente_id: inc.id, tipo: 'AUDITORIA', contenido, sha256, created_at: ahoraIso() });
    bdSeg.actualizar('incidentes', inc.id, { evidencia_preservada: true });
    registrarAccion(sesion, inc, 'CONTENCION', 'evidencia_preservada', `sha256=${sha256.slice(0, 16)}; cadena_integra=${verificacion.integra}`);
    return { sha256, eventos: JSON.parse(contenido).eventos.length, cadenaIntegra: verificacion.integra };
  }

  /** Contención: limita el impacto sin borrar nada (las cuentas se deshabilitan, no se eliminan). */
  static contener(sesion, id, entrada) {
    autorizar(sesion, PERMISOS.CONTENCION_EJECUTAR, { recurso: `incidente:${id}` });
    soloCampos(entrada, { obligatorios: ['accion'], opcionales: ['objetivo'] });
    const inc = obtener(id);
    exigirEstado(inc, ['EN_ANALISIS', 'CONTENIDO']);
    if (!inc.evidencia_preservada) throw errores.conflicto('Preserve la evidencia antes de ejecutar acciones de contención.');

    const objetivo = entrada.objetivo;
    switch (entrada.accion) {
      case 'REVOCAR_SESIONES':
        cerrarTodasLasSesiones(validar.uuid(objetivo, 'objetivo'));
        break;
      case 'DESHABILITAR_CUENTA_PERSONAL': {
        if (objetivo === sesion.usuarioId) throw errores.accesoDenegado();
        if (!bdApp.obtener('personal', validar.uuid(objetivo, 'objetivo'))) throw errores.noEncontrado('Cuenta de personal');
        bdApp.actualizar('personal', objetivo, { activo: false });
        cerrarTodasLasSesiones(objetivo);
        break;
      }
      case 'SUSPENDER_ROL':
        if (!ROLES_PERSONAL.includes(objetivo) || objetivo === ROLES.SEGURIDAD) {
          throw errores.datoInvalido('Rol inválido (no se puede suspender el rol que gestiona el incidente).');
        }
        activarControl(`rol_suspendido:${objetivo}`, inc.id, true);
        break;
      case 'SUSPENDER_EXPORTACIONES':
        activarControl('exportaciones_suspendidas', inc.id, true);
        break;
      default:
        throw errores.datoInvalido('accion debe ser REVOCAR_SESIONES, DESHABILITAR_CUENTA_PERSONAL, SUSPENDER_ROL o SUSPENDER_EXPORTACIONES.');
    }
    if (inc.estado === 'EN_ANALISIS') bdSeg.actualizar('incidentes', inc.id, { estado: 'CONTENIDO' });
    registrarAccion(sesion, inc, 'CONTENCION', `contencion:${entrada.accion.toLowerCase()}`, `objetivo=${objetivo ?? 'global'}`);
    return { id: inc.id, estado: 'CONTENIDO', accion: entrada.accion };
  }

  static erradicar(sesion, id, entrada) {
    autorizar(sesion, PERMISOS.INCIDENTES_GESTIONAR, { recurso: `incidente:${id}` });
    soloCampos(entrada, { obligatorios: ['causaRaiz', 'medidas'] });
    const inc = obtener(id);
    exigirEstado(inc, ['CONTENIDO']);
    bdSeg.actualizar('incidentes', inc.id, { estado: 'ERRADICADO', causa_raiz: texto(entrada.causaRaiz, 'causaRaiz') });
    registrarAccion(sesion, inc, 'ERRADICACION', 'causa_eliminada', texto(entrada.medidas, 'medidas'));
    return obtener(inc.id);
  }

  /** Recuperación: el ADMINISTRADOR restablece la operación solo si pasan las comprobaciones. */
  static recuperar(sesion, id) {
    autorizar(sesion, PERMISOS.RECUPERACION_EJECUTAR, { recurso: `incidente:${id}` });
    const inc = obtener(id);
    exigirEstado(inc, ['ERRADICADO']);
    const auditoria = verificarCadena();
    const puntosRotos = cuentasConIntegridadRota();
    const criticasAbiertas = bdSeg.seleccionar('alertas', a => a.severidad === 'CRITICA' && a.estado === 'ABIERTA');
    const comprobaciones = [
      { control: 'Auditoría íntegra', ok: auditoria.integra },
      { control: 'Saldos de NortiPuntos íntegros', ok: puntosRotos.length === 0 },
      { control: 'Sin alertas críticas abiertas sin revisar', ok: criticasAbiertas.length === 0 },
      { control: 'Causa raíz documentada', ok: Boolean(inc.causa_raiz) }
    ];
    const fallidas = comprobaciones.filter(c => !c.ok);
    if (fallidas.length) {
      registrarAuditoria({ sesion, accion: 'recuperacion:rechazada', recurso: `incidente:${inc.id}`, resultado: 'FALLIDO', motivo: fallidas.map(c => c.control).join('; ') });
      throw new AppError('CONFLICTO', `No se puede restablecer la operación. Comprobaciones pendientes: ${fallidas.map(c => c.control).join('; ')}.`);
    }
    for (const c of bdSeg.seleccionar('controles_operacion', x => x.incidente_id === inc.id && x.activo)) activarControl(c.id, inc.id, false);
    bdSeg.actualizar('incidentes', inc.id, { estado: 'RECUPERADO' });
    anclarAuditoria();
    registrarAccion(sesion, inc, 'RECUPERACION', 'operacion_restablecida', comprobaciones.map(c => `${c.control}: OK`).join('; '));
    return { id: inc.id, estado: 'RECUPERADO', comprobaciones };
  }

  /** Criterios de notificación (Ley 21.719): los evalúa el oficial de privacidad. */
  static evaluarNotificacion(sesion, id) {
    autorizar(sesion, PERMISOS.INCIDENTES_NOTIFICAR, { recurso: `incidente:${id}` });
    const inc = obtener(id);
    const tipos = inc.tipos_datos ? inc.tipos_datos.split(',') : [];
    const hayAfectados = (inc.titulares_afectados ?? 0) > 0 && tipos.length > 0;
    const especiales = tipos.filter(t => ['SENSIBLES', 'MENORES', 'FINANCIEROS'].includes(t));
    const fundamentos = [];
    if (hayAfectados) fundamentos.push('Hay datos personales comprometidos con riesgo razonable para los derechos de los titulares: corresponde informar a la Agencia de Protección de Datos Personales sin dilaciones indebidas.');
    else fundamentos.push('No se comprometieron datos personales: no corresponde notificar a la Agencia; se documenta la decisión.');
    if (especiales.length) fundamentos.push(`Involucra ${especiales.join(', ')}: corresponde comunicar también a los titulares afectados.`);
    if (tipos.includes('CREDENCIALES') && !especiales.length) fundamentos.push('Involucra credenciales: se recomienda comunicar a los titulares para que cambien su contraseña, aunque la ley no lo exija en este caso.');
    if (tipos.includes('FINANCIEROS')) fundamentos.push('Involucra medios de pago: avisar también a la pasarela de pago para que gestione el aviso a las marcas de tarjetas (PCI DSS).');
    return {
      notificarAgencia: hayAfectados,
      notificarTitulares: especiales.length > 0,
      comunicacionRecomendada: tipos.includes('CREDENCIALES'),
      fundamentos
    };
  }

  /** El oficial de privacidad autoriza (o descarta) la notificación y obtiene el borrador. */
  static autorizarNotificacion(sesion, id, entrada) {
    autorizar(sesion, PERMISOS.INCIDENTES_NOTIFICAR, { recurso: `incidente:${id}` });
    soloCampos(entrada, { obligatorios: ['agencia', 'titulares', 'justificacion'] });
    if (typeof entrada.agencia !== 'boolean' || typeof entrada.titulares !== 'boolean') throw errores.datoInvalido('agencia y titulares deben ser verdadero o falso.');
    const inc = obtener(id);
    exigirEstado(inc, ['CONTENIDO', 'ERRADICADO', 'RECUPERADO']);
    const ahora = ahoraIso();
    const decision = `agencia=${entrada.agencia}; titulares=${entrada.titulares}; ${texto(entrada.justificacion, 'justificacion')}`;
    bdSeg.actualizar('incidentes', inc.id, {
      decision_notificacion: decision, notificacion_autorizada_por: sesion.usuarioId,
      notificado_agencia_el: entrada.agencia ? ahora : null, notificado_titulares_el: entrada.titulares ? ahora : null
    });
    registrarAccion(sesion, inc, 'NOTIFICACION', 'decision_notificacion', decision);
    return { decision, borrador: entrada.agencia || entrada.titulares ? IncidentService.#borrador(obtener(inc.id)) : null };
  }

  static #borrador(inc) {
    const tipos = inc.tipos_datos ? inc.tipos_datos.split(',') : [];
    const acciones = bdSeg.seleccionar('incidente_acciones', a => a.incidente_id === inc.id && a.fase === 'CONTENCION' && a.accion.startsWith('contencion:'))
      .map(a => a.accion.replace('contencion:', '').replaceAll('_', ' '));
    const recomendaciones = [...new Set(tipos.map(t => RECOMENDACIONES[t]).filter(Boolean))];
    return {
      descripcion: inc.titulo,
      fecha_deteccion: inc.detectado_el,
      periodo: inc.ocurrido_desde ? `${inc.ocurrido_desde} a ${inc.ocurrido_hasta ?? 'en investigación'}` : 'En investigación',
      datos_afectados: tipos.map(t => TIPOS_DATOS[t]),
      titulares_afectados: inc.titulares_afectados ?? 0,
      posibles_consecuencias: tipos.map(t => CONSECUENCIAS[t]),
      medidas_adoptadas: acciones.length ? acciones : ['Investigación en curso'],
      recomendaciones: recomendaciones.length ? recomendaciones : ['Manténgase atento a comunicaciones de NortiShop.'],
      contacto: 'privacidad@nortishop.test (Oficial de Privacidad)'
    };
  }

  static cerrar(sesion, id, entrada) {
    autorizar(sesion, PERMISOS.INCIDENTES_GESTIONAR, { recurso: `incidente:${id}` });
    soloCampos(entrada, { obligatorios: ['lecciones', 'medidasPreventivas'] });
    const inc = obtener(id);
    exigirEstado(inc, ['RECUPERADO']);
    if (!inc.decision_notificacion) throw errores.conflicto('Falta la decisión documentada sobre la notificación (Oficial de Privacidad).');
    bdSeg.actualizar('incidentes', inc.id, { estado: 'CERRADO', lecciones: texto(entrada.lecciones, 'lecciones', 30), cerrado_el: ahoraIso() });
    registrarAccion(sesion, inc, 'CIERRE', 'cerrado', texto(entrada.medidasPreventivas, 'medidasPreventivas'));
    return obtener(inc.id);
  }

  static listar(sesion) {
    autorizar(sesion, PERMISOS.INCIDENTES_LEER, { recurso: 'incidentes' });
    return bdSeg.seleccionar('incidentes');
  }

  static detalle(sesion, id) {
    autorizar(sesion, PERMISOS.INCIDENTES_LEER, { recurso: `incidente:${id}` });
    const inc = obtener(id);
    return {
      ...inc,
      acciones: bdSeg.seleccionar('incidente_acciones', a => a.incidente_id === inc.id),
      evidencias: bdSeg.seleccionar('evidencias', e => e.incidente_id === inc.id).map(({ id: eid, tipo, sha256, created_at }) => ({ id: eid, tipo, sha256, created_at }))
    };
  }
}
