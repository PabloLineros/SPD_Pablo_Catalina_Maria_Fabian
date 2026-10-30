import crypto from 'node:crypto';
import { DB, ROLES_BD } from '../db/repository.js';
import { FINALIDADES_CONSENTIMIENTO, FINALIDADES_OTRAS_BASES, CODIGOS_FINALIDAD } from '../config/finalidades.js';
import { encryptField, decryptField, contexto } from '../crypto/cipher.js';
import { seudonimo, referenciaAleatoria } from '../crypto/pseudonymization.js';
import { PaymentVault } from '../crypto/tokenization.js';
import { autorizar, PERMISOS } from '../security/rbac.js';
import { registrarAuditoria } from '../security/audit.js';
import { errores } from '../security/errors.js';
import { soloCampos, validar } from '../security/validation.js';
import { seudonimoRegistrado } from './privacyService.js';

/**
 * Módulo de gestión del consentimiento.
 *
 * - Una decisión INDEPENDIENTE por finalidad: otorgar o revocar una nunca modifica otra, y el
 *   sistema nunca deduce un consentimiento a partir de otro (no hay "aceptar todo").
 * - Estado actual en `consentimientos` + historial de solo inserción en `consentimientos_historial`
 *   (fecha y hora, finalidad, versión del texto, acción y canal). No se guarda IP, navegador ni
 *   el texto aceptado (se guarda su versión; el texto versionado vive en textos_consentimiento).
 * - Un consentimiento solo HABILITA el tratamiento si está OTORGADO sobre la versión VIGENTE del
 *   texto. Si el texto cambia, queda en REQUIERE_RENOVACION y los procesos dejan de usarlo.
 * - La revocación es efectiva de inmediato y sin efecto retroactivo: se aplican sus efectos en los
 *   procesos dependientes (ver EFECTOS) y queda registrada con fecha y hora.
 */

const bd = DB.conectar(ROLES_BD.SVC_APP);
const bdEtl = DB.conectar(ROLES_BD.SVC_ETL);
const bdPrivacidad = DB.conectar(ROLES_BD.SVC_PRIVACIDAD);

const sha256 = (t) => crypto.createHash('sha256').update(t, 'utf8').digest('hex');
const idConsentimiento = (userId, finalidad) => `${userId}:${finalidad}`;

/** Carga el catálogo de textos versionados si la tabla está vacía (despliegue inicial). */
function asegurarTextos() {
  if (bd.seleccionar('textos_consentimiento').length > 0) return;
  for (const [finalidad, def] of Object.entries(FINALIDADES_CONSENTIMIENTO)) {
    bd.insertar('textos_consentimiento', {
      id: `${finalidad}:${def.version}`, finalidad, version: def.version, texto: def.texto,
      texto_sha256: sha256(def.texto), vigente_desde: '2026-01-01T00:00:00.000Z'
    });
  }
}

export function textoVigente(finalidad) {
  asegurarTextos();
  const versiones = bd.seleccionar('textos_consentimiento', t => t.finalidad === finalidad)
    .sort((a, b) => a.vigente_desde.localeCompare(b.vigente_desde));
  return versiones[versiones.length - 1];
}

function exigirFinalidad(finalidad) {
  if (!CODIGOS_FINALIDAD.includes(finalidad)) {
    throw errores.datoInvalido(`Finalidad desconocida o que no depende del consentimiento. Válidas: ${CODIGOS_FINALIDAD.join(', ')}.`);
  }
  return finalidad;
}

/** ¿El titular tiene consentimiento VIGENTE (otorgado sobre el texto actual) para esta finalidad? */
export function tieneConsentimientoVigente(userId, finalidad) {
  const c = bd.obtener('consentimientos', idConsentimiento(userId, finalidad));
  return c?.estado === 'OTORGADO' && c.version_texto === textoVigente(finalidad).version;
}

/** Conjunto de titulares habilitados para una finalidad, leído con la conexión del proceso que lo usa. */
export function titularesHabilitados(finalidad, conexion = bd) {
  asegurarTextos();
  const versiones = conexion.seleccionar('textos_consentimiento', t => t.finalidad === finalidad)
    .sort((a, b) => a.vigente_desde.localeCompare(b.vigente_desde));
  const vigente = versiones[versiones.length - 1]?.version;
  return new Set(conexion.seleccionar('consentimientos',
    c => c.finalidad === finalidad && c.estado === 'OTORGADO' && c.version_texto === vigente).map(c => c.user_id));
}

// Efectos en los procesos que dependen de cada consentimiento.
const EFECTOS = {
  MARKETING_EMAIL: {
    otorgar(userId) {
      if (bd.buscarUno('suscripciones_marketing', s => s.user_id === userId)) return;
      const user = bd.obtener('users', userId);
      const email = decryptField(user.email_cifrado, contexto('users', 'email_cifrado', userId));
      const id = crypto.randomUUID();
      bd.insertar('suscripciones_marketing', {
        id, user_id: userId,
        suscriptor_pseudo: seudonimoRegistrado('marketing', userId),
        email_cifrado: encryptField(email, contexto('suscripciones_marketing', 'email_cifrado', id)),
        token_desuscripcion: referenciaAleatoria()
      });
    },
    // Se elimina de la lista de envío: la próxima exportación ya no lo incluye.
    revocar(userId) {
      for (const s of bd.seleccionar('suscripciones_marketing', x => x.user_id === userId)) bd.eliminar('suscripciones_marketing', s.id);
      for (const p of bdPrivacidad.seleccionar('pseudo.pseudonimos', x => x.user_id === userId && x.finalidad === 'marketing')) {
        bdPrivacidad.eliminar('pseudo.pseudonimos', p.id);
      }
    }
  },
  GUARDAR_MEDIO_PAGO: {
    otorgar(userId, { tarjeta } = {}) {
      const user = bd.obtener('users', userId);
      if (user.token_pago) return; // ya guardada en el registro
      if (!tarjeta) throw errores.datoInvalido('Para guardar un medio de pago debe ingresar la tarjeta.');
      let pago;
      try {
        pago = PaymentVault.tokenizeCard(tarjeta);
      } catch (e) {
        throw errores.datoInvalido(e.message);
      }
      bd.actualizar('users', userId, { guardar_medio_pago: true, token_pago: pago.token_pago, tarjeta_last4: pago.last4, tarjeta_marca: pago.brand });
    },
    // El token se invalida en la pasarela y NortiShop olvida last4 y marca.
    revocar(userId) {
      const user = bd.obtener('users', userId);
      if (!user) return;
      if (user.token_pago) PaymentVault.revokeToken(user.token_pago);
      bd.actualizar('users', userId, { guardar_medio_pago: false, token_pago: null, tarjeta_last4: null, tarjeta_marca: null });
    }
  },
  ANALITICA_COMPRAS: {
    otorgar() { /* se incorpora en la próxima ejecución del ETL */ },
    // Se borran sus filas de analítica y la equivalencia del seudónimo; el ETL ya no lo incluye.
    revocar(userId) {
      const pseudo = seudonimo('analitica', userId);
      for (const t of ['analitica.compras', 'analitica.movimientos_puntos']) {
        for (const f of bdEtl.seleccionar(t, x => x.cliente_pseudo === pseudo)) bdEtl.eliminar(t, f.id);
      }
      bdPrivacidad.eliminar('pseudo.pseudonimos', `analitica:${pseudo}`);
    }
  }
};

function registrarCambio(userId, finalidad, accion, version, canal, sesion) {
  const ahora = new Date().toISOString();
  bd.insertar('consentimientos_historial', {
    id: crypto.randomUUID(), user_id: userId, finalidad, accion, version_texto: version, canal, ocurrido_el: ahora
  });
  registrarAuditoria({
    sesion, actorId: sesion ? undefined : userId, actorRol: sesion ? undefined : 'CLIENTE',
    accion: `consentimiento:${accion.toLowerCase()}`, recurso: `consentimiento:${finalidad}:${userId}`,
    resultado: 'EXITO', motivo: `version=${version}; canal=${canal}`
  });
  return ahora;
}

/** Otorga (o renueva) un consentimiento. Uso interno: registro y Centro de privacidad. */
export function otorgarConsentimiento(userId, finalidad, { canal, sesion = null, tarjeta, versionVista } = {}) {
  exigirFinalidad(finalidad);
  const vigente = textoVigente(finalidad);
  if (versionVista !== undefined && versionVista !== vigente.version) {
    throw errores.conflicto('El texto de esta finalidad cambió. Revise la versión vigente antes de aceptarla.');
  }
  const actual = bd.obtener('consentimientos', idConsentimiento(userId, finalidad));
  if (actual?.estado === 'OTORGADO' && actual.version_texto === vigente.version) {
    return { finalidad, estado: 'OTORGADO', version: vigente.version };
  }

  EFECTOS[finalidad].otorgar(userId, { tarjeta });
  const accion = actual?.estado === 'OTORGADO' ? 'RENOVADO' : 'OTORGADO';
  const ahora = registrarCambio(userId, finalidad, accion, vigente.version, canal, sesion);
  const fila = { estado: 'OTORGADO', version_texto: vigente.version, otorgado_el: ahora, revocado_el: null, actualizado_el: ahora };
  if (actual) bd.actualizar('consentimientos', actual.id, fila);
  else bd.insertar('consentimientos', { id: idConsentimiento(userId, finalidad), user_id: userId, finalidad, ...fila });
  return { finalidad, estado: 'OTORGADO', version: vigente.version, otorgado_el: ahora };
}

/** Revoca un consentimiento y aplica sus efectos de inmediato. */
export function revocarConsentimiento(userId, finalidad, { canal, sesion = null } = {}) {
  exigirFinalidad(finalidad);
  const actual = bd.obtener('consentimientos', idConsentimiento(userId, finalidad));
  if (!actual || actual.estado === 'REVOCADO') {
    return { finalidad, estado: actual?.estado ?? 'NUNCA_OTORGADO' };
  }
  EFECTOS[finalidad].revocar(userId);
  const ahora = registrarCambio(userId, finalidad, 'REVOCADO', actual.version_texto, canal, sesion);
  bd.actualizar('consentimientos', actual.id, { estado: 'REVOCADO', revocado_el: ahora, actualizado_el: ahora });
  return { finalidad, estado: 'REVOCADO', revocado_el: ahora };
}

/** Supresión de la cuenta: revoca todo con canal SUPRESION (el historial queda, sin datos personales). */
export function revocarTodoPorSupresion(userId) {
  for (const finalidad of CODIGOS_FINALIDAD) revocarConsentimiento(userId, finalidad, { canal: 'SUPRESION' });
}

function estadoDe(userId, finalidad) {
  const c = bd.obtener('consentimientos', idConsentimiento(userId, finalidad));
  const vigente = textoVigente(finalidad);
  let estado = c?.estado ?? 'NUNCA_OTORGADO';
  if (estado === 'OTORGADO' && c.version_texto !== vigente.version) estado = 'REQUIERE_RENOVACION';
  return {
    finalidad,
    nombre: FINALIDADES_CONSENTIMIENTO[finalidad].nombre,
    estado,
    habilita_tratamiento: estado === 'OTORGADO',
    version_vigente: vigente.version,
    texto_vigente: vigente.texto,
    version_aceptada: c?.version_texto ?? null,
    otorgado_el: c?.otorgado_el ?? null,
    revocado_el: c?.revocado_el ?? null,
    procesos_que_dependen: FINALIDADES_CONSENTIMIENTO[finalidad].procesos
  };
}

export class ConsentService {
  /** Panel del Centro de privacidad: estado por finalidad + tratamientos con otras bases. */
  static estado(sesion, userId) {
    autorizar(sesion, PERMISOS.CONSENTIMIENTO_PROPIO, { propietarioId: userId, recurso: `consentimiento:${userId}` });
    return {
      requierenConsentimiento: CODIGOS_FINALIDAD.map(f => estadoDe(userId, f)),
      otrasBases: Object.entries(FINALIDADES_OTRAS_BASES).map(([codigo, d]) => ({ codigo, ...d }))
    };
  }

  static otorgar(sesion, userId, entrada) {
    autorizar(sesion, PERMISOS.CONSENTIMIENTO_PROPIO, { propietarioId: userId, recurso: `consentimiento:${userId}` });
    soloCampos(entrada, { obligatorios: ['finalidad', 'version'], opcionales: ['tarjeta'] });
    return otorgarConsentimiento(userId, entrada.finalidad, {
      canal: 'CENTRO_PRIVACIDAD', sesion, tarjeta: entrada.tarjeta, versionVista: entrada.version
    });
  }

  static revocar(sesion, userId, entrada) {
    autorizar(sesion, PERMISOS.CONSENTIMIENTO_PROPIO, { propietarioId: userId, recurso: `consentimiento:${userId}` });
    soloCampos(entrada, { obligatorios: ['finalidad'] });
    return revocarConsentimiento(userId, entrada.finalidad, { canal: 'CENTRO_PRIVACIDAD', sesion });
  }

  static historial(sesion, userId) {
    autorizar(sesion, PERMISOS.CONSENTIMIENTO_PROPIO, { propietarioId: userId, recurso: `consentimiento:${userId}` });
    return bd.seleccionar('consentimientos_historial', h => h.user_id === userId)
      .sort((a, b) => a.ocurrido_el.localeCompare(b.ocurrido_el))
      .map(({ finalidad, accion, version_texto, canal, ocurrido_el }) => ({ finalidad, accion, version_texto, canal, ocurrido_el }));
  }

  /** Baja con un clic desde el correo: revoca MARKETING_EMAIL sin exigir sesión (token aleatorio). */
  static desuscribirPorToken(token) {
    validar.uuid(token, 'token');
    const s = bd.buscarUno('suscripciones_marketing', x => x.token_desuscripcion === token);
    if (s) revocarConsentimiento(s.user_id, 'MARKETING_EMAIL', { canal: 'ENLACE_CORREO' });
    return { suscrito: false }; // misma respuesta exista o no el token
  }

  /** El oficial de privacidad publica una nueva versión del texto de una finalidad. */
  static publicarVersion(sesion, entrada) {
    autorizar(sesion, PERMISOS.CONSENTIMIENTO_TEXTOS, { recurso: 'textos_consentimiento' });
    soloCampos(entrada, { obligatorios: ['finalidad', 'version', 'texto'] });
    exigirFinalidad(entrada.finalidad);
    const anterior = textoVigente(entrada.finalidad);
    if (entrada.version === anterior.version) throw errores.conflicto('Esa versión ya existe.');
    const texto = String(entrada.texto).trim();
    if (texto.length < 40) throw errores.datoInvalido('El texto informado debe ser claro y completo (mín. 40 caracteres).');
    const vigenteDesde = new Date(Math.max(Date.now(), Date.parse(anterior.vigente_desde) + 1)).toISOString();
    bd.insertar('textos_consentimiento', {
      id: `${entrada.finalidad}:${entrada.version}`, finalidad: entrada.finalidad, version: entrada.version,
      texto, texto_sha256: sha256(texto), vigente_desde: vigenteDesde
    });
    const afectados = bd.seleccionar('consentimientos', c => c.finalidad === entrada.finalidad && c.estado === 'OTORGADO').length;
    registrarAuditoria({ sesion, accion: 'consentimiento:texto_publicado', recurso: `textos:${entrada.finalidad}:${entrada.version}`, resultado: 'EXITO', motivo: `${afectados} consentimientos requieren renovación` });
    return { finalidad: entrada.finalidad, version: entrada.version, consentimientosARenovar: afectados };
  }
}
