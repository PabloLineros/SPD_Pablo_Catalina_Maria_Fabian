import crypto from 'node:crypto';
import { CONFIG } from '../config/env.js';
import { FINALIDADES_CONSENTIMIENTO, FINALIDADES_OTRAS_BASES } from '../config/finalidades.js';
import { DB, ROLES_BD } from '../db/repository.js';
import { encryptField, decryptField, contexto } from '../crypto/cipher.js';
import { verifyPassword } from '../crypto/hashing.js';
import { hmacHex, compararHmac } from '../crypto/integrity.js';
import { FINALIDADES } from '../crypto/keyring.js';
import { seudonimo } from '../crypto/pseudonymization.js';
import { enviarCorreo } from '../infra/correo.js';
import { autorizar, PERMISOS } from '../security/rbac.js';
import { registrarAuditoria } from '../security/audit.js';
import { errores, AppError } from '../security/errors.js';
import { soloCampos, validar, enmascarar } from '../security/validation.js';
import { aplicarCambiosPerfil } from './userService.js';
import { suprimirCliente, impedimentoSupresion } from './privacyService.js';

/**
 * Ejercicio de derechos del titular: acceso, portabilidad, rectificación y supresión.
 *
 * Flujo (estado y fecha de cada etapa en solicitudes_derechos):
 *   RECIBIDA -> (verificación de identidad) -> VERIFICADA -> EN_EVALUACION -> CERRADA
 *   con resultado EJECUTADA o RECHAZADA (con fundamento). ANULADA si la verificación falla
 *   demasiadas veces o vence.
 *
 * Verificación proporcional al riesgo, sin pedir datos adicionales:
 *   RECTIFICACION (nombre, teléfono, dirección): sesión + contraseña.
 *   RECTIFICACION de email: sesión + contraseña + código enviado al correo NUEVO.
 *   ACCESO, PORTABILIDAD, SUPRESION: sesión + contraseña + código enviado al correo REGISTRADO.
 */

const bd = DB.conectar(ROLES_BD.SVC_APP);
const bdPrivacidad = DB.conectar(ROLES_BD.SVC_PRIVACIDAD);

const TIPOS = ['ACCESO', 'PORTABILIDAD', 'RECTIFICACION', 'SUPRESION'];
const CAMPOS_RECTIFICABLES = ['nombre', 'telefono', 'direccionDespacho', 'comuna', 'email'];
const ABIERTAS = ['RECIBIDA', 'VERIFICADA', 'EN_EVALUACION'];
const ctxUser = (campo, id) => contexto('users', campo, id);
const ahoraIso = () => new Date().toISOString();

function nivelVerificacion(tipo, cambios) {
  if (tipo === 'RECTIFICACION') return cambios && 'email' in cambios ? 'CLAVE+CODIGO_EMAIL_NUEVO' : 'CLAVE';
  return 'CLAVE+CODIGO_EMAIL_REGISTRADO';
}

/** Valida los valores propuestos ANTES de aceptar la solicitud (reglas del sistema). */
function validarCambios(cambios) {
  soloCampos(cambios, { opcionales: CAMPOS_RECTIFICABLES });
  if (Object.keys(cambios).length === 0) throw errores.datoInvalido('Indique al menos un dato a rectificar.');
  if ('nombre' in cambios) validar.nombre(cambios.nombre);
  if ('telefono' in cambios && cambios.telefono !== null) validar.telefono(cambios.telefono);
  if ('direccionDespacho' in cambios) validar.direccion(cambios.direccionDespacho);
  if ('comuna' in cambios) validar.comuna(cambios.comuna);
  if ('email' in cambios) validar.email(cambios.email);
}

function emitirCodigo(solicitud, destinoEmail, destino) {
  const codigo = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  bd.insertar('verificaciones', {
    id: crypto.randomUUID(),
    solicitud_id: solicitud.id,
    codigo_hmac: hmacHex(FINALIDADES.VERIFICACION, `${solicitud.id}:${codigo}`),
    destino,
    expira_el: new Date(Date.now() + CONFIG.CODIGO_VERIFICACION_MINUTOS * 60_000).toISOString(),
    intentos: 0,
    usado: false
  });
  enviarCorreo({
    para: destinoEmail,
    asunto: 'NortiShop: confirma tu solicitud de privacidad',
    cuerpo: `Tu código para confirmar la solicitud de ${solicitud.tipo.toLowerCase()} es ${codigo}. ` +
      `Vence en ${CONFIG.CODIGO_VERIFICACION_MINUTOS} minutos. Si no hiciste esta solicitud, ignora este mensaje y cambia tu contraseña.`
  });
}

function resumen(s) {
  return {
    id: s.id, tipo: s.tipo, estado: s.estado, resultado: s.resultado ?? null,
    campos_solicitados: s.campos_solicitados ? s.campos_solicitados.split(',') : null,
    nivel_verificacion: s.nivel_verificacion, fundamento: s.fundamento ?? null,
    recibida_el: s.recibida_el, verificada_el: s.verificada_el ?? null, evaluada_el: s.evaluada_el ?? null,
    resuelta_el: s.resuelta_el ?? null, cerrada_el: s.cerrada_el ?? null, plazo_vence_el: s.plazo_vence_el
  };
}

function transicion(sesion, solicitud, cambios, evento, resultado = 'EXITO', motivo = null) {
  const actualizada = bd.actualizar('solicitudes_derechos', solicitud.id, cambios);
  registrarAuditoria({ sesion, accion: `derechos:${solicitud.tipo.toLowerCase()}:${evento}`, recurso: `solicitud:${solicitud.id}`, resultado, motivo });
  return actualizada;
}

/** Copia de los datos del titular. Excluye información interna y datos de terceros. */
function construirExportacion(userId, tipo) {
  const u = bd.obtener('users', userId);
  const productos = new Map(bd.seleccionar('productos').map(p => [p.id, p.nombre]));
  const pseudoResenas = seudonimo('resenas', userId);

  const datos = {
    formato: 'nortishop.export.v1',
    tipo,
    generado_el: ahoraIso(),
    titular_id: userId,
    datos_personales: {
      nombre: decryptField(u.nombre_cifrado, ctxUser('nombre_cifrado', userId)),
      email: decryptField(u.email_cifrado, ctxUser('email_cifrado', userId)),
      telefono: u.telefono_cifrado ? decryptField(u.telefono_cifrado, ctxUser('telefono_cifrado', userId)) : null,
      direccion_despacho: decryptField(u.direccion_despacho_cifrada, ctxUser('direccion_despacho_cifrada', userId)),
      comuna: u.comuna,
      mayor_de_edad_declarado_el: u.mayor_edad_declarado_el,
      cuenta_creada_el: u.created_at,
      medio_pago_guardado: u.guardar_medio_pago ? { marca: u.tarjeta_marca, ultimos_4: u.tarjeta_last4 } : null
    },
    pedidos: bd.seleccionar('orders', o => o.user_id === userId).map(o => ({
      id: o.id,
      fecha: o.created_at,
      estado: o.estado,
      total_clp: o.total_clp,
      documento: o.tipo_documento,
      comuna_envio: o.comuna_envio,
      direccion_envio: o.direccion_envio_cifrada ? decryptField(o.direccion_envio_cifrada, contexto('orders', 'direccion_envio_cifrada', o.id)) : null,
      productos: bd.seleccionar('order_items', i => i.order_id === o.id)
        .map(i => ({ producto: productos.get(i.producto_id) ?? i.producto_id, cantidad: i.cantidad, precio_unitario_clp: i.precio_unitario_clp }))
    })),
    datos_facturacion: bd.seleccionar('facturacion', f => f.user_id === userId).map(f => ({
      rut: decryptField(f.rut_facturacion_cifrado, contexto('facturacion', 'rut_facturacion_cifrado', f.id)),
      razon_social: decryptField(f.razon_social_cifrada, contexto('facturacion', 'razon_social_cifrada', f.id)),
      direccion: decryptField(f.direccion_facturacion_cifrada, contexto('facturacion', 'direccion_facturacion_cifrada', f.id))
    })),
    nortipuntos: {
      saldo: bd.obtener('loyalty_accounts', userId)?.saldo_puntos ?? 0,
      movimientos: bd.seleccionar('historial_puntos', h => h.user_id === userId).map(({ created_at, delta, motivo }) => ({ fecha: created_at, delta, motivo }))
    },
    resenas: bdPrivacidad.seleccionar('resenas', r => r.autor_pseudo === pseudoResenas).map(r => ({
      producto: productos.get(r.producto_id) ?? r.producto_id, alias: r.alias_publico, calificacion: r.calificacion, comentario: r.comentario, fecha: r.created_at
    }))
  };

  if (tipo === 'ACCESO') {
    datos.consentimientos = bd.seleccionar('consentimientos_historial', h => h.user_id === userId)
      .map(({ finalidad, accion, version_texto, canal, ocurrido_el }) => ({ finalidad, accion, version_texto, canal, ocurrido_el }));
    datos.solicitudes_de_derechos = bd.seleccionar('solicitudes_derechos', s => s.user_id === userId)
      .map(s => ({ tipo: s.tipo, estado: s.estado, resultado: s.resultado ?? null, recibida_el: s.recibida_el, cerrada_el: s.cerrada_el ?? null }));
    datos.informacion_del_tratamiento = {
      finalidades: [
        ...Object.entries(FINALIDADES_CONSENTIMIENTO).map(([codigo, f]) => ({ codigo, nombre: f.nombre, base: 'CONSENTIMIENTO' })),
        ...Object.entries(FINALIDADES_OTRAS_BASES).map(([codigo, f]) => ({ codigo, nombre: f.nombre, base: f.base }))
      ],
      destinatarios: [
        'Pasarela de pago: datos de la tarjeta (NortiShop solo conserva un token y los últimos 4 dígitos).',
        'Operador logístico: nombre, dirección y comuna de despacho, con una referencia de envío aleatoria.',
        'Plataforma de correo: email y seudónimo, solo con consentimiento MARKETING_EMAIL vigente.'
      ],
      plazos_de_conservacion: {
        cuenta: 'Mientras la cuenta esté activa.',
        documentos_tributarios: '6 años (Código Tributario, art. 17), bloqueados ante supresión.',
        contacto_de_invitados: '90 días desde la entrega.',
        historial_de_puntos: '2 años.',
        auditoria: '24 meses, sin datos personales.'
      },
      contacto_privacidad: 'privacidad@nortishop.test'
    };
  }
  // NO se incluye: hash de contraseña, índice ciego, token de pago, seudónimos, ids de transacción
  // y autorización, referencias de envío, registros de auditoría ni datos de otros titulares.
  return datos;
}

export class RightsService {
  static solicitar(sesion, userId, entrada) {
    autorizar(sesion, PERMISOS.DERECHOS_SOLICITAR, { propietarioId: userId, recurso: `derechos:${userId}` });
    soloCampos(entrada, { obligatorios: ['tipo'], opcionales: ['cambios'] });
    if (!TIPOS.includes(entrada.tipo)) throw errores.datoInvalido(`tipo debe ser uno de: ${TIPOS.join(', ')}.`);
    const user = bd.obtener('users', userId);
    if (!user) throw errores.noEncontrado('Usuario');
    if (bd.buscarUno('solicitudes_derechos', s => s.user_id === userId && s.tipo === entrada.tipo && ABIERTAS.includes(s.estado))) {
      throw errores.conflicto('Ya tiene una solicitud de este tipo en curso.');
    }
    if (entrada.tipo === 'RECTIFICACION') validarCambios(entrada.cambios ?? {});
    else if (entrada.cambios !== undefined) throw errores.campoNoPermitido(['cambios (solo aplica a RECTIFICACION)']);

    const id = crypto.randomUUID();
    const recibida = new Date();
    const solicitud = bd.insertar('solicitudes_derechos', {
      id, user_id: userId, tipo: entrada.tipo, estado: 'RECIBIDA',
      nivel_verificacion: nivelVerificacion(entrada.tipo, entrada.cambios),
      campos_solicitados: entrada.cambios ? Object.keys(entrada.cambios).join(',') : null,
      cambios_cifrados: entrada.cambios ? encryptField(JSON.stringify(entrada.cambios), contexto('solicitudes_derechos', 'cambios_cifrados', id)) : null,
      recibida_el: recibida.toISOString(),
      plazo_vence_el: new Date(recibida.getTime() + CONFIG.PLAZO_RESPUESTA_DERECHOS_DIAS * 86_400_000).toISOString()
    });

    const emailRegistrado = decryptField(user.email_cifrado, ctxUser('email_cifrado', userId));
    let destinoCodigo = null;
    if (solicitud.nivel_verificacion === 'CLAVE') {
      // Sin código: la fila solo lleva la cuenta de intentos fallidos de contraseña.
      bd.insertar('verificaciones', {
        id: crypto.randomUUID(), solicitud_id: id,
        codigo_hmac: hmacHex(FINALIDADES.VERIFICACION, `${id}:${crypto.randomBytes(16).toString('hex')}`),
        destino: 'SOLO_CONTRASENA', expira_el: solicitud.plazo_vence_el, intentos: 0, usado: false
      });
    } else if (solicitud.nivel_verificacion === 'CLAVE+CODIGO_EMAIL_REGISTRADO') {
      emitirCodigo(solicitud, emailRegistrado, 'EMAIL_REGISTRADO');
      destinoCodigo = enmascarar.email(emailRegistrado);
    } else if (solicitud.nivel_verificacion === 'CLAVE+CODIGO_EMAIL_NUEVO') {
      const nuevo = validar.email(entrada.cambios.email);
      emitirCodigo(solicitud, nuevo, 'EMAIL_NUEVO');
      destinoCodigo = enmascarar.email(nuevo);
      // Aviso al correo actual: si no fue el titular, puede reaccionar antes de que se confirme.
      enviarCorreo({ para: emailRegistrado, asunto: 'NortiShop: solicitud de cambio de correo', cuerpo: 'Se solicitó cambiar el correo de tu cuenta. Si no fuiste tú, cambia tu contraseña.' });
    }
    registrarAuditoria({ sesion, accion: `derechos:${entrada.tipo.toLowerCase()}:recibida`, recurso: `solicitud:${id}`, resultado: 'EXITO', motivo: solicitud.campos_solicitados ? `campos=${solicitud.campos_solicitados}` : null });

    return {
      ...resumen(solicitud),
      verificacion: { requiereContrasena: true, requiereCodigo: destinoCodigo !== null, codigoEnviadoA: destinoCodigo }
    };
  }

  /**
   * Verifica la identidad y, si corresponde, evalúa, ejecuta y cierra la solicitud.
   * Devuelve el resumen y, para ACCESO/PORTABILIDAD, la copia de los datos (no se guarda).
   */
  static async confirmar(sesion, userId, solicitudId, entrada) {
    autorizar(sesion, PERMISOS.DERECHOS_SOLICITAR, { propietarioId: userId, recurso: `derechos:${userId}` });
    soloCampos(entrada, { obligatorios: ['password'], opcionales: ['codigo'] });
    let s = bd.obtener('solicitudes_derechos', String(solicitudId));
    if (!s || s.user_id !== userId) throw errores.noEncontrado('Solicitud');
    if (s.estado !== 'RECIBIDA') throw errores.conflicto(`La solicitud está ${s.estado.toLowerCase()}.`);

    // 1. Verificación de identidad
    const user = bd.obtener('users', userId);
    const verif = bd.buscarUno('verificaciones', v => v.solicitud_id === s.id && !v.usado);
    const requiereCodigo = s.nivel_verificacion !== 'CLAVE';
    const claveOk = await verifyPassword(entrada.password, user.password_hash);
    let codigoOk = !requiereCodigo;
    if (requiereCodigo) {
      const vigente = verif && Date.parse(verif.expira_el) > Date.now();
      codigoOk = Boolean(vigente && /^\d{6}$/.test(String(entrada.codigo ?? '')) &&
        compararHmac(hmacHex(FINALIDADES.VERIFICACION, `${s.id}:${entrada.codigo}`), verif.codigo_hmac));
      if (verif && !vigente) {
        bd.actualizar('verificaciones', verif.id, { usado: true });
        transicion(sesion, s, { estado: 'ANULADA', cerrada_el: ahoraIso(), fundamento: 'El código de verificación venció. Puede presentar una nueva solicitud.' }, 'anulada', 'FALLIDO', 'CODIGO_VENCIDO');
        throw errores.datoInvalido('El código venció. Presente una nueva solicitud.');
      }
    }
    if (!claveOk || !codigoOk) {
      const intentos = (verif?.intentos ?? 0) + 1;
      if (verif) bd.actualizar('verificaciones', verif.id, { intentos });
      registrarAuditoria({ sesion, accion: `derechos:${s.tipo.toLowerCase()}:verificacion`, recurso: `solicitud:${s.id}`, resultado: 'FALLIDO', motivo: `intento=${intentos}` });
      if (intentos >= CONFIG.CODIGO_VERIFICACION_MAX_INTENTOS) {
        if (verif) bd.actualizar('verificaciones', verif.id, { usado: true });
        transicion(sesion, s, { estado: 'ANULADA', cerrada_el: ahoraIso(), fundamento: 'Se superó el máximo de intentos de verificación.' }, 'anulada', 'FALLIDO', 'MAX_INTENTOS');
      }
      throw new AppError('CREDENCIALES_INVALIDAS', 'No fue posible verificar su identidad.');
    }
    if (verif) bd.actualizar('verificaciones', verif.id, { usado: true });
    s = transicion(sesion, s, { estado: 'VERIFICADA', verificada_el: ahoraIso() }, 'verificada');

    // 2. Evaluación y 3. ejecución o respuesta fundamentada
    s = bd.actualizar('solicitudes_derechos', s.id, { estado: 'EN_EVALUACION', evaluada_el: ahoraIso() });
    let datos = null;
    let resultado = 'EJECUTADA';
    let fundamento = null;
    let motivoAuditoria = null;

    if (s.tipo === 'ACCESO' || s.tipo === 'PORTABILIDAD') {
      datos = construirExportacion(userId, s.tipo);
      motivoAuditoria = `formato=${datos.formato}; pedidos=${datos.pedidos.length}`;
    } else if (s.tipo === 'RECTIFICACION') {
      const cambios = JSON.parse(decryptField(s.cambios_cifrados, contexto('solicitudes_derechos', 'cambios_cifrados', s.id)));
      try {
        const r = aplicarCambiosPerfil(userId, cambios);
        motivoAuditoria = `campos=${r.modificados.join(',')}; propagado_a=${r.propagado.length}`;
        fundamento = r.propagado.length ? `Actualizado también en: ${r.propagado.map(p => p.split(':')[0]).join(', ')}.` : null;
      } catch (e) {
        if (!(e instanceof AppError)) throw e;
        resultado = 'RECHAZADA';
        fundamento = e.message;
      }
    } else if (s.tipo === 'SUPRESION') {
      const impedimento = impedimentoSupresion(userId);
      if (impedimento) {
        resultado = 'RECHAZADA';
        fundamento = impedimento;
      } else {
        const r = suprimirCliente(userId);
        fundamento = `Datos eliminados. Se conservan bloqueados ${r.facturasBloqueadas} documento(s) tributario(s) y los montos de ${r.pedidosConservados} pedido(s) por obligación legal (6 años).`;
      }
    }

    const cierre = ahoraIso();
    s = transicion(sesion, s, {
      estado: 'CERRADA', resultado, fundamento, resuelta_el: cierre, cerrada_el: cierre,
      cambios_cifrados: null // los valores propuestos ya no son necesarios
    }, resultado === 'EJECUTADA' ? 'ejecutada' : 'rechazada', resultado === 'EJECUTADA' ? 'EXITO' : 'FALLIDO', motivoAuditoria ?? fundamento);

    return { solicitud: resumen(s), datos };
  }

  static misSolicitudes(sesion, userId) {
    autorizar(sesion, PERMISOS.DERECHOS_SOLICITAR, { propietarioId: userId, recurso: `derechos:${userId}` });
    return bd.seleccionar('solicitudes_derechos', s => s.user_id === userId).map(resumen);
  }

  /** Seguimiento para el oficial de privacidad: estados, fechas y plazos, sin datos personales. */
  static listarGestion(sesion) {
    autorizar(sesion, PERMISOS.DERECHOS_GESTIONAR, { recurso: 'solicitudes_derechos' });
    const ahora = Date.now();
    return bd.seleccionar('solicitudes_derechos').map(s => ({
      ...resumen(s), titular_id: s.user_id,
      vencida: ABIERTAS.includes(s.estado) && Date.parse(s.plazo_vence_el) < ahora
    }));
  }
}
