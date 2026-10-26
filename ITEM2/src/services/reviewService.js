import crypto from 'node:crypto';
import { DB, ROLES_BD } from '../db/repository.js';
import { autorizar, PERMISOS } from '../security/rbac.js';
import { errores } from '../security/errors.js';
import { soloCampos, validar, sanitizarTexto } from '../security/validation.js';
import { seudonimoRegistrado } from './privacyService.js';

/**
 * Reseñas públicas con autor SEUDONIMIZADO.
 * - autor_pseudo = HMAC(K_resenas, user_id): permite agrupar reseñas de un mismo autor
 *   (moderación, anti-spam) sin guardar el user_id en la tabla pública.
 * - Lo único visible es el alias que el cliente elige; la vista pública no expone autor_pseudo.
 * - El comentario se sanitiza contra XSS almacenado.
 */

const bdApp = DB.conectar(ROLES_BD.SVC_APP);
const bdPublico = DB.conectar(ROLES_BD.ROL_PUBLICO);

export class ReviewService {
  static publicar(sesion, entrada) {
    autorizar(sesion, PERMISOS.RESENA_PUBLICAR, { recurso: 'resenas' });
    soloCampos(entrada, { obligatorios: ['productoId', 'calificacion', 'alias'], opcionales: ['comentario'] });
    const productoId = validar.uuid(entrada.productoId, 'productoId');
    if (!bdApp.obtener('productos', productoId)) throw errores.noEncontrado('Producto');

    const id = crypto.randomUUID();
    bdApp.insertar('resenas', {
      id,
      autor_pseudo: seudonimoRegistrado('resenas', sesion.usuarioId),
      alias_publico: validar.alias(entrada.alias),
      producto_id: productoId,
      calificacion: validar.calificacion(entrada.calificacion),
      comentario: entrada.comentario ? sanitizarTexto(entrada.comentario) : null,
      created_at: new Date().toISOString()
    });
    return { id };
  }

  /** Lectura pública a través de la vista v_resenas_publicas (rol_publico). */
  static listarPublicas(productoId) {
    return bdPublico.vista('v_resenas_publicas', { productoId: validar.uuid(productoId, 'productoId') });
  }
}
