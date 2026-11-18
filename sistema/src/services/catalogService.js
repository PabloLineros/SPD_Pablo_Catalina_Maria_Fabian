import crypto from 'node:crypto';
import { DB, ROLES_BD } from '../db/repository.js';
import { autorizar, PERMISOS } from '../security/rbac.js';
import { registrarAuditoria } from '../security/audit.js';
import { errores } from '../security/errors.js';
import { soloCampos, validar } from '../security/validation.js';

/**
 * Catálogo (sin datos personales). Lectura pública; escritura solo rol CATALOGO, auditada.
 */

const bd = DB.conectar(ROLES_BD.SVC_APP);

export class CatalogService {
  static listarProductos() {
    return bd.seleccionar('productos').map(({ id, nombre, descripcion, categoria, precio_clp, stock }) =>
      ({ id, nombre, descripcion, categoria, precio_clp, disponible: stock > 0 }));
  }

  static crearProducto(sesion, datos) {
    autorizar(sesion, PERMISOS.CATALOGO_GESTIONAR, { recurso: 'productos' });
    soloCampos(datos, { obligatorios: ['nombre', 'categoria', 'precio_clp', 'stock'], opcionales: ['descripcion'] });
    const id = crypto.randomUUID();
    bd.insertar('productos', {
      id,
      nombre: validar.nombre(datos.nombre),
      descripcion: datos.descripcion ?? null,
      categoria: validar.categoria(datos.categoria),
      precio_clp: validar.enteroPositivo(datos.precio_clp, 'precio_clp'),
      stock: validar.enteroNoNegativo(datos.stock, 'stock')
    });
    registrarAuditoria({ sesion, accion: PERMISOS.CATALOGO_GESTIONAR, recurso: `productos:${id}`, resultado: 'PERMITIDO', motivo: 'crear' });
    return { id };
  }

  static actualizarProducto(sesion, id, cambios) {
    autorizar(sesion, PERMISOS.CATALOGO_GESTIONAR, { recurso: `productos:${id}` });
    soloCampos(cambios, { opcionales: ['precio_clp', 'stock', 'descripcion'] });
    if (!bd.obtener('productos', id)) throw errores.noEncontrado('Producto');
    if ('precio_clp' in cambios) validar.enteroPositivo(cambios.precio_clp, 'precio_clp');
    if ('stock' in cambios) validar.enteroNoNegativo(cambios.stock, 'stock');
    bd.actualizar('productos', id, cambios);
    registrarAuditoria({ sesion, accion: PERMISOS.CATALOGO_GESTIONAR, recurso: `productos:${id}`, resultado: 'PERMITIDO', motivo: `actualizar ${Object.keys(cambios).join(',')}` });
    return { id };
  }

  /**
   * Calcula el total EN EL SERVIDOR a partir del catálogo (nunca se confía en el monto del cliente)
   * y descuenta stock. Uso interno de OrderService.
   */
  static reservarItems(items) {
    if (!Array.isArray(items) || items.length === 0 || items.length > 50) {
      throw errores.datoInvalido('items debe ser una lista de 1 a 50 productos.');
    }
    const lineas = items.map((item) => {
      soloCampos(item, { obligatorios: ['productoId', 'cantidad'] });
      const p = bd.obtener('productos', validar.uuid(item.productoId, 'productoId'));
      if (!p) throw errores.noEncontrado('Producto');
      const cantidad = validar.enteroPositivo(item.cantidad, 'cantidad');
      if (p.stock < cantidad) throw errores.conflicto('Stock insuficiente.');
      return { producto: p, cantidad };
    });
    for (const { producto, cantidad } of lineas) {
      bd.actualizar('productos', producto.id, { stock: producto.stock - cantidad });
    }
    return {
      total: lineas.reduce((acc, l) => acc + l.producto.precio_clp * l.cantidad, 0),
      lineas: lineas.map(l => ({ producto_id: l.producto.id, cantidad: l.cantidad, precio_unitario_clp: l.producto.precio_clp }))
    };
  }
}
