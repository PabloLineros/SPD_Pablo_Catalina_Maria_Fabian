/**
 * Base de Datos Simulada en Reposo (Persistencia de NortiShop)
 *
 * Reproduce en memoria el esquema rediseñado (01_minimizacion.sql + 02_seudonimizacion.sql)
 * y los permisos de 03_rbac.sql. Tres controles se aplican en la capa de datos:
 *
 * 1. MINIMIZACIÓN POR ESQUEMA: cada tabla declara una lista blanca de columnas. Insertar o
 *    actualizar una columna no prevista (p. ej. fecha_nacimiento) es rechazado.
 * 2. TIPOS DE PROTECCIÓN: las columnas *_cifrado solo aceptan payloads AES-GCM, las *_hmac/*_pseudo
 *    solo HMAC hexadecimales, password_hash solo hashes bcrypt, tarjeta_last4 solo 4 dígitos.
 *    Equivale a restricciones CHECK: impide guardar texto plano por error.
 * 3. GRANTS POR ROL DE BD: cada conexión se abre con un rol (svc_app, svc_privacidad, svc_etl,
 *    rol_analista, rol_marketing, rol_publico) que solo puede ejecutar las operaciones concedidas.
 */

const T = {
  uuid: (v) => typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v),
  texto: (v) => typeof v === 'string' && v.length <= 1000,
  cifrado: (v) => typeof v === 'string' && /^[0-9a-f]{24}:[0-9a-f]{32}:([0-9a-f]{2})*$/.test(v),
  hmac: (v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v),
  bcrypt: (v) => typeof v === 'string' && /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(v),
  entero: (v) => Number.isInteger(v),
  bool: (v) => typeof v === 'boolean',
  fecha: (v) => typeof v === 'string' && !Number.isNaN(Date.parse(v)),
  last4: (v) => typeof v === 'string' && /^\d{4}$/.test(v)
};

const col = (tipo, { req = false, valores = null } = {}) => ({ tipo, req, valores });
const R = { req: true };

const ESTADOS_PEDIDO = ['PAGADO', 'PREPARANDO', 'DESPACHADO', 'ENTREGADO', 'CANCELADO'];

export const ESQUEMA = Object.freeze({
  productos: {
    columnas: {
      id: col('uuid', R), nombre: col('texto', R), descripcion: col('texto'),
      categoria: col('texto', R), precio_clp: col('entero', R), stock: col('entero', R)
    }
  },
  users: {
    unicos: ['email_hmac'],
    columnas: {
      id: col('uuid', R),
      nombre_cifrado: col('cifrado', R),
      email_cifrado: col('cifrado', R),
      email_hmac: col('hmac', R),
      telefono_cifrado: col('cifrado'),
      direccion_despacho_cifrada: col('cifrado', R),
      comuna: col('texto', R),
      password_hash: col('bcrypt', R),
      guardar_medio_pago: col('bool', R),
      token_pago: col('texto'),
      tarjeta_last4: col('last4'),
      tarjeta_marca: col('texto'),
      created_at: col('fecha', R)
    }
  },
  personal: {
    unicos: ['email_hmac'],
    columnas: {
      id: col('uuid', R),
      nombre_cifrado: col('cifrado', R),
      email_cifrado: col('cifrado', R),
      email_hmac: col('hmac', R),
      password_hash: col('bcrypt', R),
      rol: col('texto', { req: true, valores: ['ADMINISTRADOR', 'OFICIAL_PRIVACIDAD', 'SOPORTE', 'LOGISTICA', 'CATALOGO', 'MARKETING', 'ANALISTA'] }),
      activo: col('bool', R),
      created_at: col('fecha', R)
    }
  },
  facturacion: {
    columnas: {
      id: col('uuid', R), user_id: col('uuid', R),
      rut_facturacion_cifrado: col('cifrado', R),
      razon_social_cifrada: col('cifrado', R),
      direccion_facturacion_cifrada: col('cifrado', R),
      bloqueado: col('bool', R), created_at: col('fecha', R)
    }
  },
  orders: {
    columnas: {
      id: col('uuid', R), user_id: col('uuid', R),
      total_clp: col('entero', R),
      transaccion_id: col('texto', R), codigo_autorizacion: col('texto', R),
      tarjeta_last4: col('last4'),
      direccion_envio_cifrada: col('cifrado'),
      comuna_envio: col('texto', R),
      tipo_documento: col('texto', { req: true, valores: ['BOLETA', 'FACTURA'] }),
      facturacion_id: col('uuid'),
      estado: col('texto', { req: true, valores: ESTADOS_PEDIDO }),
      created_at: col('fecha', R)
    }
  },
  order_items: {
    columnas: {
      id: col('texto', R), order_id: col('uuid', R), producto_id: col('uuid', R),
      cantidad: col('entero', R), precio_unitario_clp: col('entero', R)
    }
  },
  orders_invitado: {
    unicos: ['token_seguimiento'],
    columnas: {
      id: col('uuid', R),
      token_seguimiento: col('uuid', R),
      nombre_invitado_cifrado: col('cifrado'),
      email_invitado_cifrado: col('cifrado'),
      telefono_invitado_cifrado: col('cifrado'),
      direccion_envio_cifrada: col('cifrado'),
      comuna_envio: col('texto', R),
      total_clp: col('entero', R),
      transaccion_id: col('texto', R),
      estado: col('texto', { req: true, valores: ESTADOS_PEDIDO }),
      created_at: col('fecha', R),
      eliminar_contacto_desde: col('fecha')
    }
  },
  loyalty_accounts: {
    pk: 'user_id',
    columnas: {
      user_id: col('uuid', R), saldo_puntos: col('entero', R), version: col('entero', R),
      hmac_firma: col('hmac', R), updated_at: col('fecha', R)
    }
  },
  historial_puntos: {
    columnas: {
      id: col('uuid', R), user_id: col('uuid', R), delta: col('entero', R),
      motivo: col('texto', { req: true, valores: ['BIENVENIDA', 'COMPRA', 'CANJE'] }),
      created_at: col('fecha', R)
    }
  },
  resenas: {
    columnas: {
      id: col('uuid', R), autor_pseudo: col('hmac', R), alias_publico: col('texto', R),
      producto_id: col('uuid', R), calificacion: col('entero', R),
      comentario: col('texto'), created_at: col('fecha', R)
    }
  },
  suscripciones_marketing: {
    unicos: ['token_desuscripcion'],
    columnas: {
      id: col('uuid', R), user_id: col('uuid'), suscriptor_pseudo: col('hmac'),
      email_cifrado: col('cifrado', R), consentimiento_otorgado_el: col('fecha', R),
      version_texto: col('texto', R), revocado_el: col('fecha'),
      token_desuscripcion: col('uuid', R)
    }
  },
  envios: {
    unicos: ['ref_envio'],
    columnas: {
      id: col('uuid', R), order_id: col('uuid', R),
      tipo_pedido: col('texto', { req: true, valores: ['REGISTRADO', 'INVITADO'] }),
      ref_envio: col('uuid', R),
      estado_envio: col('texto', { req: true, valores: ['PENDIENTE', 'EN_RUTA', 'ENTREGADO', 'CANCELADO'] }),
      updated_at: col('fecha', R)
    }
  },
  sesiones: {
    columnas: {
      id: col('hmac', R), usuario_id: col('uuid', R),
      tipo: col('texto', { req: true, valores: ['CLIENTE', 'PERSONAL'] }),
      rol: col('texto', R), expira_el: col('fecha', R), created_at: col('fecha', R)
    }
  },
  audit_log: {
    columnas: {
      id: col('uuid', R), actor_id: col('texto', R), actor_rol: col('texto', R),
      accion: col('texto', R), recurso: col('texto'), resultado: col('texto', { req: true, valores: ['PERMITIDO', 'DENEGADO'] }),
      motivo: col('texto'), created_at: col('fecha', R)
    }
  },
  'pseudo.pseudonimos': {
    columnas: {
      id: col('texto', R), pseudo_id: col('hmac', R), user_id: col('uuid', R),
      finalidad: col('texto', { req: true, valores: ['resenas', 'analitica', 'marketing'] }),
      creado_el: col('fecha', R)
    }
  },
  'analitica.compras': {
    columnas: {
      id: col('uuid', R), cliente_pseudo: col('hmac', R), mes_compra: col('texto', R),
      rango_monto: col('texto', { req: true, valores: ['0-20k', '20-50k', '50-100k', '100k+'] }),
      categoria_producto: col('texto', R), comuna: col('texto')
    }
  },
  'analitica.movimientos_puntos': {
    columnas: {
      id: col('uuid', R), cliente_pseudo: col('hmac', R), mes_movimiento: col('texto', R),
      motivo: col('texto', R), delta: col('entero', R)
    }
  }
});

export const ROLES_BD = Object.freeze({
  SVC_APP: 'svc_app',               // Backend transaccional
  SVC_PRIVACIDAD: 'svc_privacidad', // Único con acceso a pseudo.* ; jobs de anonimización
  SVC_ETL: 'svc_etl',               // Carga seudonimizada hacia analitica.*
  ROL_ANALISTA: 'rol_analista',     // Solo esquema analitica
  ROL_MARKETING: 'rol_marketing',   // Solo v_export_marketing
  ROL_PUBLICO: 'rol_publico'        // Solo v_resenas_publicas
});

// S = SELECT, I = INSERT, U = UPDATE, D = DELETE. Lo no listado está denegado.
const GRANTS = Object.freeze({
  [ROLES_BD.SVC_APP]: {
    productos: 'SIU', users: 'SIUD', personal: 'SIU', facturacion: 'SIU', orders: 'SIU', order_items: 'SI',
    orders_invitado: 'SIU', loyalty_accounts: 'SIUD', historial_puntos: 'SID', resenas: 'I',
    suscripciones_marketing: 'SIUD', envios: 'SIU', sesiones: 'SID', audit_log: 'SI'
  },
  [ROLES_BD.SVC_PRIVACIDAD]: { 'pseudo.pseudonimos': 'SID', orders_invitado: 'SU' },
  [ROLES_BD.SVC_ETL]: {
    orders: 'S', order_items: 'S', productos: 'S', historial_puntos: 'S',
    'analitica.compras': 'SID', 'analitica.movimientos_puntos': 'SID'
  },
  [ROLES_BD.ROL_ANALISTA]: { 'analitica.compras': 'S', 'analitica.movimientos_puntos': 'S' },
  [ROLES_BD.ROL_MARKETING]: {},
  [ROLES_BD.ROL_PUBLICO]: {}
});

const GRANTS_VISTAS = Object.freeze({
  v_resenas_publicas: [ROLES_BD.ROL_PUBLICO, ROLES_BD.SVC_APP],
  v_export_marketing: [ROLES_BD.ROL_MARKETING],
  'analitica.v_ventas_por_comuna': [ROLES_BD.ROL_ANALISTA]
});

function errorBD(codigo, mensaje) {
  const e = new Error(mensaje);
  e.code = codigo;
  return e;
}

const copiar = (fila) => (fila ? structuredClone(fila) : null);

class MotorBD {
  constructor() {
    this.reiniciar();
  }

  reiniciar() {
    this.tablas = new Map(Object.keys(ESQUEMA).map(t => [t, new Map()]));
  }

  validarFila(tabla, fila, { parcial = false } = {}) {
    const def = ESQUEMA[tabla];
    const desconocidas = Object.keys(fila).filter(c => !(c in def.columnas));
    if (desconocidas.length > 0) {
      throw errorBD('BD_COLUMNA_NO_PERMITIDA', `Columna(s) no permitida(s) en ${tabla}: ${desconocidas.join(', ')}`);
    }
    for (const [nombre, spec] of Object.entries(def.columnas)) {
      const valor = fila[nombre];
      const ausente = valor === undefined || valor === null;
      if (ausente) {
        if (spec.req && (!parcial || nombre in fila)) {
          throw errorBD('BD_NOT_NULL', `${tabla}.${nombre} es obligatorio.`);
        }
        continue;
      }
      if (!T[spec.tipo](valor) || (spec.valores && !spec.valores.includes(valor))) {
        throw errorBD('BD_TIPO_INVALIDO', `${tabla}.${nombre} no cumple el tipo de protección '${spec.tipo}'.`);
      }
    }
  }

  validarUnicos(tabla, fila, pkActual) {
    const def = ESQUEMA[tabla];
    for (const columna of def.unicos ?? []) {
      if (fila[columna] === undefined || fila[columna] === null) continue;
      for (const [pk, existente] of this.tablas.get(tabla)) {
        if (pk !== pkActual && existente[columna] === fila[columna]) {
          throw errorBD('BD_UNICO', `Valor duplicado en ${tabla}.${columna}.`);
        }
      }
    }
  }
}

class Conexion {
  constructor(motor, rol) {
    if (!(rol in GRANTS)) throw errorBD('BD_ROL_DESCONOCIDO', 'Rol de base de datos desconocido.');
    this.motor = motor;
    this.rol = rol;
  }

  #exigir(tabla, op) {
    if (!(tabla in ESQUEMA)) throw errorBD('BD_TABLA_DESCONOCIDA', `Tabla desconocida: ${tabla}`);
    if (!GRANTS[this.rol][tabla]?.includes(op)) {
      throw errorBD('BD_PERMISO_DENEGADO', `permiso denegado para ${this.rol}: ${op} en ${tabla}`);
    }
  }

  insertar(tabla, fila) {
    this.#exigir(tabla, 'I');
    this.motor.validarFila(tabla, fila);
    const pk = fila[ESQUEMA[tabla].pk ?? 'id'];
    if (this.motor.tablas.get(tabla).has(pk)) throw errorBD('BD_UNICO', `Clave primaria duplicada en ${tabla}.`);
    this.motor.validarUnicos(tabla, fila, pk);
    this.motor.tablas.get(tabla).set(pk, copiar(fila));
    return copiar(fila);
  }

  actualizar(tabla, pk, cambios) {
    this.#exigir(tabla, 'U');
    const actual = this.motor.tablas.get(tabla).get(pk);
    if (!actual) throw errorBD('BD_NO_ENCONTRADO', `Registro no encontrado en ${tabla}.`);
    this.motor.validarFila(tabla, cambios, { parcial: true });
    const nueva = { ...actual, ...cambios };
    this.motor.validarUnicos(tabla, nueva, pk);
    this.motor.tablas.get(tabla).set(pk, copiar(nueva));
    return copiar(nueva);
  }

  obtener(tabla, pk) {
    this.#exigir(tabla, 'S');
    return copiar(this.motor.tablas.get(tabla).get(pk));
  }

  seleccionar(tabla, filtro = () => true) {
    this.#exigir(tabla, 'S');
    return [...this.motor.tablas.get(tabla).values()].filter(filtro).map(copiar);
  }

  buscarUno(tabla, filtro) {
    return this.seleccionar(tabla, filtro)[0] ?? null;
  }

  eliminar(tabla, pk) {
    this.#exigir(tabla, 'D');
    return this.motor.tablas.get(tabla).delete(pk);
  }

  /** Vistas: se ejecutan con privilegios del dueño, pero solo exponen columnas no sensibles. */
  vista(nombre, opciones = {}) {
    if (!GRANTS_VISTAS[nombre]?.includes(this.rol)) {
      throw errorBD('BD_PERMISO_DENEGADO', `permiso denegado para ${this.rol}: SELECT en ${nombre}`);
    }
    const t = (n) => [...this.motor.tablas.get(n).values()].map(copiar);

    if (nombre === 'v_resenas_publicas') {
      return t('resenas')
        .filter(r => !opciones.productoId || r.producto_id === opciones.productoId)
        .map(r => ({
          producto_id: r.producto_id,
          alias_publico: r.alias_publico,
          calificacion: r.calificacion,
          comentario: r.comentario,
          fecha: r.created_at.slice(0, 10)
        }));
    }
    if (nombre === 'v_export_marketing') {
      return t('suscripciones_marketing')
        .filter(s => s.revocado_el === null || s.revocado_el === undefined)
        .map(s => ({ suscriptor_pseudo: s.suscriptor_pseudo, email_cifrado: s.email_cifrado, id: s.id, token_desuscripcion: s.token_desuscripcion }));
    }
    if (nombre === 'analitica.v_ventas_por_comuna') {
      const k = opciones.k ?? 5;
      const grupos = new Map();
      for (const c of t('analitica.compras')) {
        const clave = `${c.comuna ?? 'SIN_COMUNA'}|${c.mes_compra}|${c.categoria_producto}`;
        const g = grupos.get(clave) ?? { comuna: c.comuna ?? 'SIN_COMUNA', mes_compra: c.mes_compra, categoria_producto: c.categoria_producto, clientes: new Set(), compras: 0 };
        g.clientes.add(c.cliente_pseudo);
        g.compras += 1;
        grupos.set(clave, g);
      }
      return [...grupos.values()]
        .filter(g => g.clientes.size >= k) // HAVING COUNT(DISTINCT cliente_pseudo) >= k
        .map(g => ({ comuna: g.comuna, mes_compra: g.mes_compra, categoria_producto: g.categoria_producto, clientes: g.clientes.size, compras: g.compras }));
    }
    throw errorBD('BD_TABLA_DESCONOCIDA', `Vista desconocida: ${nombre}`);
  }
}

class BaseDeDatos {
  #motor = new MotorBD();

  /** Abre una conexión con un rol de base de datos (credencial distinta por servicio). */
  conectar(rol) {
    return new Conexion(this.#motor, rol);
  }

  /**
   * Simula a un atacante (o DBA) con acceso físico a los archivos de la BD: ve TODO,
   * sin pasar por GRANTS. Se usa solo como evidencia de qué queda expuesto en reposo.
   */
  simularAccesoFisico() {
    return Object.fromEntries([...this.#motor.tablas].map(([t, filas]) => [t, [...filas.values()].map(copiar)]));
  }

  /** Simula manipulación directa de una fila (ataque a la integridad). Solo para pruebas/demo. */
  manipularFilaDirecto(tabla, pk, cambios) {
    const fila = this.#motor.tablas.get(tabla).get(pk);
    if (!fila) throw errorBD('BD_NO_ENCONTRADO', 'Registro no encontrado.');
    this.#motor.tablas.get(tabla).set(pk, { ...fila, ...cambios });
  }

  reiniciar() {
    this.#motor.reiniciar();
  }
}

export const DB = new BaseDeDatos();
