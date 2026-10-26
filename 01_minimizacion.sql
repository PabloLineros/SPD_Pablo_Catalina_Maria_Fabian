-- =============================================================================
-- NortiShop — Hito 2 · Paso 1: Esquema rediseñado aplicando MINIMIZACIÓN
-- Motor de referencia: PostgreSQL. Implementado en ITEM2/src/db/repository.js
-- (base simulada en memoria con las mismas columnas, tipos y restricciones).
-- Convenciones:
--   *_cifrado  -> AES-256-GCM (iv:tag:ciphertext), AAD = '<tabla>.<campo>:<id>'
--   *_hmac     -> HMAC-SHA256 con llave propia (índice ciego)
--   [MIN] comentario que documenta la decisión de minimización del campo
-- =============================================================================

-- Dominio: payload AES-GCM serializado. Impide guardar texto plano en columnas *_cifrado.
CREATE DOMAIN cifrado AS TEXT CHECK (VALUE ~ '^[0-9a-f]{24}:[0-9a-f]{32}:([0-9a-f]{2})*$');
CREATE DOMAIN hmac    AS CHAR(64) CHECK (VALUE ~ '^[0-9a-f]{64}$');

-- -----------------------------------------------------------------------------
-- Catálogo (no contiene datos personales)
-- -----------------------------------------------------------------------------
CREATE TABLE productos (
    id                          UUID PRIMARY KEY,
    nombre                      TEXT        NOT NULL,
    descripcion                 TEXT,
    categoria                   VARCHAR(50) NOT NULL,
    precio_clp                  INTEGER     NOT NULL CHECK (precio_clp > 0),
    stock                       INTEGER     NOT NULL CHECK (stock >= 0)
);

-- -----------------------------------------------------------------------------
-- Clientes registrados
-- -----------------------------------------------------------------------------
CREATE TABLE users (
    id                          UUID PRIMARY KEY,
    nombre_cifrado              cifrado     NOT NULL,  -- [MIN] Mantener: despacho, boleta, atención
    email_cifrado               cifrado     NOT NULL,  -- [MIN] Mantener: credencial y notificaciones
    email_hmac                  hmac        NOT NULL UNIQUE, -- [MIN] Nuevo: búsqueda en login sin descifrar
    telefono_cifrado            cifrado     NULL,      -- [MIN] Opcional: ayuda a coordinar entrega, no indispensable
    direccion_despacho_cifrada  cifrado     NOT NULL,  -- [MIN] Mantener: indispensable para entregar
    comuna                      VARCHAR(50) NOT NULL,  -- [MIN] Mantener en claro: costo de despacho y analítica agregada
                                                       -- [MIN] Eliminado: region (se deriva de la comuna)
    password_hash               TEXT        NOT NULL CHECK (password_hash ~ '^\$2[aby]\$'), -- bcrypt costo 12
    guardar_medio_pago          BOOLEAN     NOT NULL DEFAULT FALSE, -- [MIN] Privacidad por defecto: desmarcado
    token_pago                  TEXT        NULL,      -- [MIN] Opcional: solo si guardar_medio_pago = TRUE
    tarjeta_last4               CHAR(4)     NULL CHECK (tarjeta_last4 ~ '^\d{4}$'), -- [MIN] Reducido: antes máscara completa
    tarjeta_marca               VARCHAR(20) NULL,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (guardar_medio_pago OR (token_pago IS NULL AND tarjeta_last4 IS NULL))
    -- [MIN] No se recolectan (decisión preventiva, validada en el servidor): fecha_nacimiento, sexo, foto, rut
);

-- -----------------------------------------------------------------------------
-- Personal interno (cuentas separadas de los clientes; base del RBAC)
-- -----------------------------------------------------------------------------
CREATE TABLE personal (
    id                          UUID PRIMARY KEY,
    nombre_cifrado              cifrado     NOT NULL,
    email_cifrado               cifrado     NOT NULL,
    email_hmac                  hmac        NOT NULL UNIQUE,
    password_hash               TEXT        NOT NULL,
    rol                         VARCHAR(30) NOT NULL CHECK (rol IN ('ADMINISTRADOR','OFICIAL_PRIVACIDAD','SOPORTE',
                                                                   'LOGISTICA','CATALOGO','MARKETING','ANALISTA')),
    activo                      BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- Facturación (solo cuando el cliente solicita factura)
-- -----------------------------------------------------------------------------
CREATE TABLE facturacion (
    id                          UUID PRIMARY KEY,
    user_id                     UUID        NOT NULL,
    rut_facturacion_cifrado     cifrado     NOT NULL,  -- [MIN] Opcional a nivel de flujo: la boleta no lo requiere
    razon_social_cifrada        cifrado     NOT NULL,
    direccion_facturacion_cifrada cifrado   NOT NULL,
    bloqueado                   BOOLEAN     NOT NULL DEFAULT FALSE, -- Ante supresión: se bloquea (obligación tributaria)
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- Pedidos de clientes registrados
-- -----------------------------------------------------------------------------
CREATE TABLE orders (
    id                          UUID PRIMARY KEY,      -- [MIN] UUID v4 (antes 'ord_' + 8 hex)
    user_id                     UUID        NOT NULL,  -- Sin FK: el pedido sobrevive a la supresión de la cuenta
    total_clp                   INTEGER     NOT NULL CHECK (total_clp > 0), -- Calculado en el servidor
    transaccion_id              TEXT        NOT NULL,  -- Conciliación con la pasarela
    codigo_autorizacion         TEXT        NOT NULL,  -- [MIN] Mantener: reclamos y conciliación
    tarjeta_last4               CHAR(4)     NULL,      -- [MIN] Reducido a 4 dígitos
    direccion_envio_cifrada     cifrado     NULL,      -- [MIN] Reemplaza 'direccion_despacho_descifrada_logistica' (texto plano). NULL tras supresión
    comuna_envio                VARCHAR(50) NOT NULL,  -- [MIN] Generalización usada por logística y analítica
    tipo_documento              VARCHAR(7)  NOT NULL CHECK (tipo_documento IN ('BOLETA','FACTURA')),
    facturacion_id              UUID        NULL REFERENCES facturacion(id), -- Solo si tipo_documento = 'FACTURA'
    estado                      VARCHAR(30) NOT NULL CHECK (estado IN ('PAGADO','PREPARANDO','DESPACHADO','ENTREGADO','CANCELADO')),
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((tipo_documento = 'FACTURA') = (facturacion_id IS NOT NULL))
);

CREATE TABLE order_items (
    order_id                    UUID        NOT NULL,  -- orders.id u orders_invitado.id
    producto_id                 UUID        NOT NULL REFERENCES productos(id),
    cantidad                    INTEGER     NOT NULL CHECK (cantidad > 0),
    precio_unitario_clp         INTEGER     NOT NULL,
    PRIMARY KEY (order_id, producto_id)
);

-- -----------------------------------------------------------------------------
-- Pedidos de clientes invitados (con plazo de conservación)
-- -----------------------------------------------------------------------------
CREATE TABLE orders_invitado (
    id                          UUID PRIMARY KEY,
    token_seguimiento           UUID        NOT NULL UNIQUE, -- UUID v4 enviado por correo (no predecible)
    nombre_invitado_cifrado     cifrado     NULL,      -- NULL tras anonimizar
    email_invitado_cifrado      cifrado     NULL,
    telefono_invitado_cifrado   cifrado     NULL,      -- [MIN] Opcional
    direccion_envio_cifrada     cifrado     NULL,
    comuna_envio                VARCHAR(50) NOT NULL,
    total_clp                   INTEGER     NOT NULL,
    transaccion_id              TEXT        NOT NULL,
    estado                      VARCHAR(30) NOT NULL,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    eliminar_contacto_desde     TIMESTAMPTZ NULL       -- [MIN] Se fija al ENTREGAR/CANCELAR: + 90 días; luego se anonimiza
    -- [MIN] Eliminado: datos_checkout_temporal (la tarjeta va directo a la pasarela; nada se guarda)
);

-- -----------------------------------------------------------------------------
-- Fidelización
-- -----------------------------------------------------------------------------
CREATE TABLE loyalty_accounts (
    user_id                     UUID PRIMARY KEY,
    saldo_puntos                INTEGER     NOT NULL CHECK (saldo_puntos >= 0),
    version                     INTEGER     NOT NULL DEFAULT 1,  -- = nº de movimientos; evita restaurar saldo antiguo con su firma
    hmac_firma                  hmac        NOT NULL,            -- HMAC(K_integridad, user_id:version:saldo)
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE historial_puntos (
    id                          UUID PRIMARY KEY,
    user_id                     UUID        NOT NULL,
    delta                       INTEGER     NOT NULL,
    motivo                      VARCHAR(30) NOT NULL CHECK (motivo IN ('BIENVENIDA','COMPRA','CANJE')),
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
    -- [MIN] Plazo de conservación: 2 años (propuesta)
);

-- -----------------------------------------------------------------------------
-- Reseñas (públicas)
-- -----------------------------------------------------------------------------
CREATE TABLE resenas (
    id                          UUID PRIMARY KEY,
    user_id                     UUID        NOT NULL,  -- Paso 2: se reemplaza por seudónimo
    producto_id                 UUID        NOT NULL REFERENCES productos(id),
    calificacion                SMALLINT    NOT NULL CHECK (calificacion BETWEEN 1 AND 5),
    comentario                  TEXT,                  -- Sanitizado (XSS)
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
    -- [MIN] Paso 2: se publica un alias elegido por el cliente, nunca el nombre real
);

-- -----------------------------------------------------------------------------
-- Carritos (dato temporal)
-- -----------------------------------------------------------------------------
CREATE TABLE carritos (
    id                          UUID PRIMARY KEY,
    user_id                     UUID        NULL,      -- NULL si no ha iniciado sesión
    actualizado_el              TIMESTAMPTZ NOT NULL DEFAULT now()
    -- [MIN] Se elimina tras 30 días sin actividad (propuesta)
);

CREATE TABLE carrito_items (
    carrito_id                  UUID        NOT NULL REFERENCES carritos(id) ON DELETE CASCADE,
    producto_id                 UUID        NOT NULL REFERENCES productos(id),
    cantidad                    INTEGER     NOT NULL CHECK (cantidad > 0),
    PRIMARY KEY (carrito_id, producto_id)
);

-- -----------------------------------------------------------------------------
-- Envíos
-- -----------------------------------------------------------------------------
CREATE TABLE envios (
    id                          UUID PRIMARY KEY,
    order_id                    UUID        NOT NULL,  -- orders.id u orders_invitado.id (uso interno)
    tipo_pedido                 VARCHAR(10) NOT NULL CHECK (tipo_pedido IN ('REGISTRADO','INVITADO')),
    estado_envio                VARCHAR(30) NOT NULL CHECK (estado_envio IN ('PENDIENTE','EN_RUTA','ENTREGADO','CANCELADO')),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- Marketing
-- -----------------------------------------------------------------------------
CREATE TABLE suscripciones_marketing (
    id                          UUID PRIMARY KEY,
    user_id                     UUID        NULL,
    email_cifrado               cifrado     NOT NULL,
    consentimiento_otorgado_el  TIMESTAMPTZ NOT NULL,  -- [MIN] Opt-in explícito con fecha
    version_texto               VARCHAR(10) NOT NULL,  -- Versión del texto aceptado (prueba del consentimiento)
    revocado_el                 TIMESTAMPTZ NULL
    -- [MIN] Eliminado: nombre_contacto (el boletín funciona solo con el correo)
);

-- -----------------------------------------------------------------------------
-- Sesiones y auditoría (soporte del control de acceso)
-- -----------------------------------------------------------------------------
CREATE TABLE sesiones (
    id                          hmac PRIMARY KEY,      -- SHA-256 del token; el token en claro nunca se guarda
    usuario_id                  UUID        NOT NULL,
    tipo                        VARCHAR(8)  NOT NULL CHECK (tipo IN ('CLIENTE','PERSONAL')),
    rol                         VARCHAR(30) NOT NULL,
    expira_el                   TIMESTAMPTZ NOT NULL,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    id                          UUID PRIMARY KEY,
    actor_id                    TEXT        NOT NULL,  -- id interno, nunca email/nombre
    actor_rol                   VARCHAR(30) NOT NULL,
    accion                      VARCHAR(60) NOT NULL,
    recurso                     TEXT        NULL,      -- tipo:id del recurso, sin contenido
    resultado                   VARCHAR(10) NOT NULL CHECK (resultado IN ('PERMITIDO','DENEGADO')),
    motivo                      TEXT        NULL,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =============================================================================
-- Campos ELIMINADOS o REDUCIDOS respecto del esquema original (00_esquema_original.sql)
--   users.region                                  -> eliminado (redundante con comuna)
--   users.telefono                                -> opcional
--   users.mascara_tarjeta / orders.mascara_tarjeta_usada -> reducidos a *_last4
--   users.token_pago                              -> opcional (consentimiento guardar_medio_pago)
--   facturacion.*                                 -> opcional (solo si tipo_documento = FACTURA)
--   orders.direccion_despacho_descifrada_logistica -> reemplazado por direccion_envio_cifrada
--   orders.items (JSON libre)                     -> order_items normalizado
--   orders_invitado.datos_checkout_temporal       -> eliminado
--   orders_invitado.telefono_invitado             -> opcional
--   resenas.user_id                               -> reemplazado por seudónimo (Paso 2)
--   suscripciones_marketing.nombre_contacto       -> eliminado
--   vault.card_holder, vault.pan_hash             -> fuera de NortiShop (custodia de la pasarela)
-- No incorporados (decisión preventiva): fecha_nacimiento, sexo, foto, rut en users
-- =============================================================================
