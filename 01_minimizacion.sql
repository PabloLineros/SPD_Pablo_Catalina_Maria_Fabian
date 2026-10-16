-- =============================================================================
-- NortiShop — Hito 2 · Paso 1: Esquema rediseñado aplicando MINIMIZACIÓN
-- Motor de referencia: PostgreSQL. Documento de diseño (aún no desplegado).
-- Convenciones:
--   *_cifrado  -> AES-256-GCM (iv:tag:ciphertext), AAD = '<id>:<campo>'
--   *_hmac     -> HMAC-SHA256 con llave propia (índice ciego)
--   [MIN] comentario que documenta la decisión de minimización del campo
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Catálogo (no contiene datos personales)
-- -----------------------------------------------------------------------------
CREATE TABLE productos (
    id                          UUID PRIMARY KEY,
    nombre                      TEXT        NOT NULL,
    descripcion                 TEXT,
    categoria                   VARCHAR(50) NOT NULL,
    precio_clp                  INTEGER     NOT NULL,
    stock                       INTEGER     NOT NULL
);

-- -----------------------------------------------------------------------------
-- Clientes registrados
-- -----------------------------------------------------------------------------
CREATE TABLE users (
    id                          UUID PRIMARY KEY,
    nombre_cifrado              TEXT        NOT NULL,  -- [MIN] Mantener: despacho, boleta, atención
    email_cifrado               TEXT        NOT NULL,  -- [MIN] Mantener: credencial y notificaciones
    email_hmac                  CHAR(64)    NOT NULL UNIQUE, -- [MIN] Nuevo: búsqueda en login sin descifrar
    telefono_cifrado            TEXT        NULL,      -- [MIN] Opcional: ayuda a coordinar entrega, no indispensable
    direccion_despacho_cifrada  TEXT        NOT NULL,  -- [MIN] Mantener: indispensable para entregar
    password_hash               TEXT        NOT NULL,  -- bcrypt costo 12
    guardar_medio_pago          BOOLEAN     NOT NULL DEFAULT FALSE, -- [MIN] Privacidad por defecto: desmarcado
    token_pago                  TEXT        NULL,      -- [MIN] Opcional: solo si guardar_medio_pago = TRUE
    tarjeta_last4               CHAR(4)     NULL,      -- [MIN] Reducido: antes máscara completa (revelaba largo del PAN)
    tarjeta_marca               VARCHAR(20) NULL,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
    -- [MIN] Eliminado/no recolectado: fecha_nacimiento, sexo, foto, RUT (sin finalidad para comprar)
);

-- -----------------------------------------------------------------------------
-- Facturación (solo cuando el cliente solicita factura)
-- -----------------------------------------------------------------------------
CREATE TABLE facturacion (
    id                          UUID PRIMARY KEY,
    user_id                     UUID        NOT NULL REFERENCES users(id),
    rut_facturacion_cifrado     TEXT        NOT NULL,  -- [MIN] Opcional a nivel de flujo: la boleta no lo requiere
    razon_social_cifrada        TEXT        NOT NULL,
    direccion_facturacion_cifrada TEXT      NOT NULL,
    bloqueado                   BOOLEAN     NOT NULL DEFAULT FALSE, -- Ante supresión: se bloquea (obligación tributaria)
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- Pedidos de clientes registrados
-- -----------------------------------------------------------------------------
CREATE TABLE orders (
    id                          UUID PRIMARY KEY,
    user_id                     UUID        NOT NULL REFERENCES users(id),
    total_clp                   INTEGER     NOT NULL CHECK (total_clp > 0),
    transaccion_id              TEXT        NOT NULL,  -- Conciliación con la pasarela
    codigo_autorizacion         TEXT        NOT NULL,  -- [MIN] Mantener: reclamos y conciliación
    tarjeta_last4               CHAR(4)     NULL,      -- [MIN] Reducido a 4 dígitos
    direccion_envio_cifrada     TEXT        NOT NULL,  -- [MIN] Reemplaza 'direccionDespachoDescifradaLogistica' (estaba en texto plano)
    estado                      VARCHAR(30) NOT NULL,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE order_items (
    order_id                    UUID        NOT NULL REFERENCES orders(id),
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
    token_seguimiento           CHAR(36)    NOT NULL UNIQUE, -- UUID v4 enviado por correo (no predecible)
    nombre_invitado_cifrado     TEXT        NULL,      -- NULL tras anonimizar
    email_invitado_cifrado      TEXT        NULL,
    telefono_invitado_cifrado   TEXT        NULL,      -- [MIN] Opcional
    direccion_envio_cifrada     TEXT        NULL,
    total_clp                   INTEGER     NOT NULL,
    estado                      VARCHAR(30) NOT NULL,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    eliminar_contacto_desde     TIMESTAMPTZ NOT NULL   -- [MIN] Plazo: entrega + 90 días (propuesta), luego se anonimiza
);

-- -----------------------------------------------------------------------------
-- Fidelización
-- -----------------------------------------------------------------------------
CREATE TABLE loyalty_accounts (
    user_id                     UUID PRIMARY KEY REFERENCES users(id),
    saldo_puntos                INTEGER     NOT NULL CHECK (saldo_puntos >= 0),
    version                     INTEGER     NOT NULL DEFAULT 1,  -- Evita restaurar saldo antiguo con su firma
    hmac_firma                  CHAR(64)    NOT NULL,            -- HMAC(user_id:version:saldo)
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE historial_puntos (
    id                          BIGSERIAL PRIMARY KEY,
    user_id                     UUID        NOT NULL REFERENCES users(id),
    delta                       INTEGER     NOT NULL,
    motivo                      VARCHAR(30) NOT NULL,  -- compra | canje | bienvenida
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
    -- [MIN] Plazo de conservación: 2 años (propuesta)
);

-- -----------------------------------------------------------------------------
-- Reseñas (públicas)
-- -----------------------------------------------------------------------------
CREATE TABLE resenas (
    id                          UUID PRIMARY KEY,
    user_id                     UUID        NOT NULL REFERENCES users(id), -- Paso 2: se reemplaza por seudónimo
    producto_id                 UUID        NOT NULL REFERENCES productos(id),
    calificacion                SMALLINT    NOT NULL CHECK (calificacion BETWEEN 1 AND 5),
    comentario                  TEXT,                  -- Sanitizado (XSS)
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- Carritos (dato temporal)
-- -----------------------------------------------------------------------------
CREATE TABLE carritos (
    id                          UUID PRIMARY KEY,
    user_id                     UUID        NULL REFERENCES users(id), -- NULL si no ha iniciado sesión
    actualizado_el              TIMESTAMPTZ NOT NULL DEFAULT now()
    -- [MIN] Se elimina tras 30 días sin actividad (propuesta)
);

CREATE TABLE carrito_items (
    carrito_id                  UUID        NOT NULL REFERENCES carritos(id) ON DELETE CASCADE,
    producto_id                 UUID        NOT NULL REFERENCES productos(id),
    cantidad                    INTEGER     NOT NULL,
    PRIMARY KEY (carrito_id, producto_id)
);

-- -----------------------------------------------------------------------------
-- Envíos
-- -----------------------------------------------------------------------------
CREATE TABLE envios (
    id                          UUID PRIMARY KEY,
    order_id                    UUID        NOT NULL,  -- orders.id u orders_invitado.id
    codigo_seguimiento          TEXT        NOT NULL,
    estado_envio                VARCHAR(30) NOT NULL,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- Marketing
-- -----------------------------------------------------------------------------
CREATE TABLE suscripciones_marketing (
    id                          UUID PRIMARY KEY,
    user_id                     UUID        NULL REFERENCES users(id),
    email_cifrado               TEXT        NOT NULL,
    consentimiento_otorgado_el  TIMESTAMPTZ NOT NULL,
    version_texto               VARCHAR(10) NOT NULL,
    revocado_el                 TIMESTAMPTZ NULL
    -- [MIN] Eliminado: nombre_contacto (el boletín funciona solo con el correo)
);

-- =============================================================================
-- Campos ELIMINADOS respecto del diseño anterior (resumen)
--   orders.direccionDespachoDescifradaLogistica  -> reemplazado por direccion_envio_cifrada
--   users.mascara_tarjeta / orders.mascaraTarjetaUsada -> reducidos a *_last4
--   suscripciones_marketing.nombre_contacto      -> eliminado
--   vault.cardHolder, vault.panHash              -> fuera de NortiShop (custodia de la pasarela)
-- =============================================================================
