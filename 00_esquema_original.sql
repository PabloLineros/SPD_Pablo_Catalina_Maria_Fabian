-- =============================================================================
-- NortiShop — Hito 2 · Paso 0: ESQUEMA ORIGINAL (antes del rediseño)
-- Motor de referencia: PostgreSQL. Reconstruido SOLO a partir de fuentes previas:
--   [INV]  Informe de Análisis de Datos Personales (inventario de datos, 5-oct-2026)
--   [IT1]  Tabla por Campo Sensible (Ítem I)
--   [V1]   Código v1 del Ítem II (repository.js, services/*, tokenization.js)
-- Sirve como línea base para la comparación con 01_minimizacion.sql.
-- Convención: [RIESGO] problema de privacidad/seguridad que motiva un cambio.
-- =============================================================================

CREATE TABLE productos (                            -- [IT1] precio, stock, descripcion_producto
    id                  UUID PRIMARY KEY,
    nombre              TEXT        NOT NULL,
    descripcion         TEXT,
    precio              INTEGER     NOT NULL,
    stock               INTEGER     NOT NULL
);

CREATE TABLE users (                                -- [INV] DB.users / [V1] UserService.registerUser
    id                  TEXT PRIMARY KEY,           -- 'usr_<uuid>'
    nombre_cifrado      TEXT        NOT NULL,       -- AES-GCM SIN AAD: un criptograma puede copiarse a otro registro
    email_cifrado       TEXT        NOT NULL,       -- [RIESGO] sin índice: el login descifraba TODOS los emails para buscar uno
    telefono            TEXT        NOT NULL,       -- [IT1] [RIESGO] obligatorio sin ser indispensable
    direccion_despacho_cifrada TEXT NOT NULL,       -- AES-GCM sin AAD
    comuna              VARCHAR(50) NOT NULL,       -- [IT1]
    region              VARCHAR(50) NOT NULL,       -- [IT1] [RIESGO] redundante: se deriva de la comuna
    password_hash       TEXT        NOT NULL,       -- bcrypt costo 12
    token_pago          TEXT        NOT NULL,       -- [RIESGO] la tarjeta se guardaba siempre, sin opción de no hacerlo
    mascara_tarjeta     VARCHAR(19) NOT NULL,       -- [RIESGO] '************4582' revela el largo del PAN
    tarjeta_marca       VARCHAR(20) NOT NULL,       -- [RIESGO] toda tarjeta no-5/no-3 se clasificaba VISA
    created_at          TIMESTAMPTZ NOT NULL
);

CREATE TABLE facturacion (                          -- [IT1] direccion_facturacion, rut_facturacion
    id                      UUID PRIMARY KEY,
    user_id                 TEXT NOT NULL REFERENCES users(id),
    rut_facturacion         TEXT NOT NULL,          -- [RIESGO] el diseño no distinguía boleta de factura
    direccion_facturacion   TEXT NOT NULL
);

CREATE TABLE orders (                               -- [INV] DB.orders / [V1] OrderService.processOrder
    id                                  TEXT PRIMARY KEY,   -- 'ord_<8 hex>' (corto)
    user_id                             TEXT NOT NULL REFERENCES users(id),
    items                               JSONB NOT NULL,     -- Nombres de productos en texto libre
    total_amount                        INTEGER NOT NULL,   -- [RIESGO] el monto lo enviaba el cliente
    transaccion_id                      TEXT NOT NULL,
    codigo_autorizacion                 TEXT NOT NULL,      -- [RIESGO] generado con Math.random
    mascara_tarjeta_usada               VARCHAR(19),        -- [RIESGO] máscara completa
    direccion_despacho_descifrada_logistica TEXT NOT NULL,  -- [INV][RIESGO] ¡dirección en TEXTO PLANO!
    estado                              VARCHAR(40) NOT NULL,
    created_at                          TIMESTAMPTZ NOT NULL
);

CREATE TABLE orders_invitado (                      -- [IT1] Cliente invitado
    id_orden_invitado       UUID PRIMARY KEY,       -- token UUID v4 de seguimiento
    nombre_invitado         TEXT NOT NULL,
    email_invitado          TEXT NOT NULL,
    telefono_invitado       TEXT NOT NULL,          -- [RIESGO] obligatorio
    direccion_envio_invitado TEXT NOT NULL,
    datos_checkout_temporal JSONB,                  -- [RIESGO] volcado del formulario de checkout
    resumen_compra          JSONB NOT NULL
    -- [INV][RIESGO] plazo de conservación "No indicado": se guardaba indefinidamente
);

CREATE TABLE loyalty_accounts (                     -- [INV] DB.loyaltyAccounts
    user_id             TEXT PRIMARY KEY REFERENCES users(id),
    saldo_puntos        INTEGER NOT NULL,
    hmac_firma          CHAR(64) NOT NULL,          -- HMAC(user_id:saldo). [RIESGO] sin versión: admite repetición
    ultima_actualizacion TIMESTAMPTZ NOT NULL
);

CREATE TABLE historial_puntos (                     -- [IT1] historial_puntos (no implementado en V1)
    id                  BIGSERIAL PRIMARY KEY,
    user_id             TEXT NOT NULL REFERENCES users(id),
    delta               INTEGER NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE resenas (                              -- [IT1] comentario_resena, calificacion, id_producto
    id                  UUID PRIMARY KEY,
    user_id             TEXT NOT NULL REFERENCES users(id), -- [RIESGO] vínculo directo con la identidad
    id_producto         UUID NOT NULL REFERENCES productos(id),
    calificacion        SMALLINT NOT NULL,
    comentario_resena   TEXT
);

CREATE TABLE carritos (                             -- [IT1] id_carrito, productos, cantidades
    id_carrito          UUID PRIMARY KEY,
    user_id             TEXT REFERENCES users(id),
    productos           JSONB NOT NULL
    -- [RIESGO] sin expiración
);

CREATE TABLE envios (                               -- [IT1] estado_envio, codigo_seguimiento
    id                  UUID PRIMARY KEY,
    order_id            TEXT NOT NULL,              -- [RIESGO] el operador logístico recibía el id interno
    codigo_seguimiento  TEXT NOT NULL,
    estado_envio        VARCHAR(30) NOT NULL
);

CREATE TABLE suscripciones_marketing (              -- [IT1] email_suscripcion, nombre_contacto
    id                  UUID PRIMARY KEY,
    email_suscripcion   TEXT NOT NULL,
    nombre_contacto     TEXT NOT NULL               -- [RIESGO] innecesario para enviar un boletín
    -- [RIESGO] el consentimiento se mencionaba, pero no había columnas para registrarlo
);

-- Bóveda de pagos simulada DENTRO del proceso de NortiShop ([INV] Map local de PaymentVault)
CREATE TABLE vault (
    token_pago          TEXT PRIMARY KEY,
    pan_hash            CHAR(64) NOT NULL,          -- [INV][RIESGO] SHA-256 sin sal de un PAN: reversible por fuerza bruta
    card_holder         TEXT NOT NULL,              -- [INV] titular
    expiration_date     VARCHAR(5) NOT NULL,        -- [INV] vencimiento
    brand               VARCHAR(20) NOT NULL
);

-- Control de acceso original ([INV] Conclusiones: "control de accesos insuficiente"):
-- el repositorio no tenía roles ni permisos; cualquier servicio leía y escribía todas las
-- tablas, no existía auditoría, plazos de conservación ni procedimiento de supresión.
