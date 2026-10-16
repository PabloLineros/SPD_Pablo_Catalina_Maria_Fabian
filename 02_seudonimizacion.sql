-- =============================================================================
-- NortiShop — Hito 2 · Paso 2: SEUDONIMIZACIÓN y ANONIMIZACIÓN
-- Se aplica sobre el esquema minimizado (01_minimizacion.sql).
-- Llaves (en gestor de secretos, NUNCA en la BD; una por finalidad):
--   K_indice     -> email_hmac (login)
--   K_resenas    -> autor de reseñas
--   K_analitica  -> exportaciones para análisis
--   K_marketing  -> envío a plataforma de correo
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 2.1 Tabla de equivalencias: ESQUEMA SEPARADO, acceso solo del servicio de privacidad
-- -----------------------------------------------------------------------------
CREATE SCHEMA pseudo;
REVOKE ALL ON SCHEMA pseudo FROM PUBLIC;

CREATE TABLE pseudo.pseudonimos (
    pseudo_id       CHAR(64)    NOT NULL,      -- HMAC(K_<finalidad>, user_id)
    user_id         UUID        NOT NULL,
    finalidad       VARCHAR(20) NOT NULL,      -- resenas | analitica | marketing
    creado_el       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (pseudo_id, finalidad)
);

-- -----------------------------------------------------------------------------
-- 2.2 Reseñas: el autor se guarda como seudónimo + alias público
-- -----------------------------------------------------------------------------
ALTER TABLE resenas DROP COLUMN user_id;
ALTER TABLE resenas ADD COLUMN autor_pseudo  CHAR(64)    NOT NULL; -- HMAC(K_resenas, user_id)
ALTER TABLE resenas ADD COLUMN alias_publico VARCHAR(30) NOT NULL; -- elegido por el cliente

-- Vista pública: nunca expone autor_pseudo
CREATE VIEW v_resenas_publicas AS
SELECT producto_id, alias_publico, calificacion, comentario, created_at::date AS fecha
FROM resenas;

-- -----------------------------------------------------------------------------
-- 2.3 Esquema de analítica: solo datos seudonimizados y generalizados
-- -----------------------------------------------------------------------------
CREATE SCHEMA analitica;

CREATE TABLE analitica.compras (
    cliente_pseudo      CHAR(64)    NOT NULL,  -- HMAC(K_analitica, user_id)
    mes_compra          DATE        NOT NULL,  -- generalización: primer día del mes
    rango_monto         VARCHAR(20) NOT NULL,  -- '0-20k' | '20-50k' | '50-100k' | '100k+'
    categoria_producto  VARCHAR(50) NOT NULL,  -- generalización del item
    comuna              VARCHAR(50) NULL       -- generalización de la dirección
    -- SUPRIMIDOS: order_id, transaccion_id, codigo_autorizacion, tarjeta_last4, dirección
);

CREATE TABLE analitica.movimientos_puntos (
    cliente_pseudo      CHAR(64)    NOT NULL,  -- mismo seudónimo que analitica.compras
    mes_movimiento      DATE        NOT NULL,
    motivo              VARCHAR(30) NOT NULL,
    delta               INTEGER     NOT NULL
);

-- -----------------------------------------------------------------------------
-- 2.4 Anonimización: reporte de ventas agregado con umbral k = 5
-- -----------------------------------------------------------------------------
CREATE VIEW analitica.v_ventas_por_comuna AS
SELECT comuna, mes_compra, categoria_producto,
       COUNT(DISTINCT cliente_pseudo) AS clientes,
       COUNT(*)                       AS compras
FROM analitica.compras
GROUP BY comuna, mes_compra, categoria_producto
HAVING COUNT(DISTINCT cliente_pseudo) >= 5;   -- grupos pequeños se suprimen

-- -----------------------------------------------------------------------------
-- 2.5 Marketing: lo que se envía a la plataforma de correo
-- -----------------------------------------------------------------------------
ALTER TABLE suscripciones_marketing ADD COLUMN suscriptor_pseudo   CHAR(64) NULL; -- HMAC(K_marketing, user_id)
ALTER TABLE suscripciones_marketing ADD COLUMN token_desuscripcion CHAR(36) NOT NULL UNIQUE; -- aleatorio

-- Exportación: solo consentimientos vigentes; email se descifra en la capa de aplicación al enviar
CREATE VIEW v_export_marketing AS
SELECT suscriptor_pseudo, email_cifrado, token_desuscripcion
FROM suscripciones_marketing
WHERE revocado_el IS NULL;

-- -----------------------------------------------------------------------------
-- 2.6 Operador logístico: referencia opaca, sin identificadores internos
-- -----------------------------------------------------------------------------
ALTER TABLE envios ADD COLUMN ref_envio CHAR(36) NOT NULL UNIQUE; -- aleatoria; es lo único que ve el courier
-- Al courier se entrega: ref_envio + nombre + dirección (descifrados al generar la etiqueta).
-- No se entrega: order_id, user_id, email, teléfono, monto.

-- -----------------------------------------------------------------------------
-- 2.7 Anonimización de invitados al vencer el plazo (job programado diario)
-- -----------------------------------------------------------------------------
UPDATE orders_invitado
SET nombre_invitado_cifrado   = NULL,
    email_invitado_cifrado    = NULL,
    telefono_invitado_cifrado = NULL,
    direccion_envio_cifrada   = NULL
WHERE eliminar_contacto_desde <= now()
  AND estado IN ('ENTREGADO', 'CANCELADO');
-- Se conservan total_clp, estado y fechas con fines contables.

-- -----------------------------------------------------------------------------
-- 2.8 Permisos (resumen; detalle en el modelo RBAC)
-- -----------------------------------------------------------------------------
-- rol_analista   : SELECT solo en esquema analitica. Sin acceso a pseudo ni a tablas operativas.
-- rol_marketing  : SELECT solo en v_export_marketing.
-- rol_publico    : SELECT solo en v_resenas_publicas.
-- svc_privacidad : único con acceso a pseudo.pseudonimos.
-- Las llaves K_* las administra el custodio de llaves, no el DBA.
