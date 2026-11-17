-- =============================================================================
-- NortiShop — Hito 2 · Paso 2: SEUDONIMIZACIÓN y ANONIMIZACIÓN
-- Se aplica sobre el esquema minimizado (01_minimizacion.sql).
-- Implementación: ITEM2/src/crypto/pseudonymization.js y src/services/privacyService.js
-- Llaves (en gestor de secretos, NUNCA en la BD; una por finalidad):
--   K_indice     -> email_hmac (login)
--   K_resenas    -> autor de reseñas
--   K_analitica  -> exportaciones para análisis
--   K_marketing  -> envío a plataforma de correo
--   K_integridad -> firma de saldos (no es seudonimización; se lista por completitud)
-- Nota: los HMAC no se pueden calcular en SQL sin exponer la llave al motor; por eso
-- los valores se generan en la capa de aplicación y las migraciones se hacen en 3 pasos
-- (columna NULL -> backfill desde la aplicación -> NOT NULL).
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 2.1 Tabla de equivalencias: ESQUEMA SEPARADO, acceso solo del servicio de privacidad
-- -----------------------------------------------------------------------------
CREATE SCHEMA pseudo;
REVOKE ALL ON SCHEMA pseudo FROM PUBLIC;

CREATE TABLE pseudo.pseudonimos (
    pseudo_id       CHAR(64)    NOT NULL,      -- HMAC(K_<finalidad>, user_id)
    user_id         UUID        NOT NULL,
    finalidad       VARCHAR(20) NOT NULL CHECK (finalidad IN ('resenas','analitica','marketing')),
    creado_el       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (pseudo_id, finalidad)
);
-- Ante supresión de la cuenta se BORRAN las filas del titular: sus reseñas y datos
-- analíticos dejan de ser atribuibles (pasan de seudonimizados a efectivamente anónimos).

-- -----------------------------------------------------------------------------
-- 2.2 Reseñas: el autor se guarda como seudónimo + alias público
-- -----------------------------------------------------------------------------
ALTER TABLE resenas ADD COLUMN autor_pseudo  CHAR(64)    NULL;  -- HMAC(K_resenas, user_id)
ALTER TABLE resenas ADD COLUMN alias_publico VARCHAR(30) NULL;  -- elegido por el cliente
-- (backfill desde la aplicación: autor_pseudo = HMAC(K_resenas, user_id), alias = 'cliente_<n>')
ALTER TABLE resenas ALTER COLUMN autor_pseudo  SET NOT NULL;
ALTER TABLE resenas ALTER COLUMN alias_publico SET NOT NULL;
ALTER TABLE resenas DROP COLUMN user_id;   -- recién ahora, cuando el seudónimo ya existe

-- Vista pública: nunca expone autor_pseudo
CREATE VIEW v_resenas_publicas AS
SELECT producto_id, alias_publico, calificacion, comentario, created_at::date AS fecha
FROM resenas;

-- -----------------------------------------------------------------------------
-- 2.3 Esquema de analítica: solo datos seudonimizados y generalizados
-- -----------------------------------------------------------------------------
CREATE SCHEMA analitica;
REVOKE ALL ON SCHEMA analitica FROM PUBLIC;

CREATE TABLE analitica.compras (
    id                  UUID        PRIMARY KEY,
    cliente_pseudo      CHAR(64)    NOT NULL,  -- HMAC(K_analitica, user_id)
    mes_compra          DATE        NOT NULL,  -- generalización: primer día del mes
    rango_monto         VARCHAR(20) NOT NULL CHECK (rango_monto IN ('0-20k','20-50k','50-100k','100k+')),
    categoria_producto  VARCHAR(50) NOT NULL,  -- generalización del item (1 fila por pedido y categoría)
    comuna              VARCHAR(50) NULL       -- generalización de la dirección
    -- SUPRIMIDOS: order_id, transaccion_id, codigo_autorizacion, tarjeta_last4, dirección, monto exacto
);

CREATE TABLE analitica.movimientos_puntos (
    id                  UUID        PRIMARY KEY,
    cliente_pseudo      CHAR(64)    NOT NULL,  -- mismo seudónimo que analitica.compras
    mes_movimiento      DATE        NOT NULL,
    motivo              VARCHAR(30) NOT NULL,
    delta               INTEGER     NOT NULL
);

-- -----------------------------------------------------------------------------
-- 2.4 Anonimización: reporte de ventas agregado con umbral k = 5
-- -----------------------------------------------------------------------------
CREATE VIEW analitica.v_ventas_por_comuna AS
SELECT COALESCE(comuna, 'SIN_COMUNA') AS comuna, mes_compra, categoria_producto,
       COUNT(DISTINCT cliente_pseudo) AS clientes,
       COUNT(*)                       AS compras
FROM analitica.compras
GROUP BY COALESCE(comuna, 'SIN_COMUNA'), mes_compra, categoria_producto
HAVING COUNT(DISTINCT cliente_pseudo) >= 5;   -- grupos pequeños se suprimen

-- -----------------------------------------------------------------------------
-- 2.5 Marketing: lo que se envía a la plataforma de correo
-- -----------------------------------------------------------------------------
ALTER TABLE suscripciones_marketing ADD COLUMN suscriptor_pseudo   CHAR(64) NULL; -- HMAC(K_marketing, user_id)
ALTER TABLE suscripciones_marketing ADD COLUMN token_desuscripcion UUID     NULL;
UPDATE suscripciones_marketing SET token_desuscripcion = gen_random_uuid() WHERE token_desuscripcion IS NULL;
ALTER TABLE suscripciones_marketing ALTER COLUMN token_desuscripcion SET NOT NULL;
ALTER TABLE suscripciones_marketing ADD CONSTRAINT uq_token_desuscripcion UNIQUE (token_desuscripcion);

-- Exportación: solo consentimientos vigentes; email se descifra en la capa de aplicación al enviar
CREATE VIEW v_export_marketing AS
SELECT id, suscriptor_pseudo, email_cifrado, token_desuscripcion
FROM suscripciones_marketing
WHERE revocado_el IS NULL;

-- -----------------------------------------------------------------------------
-- 2.6 Operador logístico: referencia opaca, sin identificadores internos
-- -----------------------------------------------------------------------------
ALTER TABLE envios ADD COLUMN ref_envio UUID NULL;
UPDATE envios SET ref_envio = gen_random_uuid() WHERE ref_envio IS NULL;
ALTER TABLE envios ALTER COLUMN ref_envio SET NOT NULL;
ALTER TABLE envios ADD CONSTRAINT uq_ref_envio UNIQUE (ref_envio);
-- Al courier se entrega: ref_envio + nombre + dirección + comuna (descifrados al generar la etiqueta).
-- No se entrega: order_id, user_id, email, teléfono, monto.

-- -----------------------------------------------------------------------------
-- 2.7 Anonimización de invitados al vencer el plazo (job programado diario)
--     Se define como función; la ejecuta el planificador con el rol svc_privacidad.
-- -----------------------------------------------------------------------------
CREATE FUNCTION pseudo.anonimizar_invitados_vencidos() RETURNS INTEGER
LANGUAGE sql AS $$
    WITH vencidos AS (
        UPDATE orders_invitado
        SET nombre_invitado_cifrado   = NULL,
            email_invitado_cifrado    = NULL,
            telefono_invitado_cifrado = NULL,
            direccion_envio_cifrada   = NULL
        WHERE eliminar_contacto_desde <= now()
          AND estado IN ('ENTREGADO', 'CANCELADO')
          AND (nombre_invitado_cifrado IS NOT NULL OR email_invitado_cifrado IS NOT NULL
               OR telefono_invitado_cifrado IS NOT NULL OR direccion_envio_cifrada IS NOT NULL)
        RETURNING 1
    )
    SELECT COUNT(*)::INTEGER FROM vencidos;
$$;
-- Se conservan total_clp, estado y fechas con fines contables.

-- -----------------------------------------------------------------------------
-- 2.8 Ambientes de desarrollo y pruebas
-- -----------------------------------------------------------------------------
-- Nunca se restaura una copia de producción en desarrollo. Se usa:
--   a) datos sintéticos (ITEM2/src/dev/escenario.js, dominio .test), o
--   b) la copia generada por privacyService.generarCopiaDesarrollo(): ids regenerados,
--      PII reemplazada por valores ficticios, sin hashes, tokens ni criptogramas.
-- Desarrollo y pruebas usan llaves propias (las pruebas generan llaves efímeras).

-- Permisos: ver 03_rbac.sql
