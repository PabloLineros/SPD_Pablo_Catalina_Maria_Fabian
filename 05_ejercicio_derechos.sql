-- =============================================================================
-- NortiShop — Paso 5: MECANISMOS TÉCNICOS PARA EL EJERCICIO DE DERECHOS
-- Amplía 04_consentimiento_derechos_auditoria.sql según la actividad PR-05:
-- canal sin cuenta, folio, registro de rectificaciones, descargas de un solo uso,
-- comunicación a terceros, oposición, bloqueo y fin del bloqueo legal.
-- Implementado en ITEM2/src/db/repository.js (mismas columnas, tipos y GRANTS).
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 5.1 Canal y seguimiento de solicitudes
-- -----------------------------------------------------------------------------
ALTER TABLE solicitudes_derechos ADD COLUMN folio VARCHAR(20) NULL;          -- DER-2026-000001
UPDATE solicitudes_derechos s SET folio = f.folio                              -- folio para las solicitudes previas
FROM (SELECT id, 'DER-' || to_char(recibida_el, 'YYYY') || '-' ||
             lpad((row_number() OVER (ORDER BY recibida_el))::text, 6, '0') AS folio
      FROM solicitudes_derechos) f
WHERE s.id = f.id;
ALTER TABLE solicitudes_derechos ALTER COLUMN folio SET NOT NULL;
ALTER TABLE solicitudes_derechos ADD CONSTRAINT uq_folio UNIQUE (folio);

ALTER TABLE solicitudes_derechos ALTER COLUMN user_id DROP NOT NULL;          -- NULL si no tiene cuenta
ALTER TABLE solicitudes_derechos ADD COLUMN titular_ref CHAR(64) NULL;        -- índice ciego del correo (sin cuenta)
ALTER TABLE solicitudes_derechos ADD COLUMN canal VARCHAR(25) NOT NULL DEFAULT 'CENTRO_PRIVACIDAD'
    CHECK (canal IN ('CENTRO_PRIVACIDAD','FORMULARIO_SIN_CUENTA'));
ALTER TABLE solicitudes_derechos ADD COLUMN presentada_por VARCHAR(15) NOT NULL DEFAULT 'TITULAR'
    CHECK (presentada_por IN ('TITULAR'));                                    -- representantes: proceso manual del DPO
ALTER TABLE solicitudes_derechos ADD COLUMN objeto VARCHAR(40) NULL;          -- tratamiento (oposición) o motivo (bloqueo)
ALTER TABLE solicitudes_derechos DROP CONSTRAINT IF EXISTS solicitudes_derechos_tipo_check;
ALTER TABLE solicitudes_derechos ADD CONSTRAINT solicitudes_derechos_tipo_check
    CHECK (tipo IN ('ACCESO','PORTABILIDAD','RECTIFICACION','SUPRESION','OPOSICION','BLOQUEO'));
ALTER TABLE solicitudes_derechos DROP CONSTRAINT IF EXISTS solicitudes_derechos_resultado_check;
ALTER TABLE solicitudes_derechos ADD CONSTRAINT solicitudes_derechos_resultado_check
    CHECK (resultado IN ('EJECUTADA','PARCIAL','RECHAZADA'));                 -- PARCIAL: parte se conserva por ley
ALTER TABLE solicitudes_derechos ADD CONSTRAINT ck_titular_identificado
    CHECK (user_id IS NOT NULL OR titular_ref IS NOT NULL);

ALTER TABLE verificaciones DROP CONSTRAINT IF EXISTS verificaciones_destino_check;
ALTER TABLE verificaciones ADD CONSTRAINT verificaciones_destino_check
    CHECK (destino IN ('EMAIL_REGISTRADO','EMAIL_NUEVO','SOLO_CONTRASENA','EMAIL_INFORMADO'));

-- Invitados: índice ciego del correo para atender derechos sin cuenta (NULL al anonimizar)
ALTER TABLE orders_invitado ADD COLUMN email_hmac CHAR(64) NULL;
CREATE INDEX ix_orders_invitado_email_hmac ON orders_invitado (email_hmac);

-- -----------------------------------------------------------------------------
-- 5.2 Acceso y portabilidad: copia cifrada, enlace temporal y de un solo uso
-- -----------------------------------------------------------------------------
CREATE TABLE descargas (
    id                  CHAR(64)    PRIMARY KEY,     -- SHA-256 del token (el token no se guarda)
    solicitud_id        UUID        NOT NULL REFERENCES solicitudes_derechos(id),
    user_id             UUID        NULL,            -- NULL en el canal sin cuenta
    contenido_cifrado   TEXT        NOT NULL,        -- AES-256-GCM, AAD 'descargas.contenido_cifrado:<id>'
    expira_el           TIMESTAMPTZ NOT NULL,        -- 24 horas
    created_at          TIMESTAMPTZ NOT NULL
);
-- Se BORRA al descargarse (un solo uso), al vencer y al suprimir la cuenta.

-- -----------------------------------------------------------------------------
-- 5.3 Rectificación: valor anterior, valor nuevo, quién y cuándo
-- -----------------------------------------------------------------------------
CREATE TABLE rectificaciones (
    id                      UUID PRIMARY KEY,
    solicitud_id            UUID        NOT NULL REFERENCES solicitudes_derechos(id),
    user_id                 UUID        NOT NULL,
    campo                   VARCHAR(30) NOT NULL,
    valor_anterior_cifrado  TEXT        NULL,        -- AES-256-GCM con AAD propio
    valor_nuevo_cifrado     TEXT        NULL,
    actor_id                TEXT        NOT NULL,
    actor_rol               VARCHAR(30) NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL
);
-- Los valores van cifrados porque son datos personales; la auditoría solo registra el nombre del campo.

-- -----------------------------------------------------------------------------
-- 5.4 Propagación a terceros (constancia, sin datos personales)
-- -----------------------------------------------------------------------------
CREATE TABLE comunicaciones_terceros (
    id              UUID PRIMARY KEY,
    tercero         VARCHAR(25) NOT NULL CHECK (tercero IN ('PASARELA_PAGO','PLATAFORMA_CORREO','OPERADOR_LOGISTICO')),
    tipo            VARCHAR(15) NOT NULL CHECK (tipo IN ('RECTIFICACION','SUPRESION','OPOSICION','BLOQUEO')),
    referencia      VARCHAR(200) NOT NULL,           -- ref_envio, seudónimo o id interno
    solicitud_id    UUID NULL REFERENCES solicitudes_derechos(id),
    enviado_el      TIMESTAMPTZ NOT NULL
);

-- -----------------------------------------------------------------------------
-- 5.5 Oposición y bloqueo
-- -----------------------------------------------------------------------------
CREATE TABLE oposiciones (                          -- marca de exclusión por tratamiento
    id              TEXT PRIMARY KEY,                -- '<user_id>:<tratamiento>'
    user_id         UUID        NOT NULL,
    tratamiento     VARCHAR(40) NOT NULL CHECK (tratamiento IN ('ENCUESTAS_SATISFACCION')),
    estado          VARCHAR(10) NOT NULL CHECK (estado IN ('ACTIVA','RETIRADA')),
    desde           TIMESTAMPTZ NOT NULL,
    retirada_el     TIMESTAMPTZ NULL,
    solicitud_id    UUID NULL REFERENCES solicitudes_derechos(id)
);

CREATE TABLE bloqueos (                             -- estado "restringido": se conserva, no se usa
    id                  UUID PRIMARY KEY,
    user_id             UUID        NOT NULL,
    motivo              VARCHAR(25) NOT NULL CHECK (motivo IN ('EXACTITUD_EN_DISPUTA','VIGENCIA_DUDOSA')),
    estado              VARCHAR(10) NOT NULL CHECK (estado IN ('ACTIVO','LEVANTADO')),
    desde               TIMESTAMPTZ NOT NULL,
    levantado_el        TIMESTAMPTZ NULL,
    causa_levantamiento TEXT NULL,
    solicitud_id        UUID NULL REFERENCES solicitudes_derechos(id)
);
CREATE UNIQUE INDEX uq_bloqueo_activo ON bloqueos (user_id) WHERE estado = 'ACTIVO';

-- La exportación de marketing excluye a los titulares bloqueados
CREATE OR REPLACE VIEW v_export_marketing AS
SELECT s.id, s.suscriptor_pseudo, s.email_cifrado, s.token_desuscripcion
FROM suscripciones_marketing s
JOIN consentimientos c ON c.user_id = s.user_id AND c.finalidad = 'MARKETING_EMAIL' AND c.estado = 'OTORGADO'
WHERE c.version_texto = (SELECT version FROM textos_consentimiento
                         WHERE finalidad = 'MARKETING_EMAIL' ORDER BY vigente_desde DESC LIMIT 1)
  AND NOT EXISTS (SELECT 1 FROM bloqueos b WHERE b.user_id = s.user_id AND b.estado = 'ACTIVO');

-- -----------------------------------------------------------------------------
-- 5.6 Conservación legal: se bloquea y, cumplido el plazo, se elimina
-- -----------------------------------------------------------------------------
ALTER TABLE facturacion ADD COLUMN bloqueado_hasta TIMESTAMPTZ NULL;         -- created_at + 6 años (CT art. 17)
-- Job: DELETE FROM facturacion WHERE bloqueado AND bloqueado_hasta <= now();  (antes: orders.facturacion_id = NULL)

-- -----------------------------------------------------------------------------
-- 5.7 Permisos
-- -----------------------------------------------------------------------------
GRANT SELECT, INSERT, DELETE         ON descargas, rectificaciones TO svc_app;
GRANT SELECT, INSERT                 ON comunicaciones_terceros TO svc_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON oposiciones, bloqueos TO svc_app;
GRANT DELETE                         ON facturacion TO svc_app;              -- solo para el job de fin de bloqueo legal
GRANT SELECT                         ON bloqueos TO svc_etl;                  -- el ETL excluye a los bloqueados
-- Ningún rol tiene UPDATE sobre rectificaciones ni comunicaciones_terceros.
