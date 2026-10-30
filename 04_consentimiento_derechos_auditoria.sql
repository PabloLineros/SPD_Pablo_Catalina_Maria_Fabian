-- =============================================================================
-- NortiShop — Paso 4: CONSENTIMIENTO, DERECHOS, AUDITORÍA E INCIDENTES
-- Motor de referencia: PostgreSQL. Se aplica sobre 01, 02 y 03.
-- Implementado en ITEM2/src/db/repository.js (mismas columnas, tipos y GRANTS).
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 4.1 Mayoría de edad: solo la declaración y su fecha (nunca la fecha de nacimiento)
-- -----------------------------------------------------------------------------
ALTER TABLE users ADD COLUMN mayor_edad_declarado_el TIMESTAMPTZ NULL;
UPDATE users SET mayor_edad_declarado_el = created_at WHERE mayor_edad_declarado_el IS NULL;
ALTER TABLE users ALTER COLUMN mayor_edad_declarado_el SET NOT NULL;

-- -----------------------------------------------------------------------------
-- 4.2 Módulo de consentimiento
-- -----------------------------------------------------------------------------
CREATE TABLE textos_consentimiento (
    id              TEXT PRIMARY KEY,                -- '<finalidad>:<version>'
    finalidad       VARCHAR(40) NOT NULL CHECK (finalidad IN ('MARKETING_EMAIL','GUARDAR_MEDIO_PAGO','ANALITICA_COMPRAS')),
    version         VARCHAR(10) NOT NULL,
    texto           TEXT        NOT NULL,            -- texto informado exacto
    texto_sha256    CHAR(64)    NOT NULL,            -- prueba de qué texto se mostró
    vigente_desde   TIMESTAMPTZ NOT NULL,
    UNIQUE (finalidad, version)
);

-- Estado ACTUAL: una fila por titular y finalidad
CREATE TABLE consentimientos (
    id              TEXT PRIMARY KEY,                -- '<user_id>:<finalidad>'
    user_id         UUID        NOT NULL,
    finalidad       VARCHAR(40) NOT NULL,
    estado          VARCHAR(10) NOT NULL CHECK (estado IN ('OTORGADO','REVOCADO')),
    version_texto   VARCHAR(10) NOT NULL,
    otorgado_el     TIMESTAMPTZ NULL,
    revocado_el     TIMESTAMPTZ NULL,
    actualizado_el  TIMESTAMPTZ NOT NULL,
    UNIQUE (user_id, finalidad),
    FOREIGN KEY (finalidad, version_texto) REFERENCES textos_consentimiento (finalidad, version)
);
-- Un consentimiento HABILITA el tratamiento solo si estado = 'OTORGADO' y version_texto es la
-- versión vigente; si cambia el texto queda en REQUIERE_RENOVACION (estado calculado).

-- HISTORIAL: solo inserción. Sin IP, navegador ni datos de contacto.
CREATE TABLE consentimientos_historial (
    id              UUID PRIMARY KEY,
    user_id         UUID        NOT NULL,
    finalidad       VARCHAR(40) NOT NULL,
    accion          VARCHAR(10) NOT NULL CHECK (accion IN ('OTORGADO','REVOCADO','RENOVADO')),
    version_texto   VARCHAR(10) NOT NULL,
    canal           VARCHAR(20) NOT NULL CHECK (canal IN ('REGISTRO','CENTRO_PRIVACIDAD','ENLACE_CORREO','SUPRESION')),
    ocurrido_el     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- La lista de envío de marketing ya no guarda la prueba del consentimiento (vive arriba):
-- existe una fila solo mientras MARKETING_EMAIL está vigente; al revocar se borra.
ALTER TABLE suscripciones_marketing DROP COLUMN consentimiento_otorgado_el;
ALTER TABLE suscripciones_marketing DROP COLUMN version_texto;
ALTER TABLE suscripciones_marketing DROP COLUMN revocado_el;
ALTER TABLE suscripciones_marketing ADD CONSTRAINT uq_suscripcion_user UNIQUE (user_id);

CREATE OR REPLACE VIEW v_export_marketing AS
SELECT s.id, s.suscriptor_pseudo, s.email_cifrado, s.token_desuscripcion
FROM suscripciones_marketing s
JOIN consentimientos c ON c.user_id = s.user_id AND c.finalidad = 'MARKETING_EMAIL' AND c.estado = 'OTORGADO'
WHERE c.version_texto = (SELECT version FROM textos_consentimiento
                         WHERE finalidad = 'MARKETING_EMAIL' ORDER BY vigente_desde DESC LIMIT 1);

-- -----------------------------------------------------------------------------
-- 4.3 Ejercicio de derechos
-- -----------------------------------------------------------------------------
CREATE TABLE solicitudes_derechos (
    id                  UUID PRIMARY KEY,
    user_id             UUID        NOT NULL,        -- se conserva tras la supresión (constancia), sin datos personales
    tipo                VARCHAR(15) NOT NULL CHECK (tipo IN ('ACCESO','PORTABILIDAD','RECTIFICACION','SUPRESION')),
    estado              VARCHAR(15) NOT NULL CHECK (estado IN ('RECIBIDA','VERIFICADA','EN_EVALUACION','CERRADA','ANULADA')),
    resultado           VARCHAR(10) NULL CHECK (resultado IN ('EJECUTADA','RECHAZADA')),
    nivel_verificacion  VARCHAR(40) NOT NULL,
    campos_solicitados  TEXT        NULL,            -- nombres de campos, nunca valores
    cambios_cifrados    TEXT        NULL,            -- valores propuestos (AES-GCM); NULL al ejecutar
    fundamento          TEXT        NULL,            -- respuesta fundamentada (rechazos, conservación legal)
    recibida_el         TIMESTAMPTZ NOT NULL,
    verificada_el       TIMESTAMPTZ NULL,
    evaluada_el         TIMESTAMPTZ NULL,
    resuelta_el         TIMESTAMPTZ NULL,
    cerrada_el          TIMESTAMPTZ NULL,
    plazo_vence_el      TIMESTAMPTZ NOT NULL         -- recibida + 30 días corridos
);
CREATE UNIQUE INDEX uq_solicitud_abierta ON solicitudes_derechos (user_id, tipo)
    WHERE estado IN ('RECIBIDA','VERIFICADA','EN_EVALUACION');

CREATE TABLE verificaciones (
    id              UUID PRIMARY KEY,
    solicitud_id    UUID        NOT NULL REFERENCES solicitudes_derechos(id),
    codigo_hmac     CHAR(64)    NOT NULL,            -- HMAC(K_verificacion, solicitud:codigo); el código nunca se guarda
    destino         VARCHAR(20) NOT NULL CHECK (destino IN ('EMAIL_REGISTRADO','EMAIL_NUEVO','SOLO_CONTRASENA')),
    expira_el       TIMESTAMPTZ NOT NULL,            -- 10 minutos
    intentos        SMALLINT    NOT NULL DEFAULT 0,  -- 5 intentos -> solicitud ANULADA
    usado           BOOLEAN     NOT NULL DEFAULT FALSE
);

-- Lápidas de supresión: HMAC del user_id (sin datos personales). Impiden que el ETL o una
-- restauración de respaldo vuelvan a usar los datos de un titular suprimido.
CREATE TABLE supresiones (
    id              CHAR(64) PRIMARY KEY,
    suprimido_el    TIMESTAMPTZ NOT NULL
);

-- -----------------------------------------------------------------------------
-- 4.4 Auditoría: cadena sellada, solo inserción, anclas y constancia de purgas
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS audit_log;
CREATE TABLE audit_log (
    secuencia       BIGINT      PRIMARY KEY,         -- consecutiva, asignada al insertar
    id              UUID        NOT NULL UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL,
    actor_id        TEXT        NOT NULL,            -- id interno o 'cuenta:<prefijo índice ciego>'
    actor_rol       VARCHAR(30) NOT NULL,
    accion          VARCHAR(60) NOT NULL,
    categoria       VARCHAR(30) NOT NULL,
    recurso         VARCHAR(200) NULL,               -- tipo:id, sin contenido
    resultado       VARCHAR(10) NOT NULL CHECK (resultado IN ('PERMITIDO','DENEGADO','EXITO','FALLIDO')),
    motivo          VARCHAR(300) NULL,               -- redactado automáticamente
    hash_previo     CHAR(64)    NOT NULL,
    hash            CHAR(64)    NOT NULL             -- HMAC(K_auditoria, hash_previo + contenido)
);

-- Nadie modifica ni borra fuera de la purga controlada (defensa adicional a los GRANTS).
CREATE FUNCTION audit_log_inmutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'audit_log es de solo inserción';
    END IF;
    IF TG_OP = 'DELETE' AND current_user <> 'svc_retencion' THEN
        RAISE EXCEPTION 'solo svc_retencion puede purgar audit_log';
    END IF;
    RETURN OLD;
END $$;
CREATE TRIGGER trg_audit_log_inmutable BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_inmutable();
-- Nota de despliegue: el sello HMAC requiere K_auditoria, que NO debe vivir en la BD. En
-- producción lo calcula un servicio de auditoría dedicado (único escritor, con la llave en el
-- KMS); en el prototipo lo hace un disparador de la BD simulada (src/security/audit.js).

CREATE TABLE auditoria_anclas (                     -- copia de la cabeza de la cadena (WORM en producción)
    id UUID PRIMARY KEY, secuencia BIGINT NOT NULL, hash CHAR(64) NOT NULL, created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE auditoria_purgas (                     -- constancia de cada purga por retención (24 meses)
    id UUID PRIMARY KEY, hasta_secuencia BIGINT NOT NULL, hash_ultimo CHAR(64) NOT NULL,
    filas INTEGER NOT NULL, ejecutada_el TIMESTAMPTZ NOT NULL, actor_id TEXT NOT NULL
);

-- -----------------------------------------------------------------------------
-- 4.5 Detección y respuesta a incidentes
-- -----------------------------------------------------------------------------
CREATE TABLE alertas (
    id UUID PRIMARY KEY, regla VARCHAR(40) NOT NULL,
    nivel VARCHAR(20) NOT NULL CHECK (nivel IN ('ALERTA','EVENTO_SOSPECHOSO')),
    severidad VARCHAR(10) NOT NULL CHECK (severidad IN ('BAJA','MEDIA','ALTA','CRITICA')),
    sujeto TEXT NOT NULL, detalle TEXT NOT NULL,
    estado VARCHAR(12) NOT NULL CHECK (estado IN ('ABIERTA','DESCARTADA','ESCALADA')),
    incidente_id UUID NULL, created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE incidentes (
    id UUID PRIMARY KEY, titulo TEXT NOT NULL,
    severidad VARCHAR(10) NOT NULL,
    estado VARCHAR(12) NOT NULL CHECK (estado IN ('EN_ANALISIS','CONTENIDO','ERRADICADO','RECUPERADO','CERRADO','DESCARTADO')),
    detectado_el TIMESTAMPTZ NOT NULL, ocurrido_desde TIMESTAMPTZ NULL, ocurrido_hasta TIMESTAMPTZ NULL,
    tipos_datos TEXT NULL, titulares_afectados INTEGER NULL, evidencia_preservada BOOLEAN NOT NULL DEFAULT FALSE,
    decision_notificacion TEXT NULL, notificacion_autorizada_por TEXT NULL,
    notificado_agencia_el TIMESTAMPTZ NULL, notificado_titulares_el TIMESTAMPTZ NULL,
    causa_raiz TEXT NULL, lecciones TEXT NULL, cerrado_el TIMESTAMPTZ NULL, responsable_id TEXT NOT NULL
);
CREATE TABLE incidente_acciones (                   -- bitácora del incidente, solo inserción
    id UUID PRIMARY KEY, incidente_id UUID NOT NULL REFERENCES incidentes(id),
    fase VARCHAR(15) NOT NULL, accion VARCHAR(60) NOT NULL, detalle TEXT NULL,
    actor_id TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE evidencias (                           -- copia de eventos + verificación + ancla, con SHA-256
    id UUID PRIMARY KEY, incidente_id UUID NOT NULL REFERENCES incidentes(id),
    tipo VARCHAR(20) NOT NULL, contenido JSONB NOT NULL, sha256 CHAR(64) NOT NULL, created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE controles_operacion (                  -- contención: 'rol_suspendido:<ROL>', 'exportaciones_suspendidas'
    id TEXT PRIMARY KEY, activo BOOLEAN NOT NULL, incidente_id UUID NULL, actualizado_el TIMESTAMPTZ NOT NULL
);

-- -----------------------------------------------------------------------------
-- 4.6 Permisos (amplía 03_rbac.sql)
-- -----------------------------------------------------------------------------
CREATE ROLE rol_auditor   NOLOGIN;   -- solo lectura de la auditoría
CREATE ROLE svc_retencion NOLOGIN;   -- única que borra auditoría vencida
CREATE ROLE svc_seguridad NOLOGIN;   -- alertas, incidentes, evidencias y contención

REVOKE ALL ON audit_log FROM svc_app;
GRANT INSERT                 ON audit_log TO svc_app;            -- la aplicación ya no puede leer la auditoría
GRANT SELECT                 ON audit_log, auditoria_anclas, auditoria_purgas TO rol_auditor;
GRANT DELETE                 ON audit_log TO svc_retencion;
GRANT INSERT                 ON auditoria_purgas TO svc_retencion;

GRANT SELECT, INSERT         ON textos_consentimiento, consentimientos_historial, supresiones TO svc_app;
GRANT SELECT, INSERT, UPDATE ON consentimientos, solicitudes_derechos, verificaciones TO svc_app;
GRANT INSERT                 ON alertas TO svc_app;              -- el motor de detección solo crea alertas
GRANT SELECT                 ON controles_operacion TO svc_app;
GRANT SELECT                 ON consentimientos, textos_consentimiento, supresiones TO svc_etl;
GRANT SELECT                 ON resenas TO svc_privacidad;       -- para incluir las reseñas propias en el derecho de acceso

GRANT SELECT, UPDATE         ON alertas TO svc_seguridad;
GRANT SELECT, INSERT, UPDATE ON incidentes, controles_operacion TO svc_seguridad;
GRANT SELECT, INSERT         ON incidente_acciones, evidencias TO svc_seguridad;
GRANT INSERT                 ON auditoria_anclas TO svc_seguridad;
-- Ningún rol tiene UPDATE ni DELETE sobre consentimientos_historial, incidente_acciones,
-- evidencias, auditoria_anclas ni auditoria_purgas.
