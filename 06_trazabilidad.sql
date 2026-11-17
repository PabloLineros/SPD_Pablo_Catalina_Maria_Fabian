-- =============================================================================
-- NortiShop — Paso 6: TRAZABILIDAD Y PLAN DE RESPUESTA
-- Amplía 04_consentimiento_derechos_auditoria.sql: catálogo de eventos auditados, campos de
-- trazabilidad (titular, datos tocados, sesión, origen seudonimizado, correlación), índices para
-- reconstruir incidentes, conservación de todos los registros y retención extendida (legal hold).
-- Implementado en ITEM2/src/security/catalogoAuditoria.js, audit.js, detection.js y
-- ITEM2/src/services/auditService.js (mismas columnas, tipos y GRANTS en src/db/repository.js).
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 6.1 Catálogo de eventos auditados (fuente: src/security/catalogoAuditoria.js)
-- -----------------------------------------------------------------------------
CREATE TABLE eventos_auditables (
    accion      VARCHAR(60)  PRIMARY KEY,           -- patrón de la acción (p. ej. 'clientes:pii:revelar')
    categoria   VARCHAR(30)  NOT NULL,
    datos       TEXT         NULL,                  -- NOMBRES de campos personales que toca, nunca valores
    exposicion  VARCHAR(12)  NULL CHECK (exposicion IN ('COMPLETO','ENMASCARADO','REFERENCIA')),
    descripcion TEXT         NOT NULL
);
INSERT INTO eventos_auditables (accion, categoria, datos, exposicion, descripcion) VALUES
 ('auth:login',                       'AUTENTICACION',  'credenciales',                          'REFERENCIA',  'Inicio de sesión exitoso o fallido'),
 ('auth:logout',                      'AUTENTICACION',  NULL,                                    NULL,          'Cierre de sesión'),
 ('auth:registro',                    'AUTENTICACION',  'nombre,email,telefono,direccion,medio_pago,credenciales', 'REFERENCIA', 'Creación de una cuenta'),
 ('perfil:propio:leer',               'ACCESO_DATOS',   'nombre,email,telefono,direccion,medio_pago', 'COMPLETO', 'El titular ve su perfil'),
 ('pedidos:propios:leer',             'ACCESO_DATOS',   'pedidos',                               'COMPLETO',    'El titular ve sus pedidos'),
 ('puntos:consultar',                 'ACCESO_DATOS',   'puntos',                                'COMPLETO',    'El titular consulta su saldo de NortiPuntos'),
 ('invitado:pedido:consultar',        'ACCESO_DATOS',   'pedidos',                               'COMPLETO',    'Seguimiento de un pedido sin cuenta (sin datos de contacto)'),
 ('puntos:canjear',                   'TRANSACCION',    'puntos',                                'REFERENCIA',  'Canje de NortiPuntos'),
 ('resena:publicar',                  'MODIFICACION',   'resena',                                'REFERENCIA',  'Publicación de una reseña con autor seudonimizado'),
 ('clientes:buscar:enmascarado',      'ACCESO_DATOS',   'nombre,email,telefono',                 'ENMASCARADO', 'Soporte busca un cliente'),
 ('clientes:pii:revelar',             'ACCESO_SENSIBLE','nombre,email,telefono,direccion',       'COMPLETO',    'Soporte revela datos completos (ticket + motivo)'),
 ('envios:etiqueta',                  'ACCESO_SENSIBLE','nombre,direccion',                      'COMPLETO',    'Logística genera una etiqueta'),
 ('seudonimos:revertir',              'ACCESO_SENSIBLE','seudonimo',                             'REFERENCIA',  'El DPO revierte un seudónimo'),
 ('derechos:localizar',               'ACCESO_SENSIBLE', NULL,                                   'REFERENCIA',  'Mapa de dónde hay datos de un titular'),
 ('perfil:propio:editar',             'MODIFICACION',   '(campos cambiados)',                    'REFERENCIA',  'Cambio de teléfono, dirección o comuna'),
 ('derechos:rectificacion:ejecutada', 'MODIFICACION',   '(campos rectificados)',                 'REFERENCIA',  'Rectificación aplicada'),
 ('pedido:crear',                     'TRANSACCION',    'direccion,pedidos[,medio_pago]',        'REFERENCIA',  'Compra; el motivo indica si se usó la tarjeta guardada'),
 ('invitado:pedido:crear',            'TRANSACCION',    'nombre,email,telefono,direccion,medio_pago', 'REFERENCIA', 'Compra sin cuenta'),
 ('derechos:acceso|portabilidad:*',   'EXPORTACION',    'copia_completa',                        'COMPLETO',    'Copia de los datos del titular generada o descargada'),
 ('derechos:supresion:*',             'SUPRESION',      'nombre,email,telefono,direccion,medio_pago,pedidos,puntos,facturacion', 'REFERENCIA', 'Supresión (o bloqueo legal)'),
 ('derechos:*',                       'DERECHOS',       NULL,                                    NULL,          'Recepción, verificación y cierre de solicitudes'),
 ('consentimiento:*',                 'CONSENTIMIENTO', 'consentimientos',                       'REFERENCIA',  'Otorgamiento, revocación o renovación'),
 ('tratamiento:encuesta_satisfaccion','TRATAMIENTO',    'email',                                 'REFERENCIA',  'Envío u omisión de la encuesta'),
 ('marketing:exportar',               'EXPORTACION',    'email',                                 'REFERENCIA',  'Exportación de suscriptores'),
 ('copia_desarrollo',                 'EXPORTACION',    NULL,                                    NULL,          'Copia sintética para desarrollo'),
 ('roles:gestionar | catalogo:gestionar | pedidos:gestionar | envios:estado', 'ADMINISTRACION', NULL, NULL, 'Administración'),
 ('etl:analitica | job:*',            'PROCESO_PRIVACIDAD', NULL,                                NULL,          'ETL seudonimizado y procesos de plazos'),
 ('seguridad:* | incidente:* | recuperacion:*', 'SEGURIDAD', NULL,                               NULL,          'Alertas y fases de incidentes'),
 ('auditoria:*',                      'AUDITORIA',      NULL,                                    NULL,          'Consulta, verificación, reconstrucción y purga'),
 ('(cualquier permiso) DENEGADO',     'CONTROL_ACCESO', NULL,                                    NULL,          'Intento de acceso sin permiso, ajeno o con rol suspendido');

-- -----------------------------------------------------------------------------
-- 6.2 Campos de trazabilidad en audit_log (todos entran en el sello HMAC encadenado)
-- -----------------------------------------------------------------------------
ALTER TABLE audit_log ADD COLUMN titular_ref    TEXT        NULL;  -- id interno del titular afectado (no su nombre ni correo)
ALTER TABLE audit_log ADD COLUMN datos          TEXT        NULL;  -- nombres de campos: 'nombre,direccion' (nunca valores)
ALTER TABLE audit_log ADD COLUMN sesion_ref     VARCHAR(24) NULL;  -- 'ses:' + 16 hex del SHA-256 del token (el token no se guarda)
ALTER TABLE audit_log ADD COLUMN origen_ref     VARCHAR(24) NULL;  -- 'org:' + 16 hex de HMAC(K_origen, ip): la IP NO se guarda
ALTER TABLE audit_log ADD COLUMN correlacion_id UUID        NULL;  -- una por solicitud HTTP/API
ALTER TABLE audit_log ADD CONSTRAINT chk_audit_datos_sin_valores
    CHECK (datos IS NULL OR datos ~ '^[a-z_]+(,[a-z_]+)*$');      -- solo nombres de campos

-- Índices para reconstruir un incidente por origen, sesión o titular sin recorrer toda la tabla
CREATE INDEX ix_audit_origen  ON audit_log (origen_ref, created_at)  WHERE origen_ref IS NOT NULL;
CREATE INDEX ix_audit_sesion  ON audit_log (sesion_ref, secuencia)   WHERE sesion_ref IS NOT NULL;
CREATE INDEX ix_audit_titular ON audit_log (titular_ref, created_at) WHERE titular_ref IS NOT NULL;

-- -----------------------------------------------------------------------------
-- 6.3 Conservación y retención extendida (legal hold)
-- -----------------------------------------------------------------------------
-- Plazos: audit_log y alertas 24 meses; evidencias 5 años desde el cierre del incidente;
-- anclas y constancias de purga indefinido (sin datos personales); logs de aplicación 90 días.
-- Mientras exista un incidente abierto, nada posterior a (su inicio - 24 h) se purga.
CREATE FUNCTION limite_purga_auditoria(p_ahora TIMESTAMPTZ) RETURNS TIMESTAMPTZ
LANGUAGE sql STABLE AS $$
    SELECT LEAST(
        p_ahora - INTERVAL '730 days',
        COALESCE((SELECT MIN(COALESCE(ocurrido_desde, detectado_el)) - INTERVAL '1 day'
                  FROM incidentes WHERE estado NOT IN ('CERRADO','DESCARTADO')), 'infinity'::timestamptz)
    );
$$;

GRANT SELECT, DELETE ON alertas, evidencias TO svc_retencion;   -- solo alertas resueltas y evidencias vencidas
GRANT SELECT         ON incidentes        TO svc_retencion;     -- para respetar la retención extendida

-- -----------------------------------------------------------------------------
-- 6.4 Acceso restringido
-- -----------------------------------------------------------------------------
-- Sin cambios a los GRANTS de 04: svc_app solo INSERTA en audit_log; solo rol_auditor lee.
-- En la aplicación, leer la auditoría (auditoria:leer) es de ADMINISTRADOR, OFICIAL_PRIVACIDAD y
-- SEGURIDAD; RECONSTRUIR por titular, sesión u origen (auditoria:reconstruir) solo de SEGURIDAD y
-- OFICIAL_PRIVACIDAD, con motivo obligatorio, y cada consulta queda auditada.
REVOKE SELECT ON eventos_auditables FROM PUBLIC;
GRANT  SELECT ON eventos_auditables TO rol_auditor, svc_app;
