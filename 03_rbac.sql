-- =============================================================================
-- NortiShop — Hito 2 · Paso 3: CONTROL DE ACCESO EN LA BASE DE DATOS
-- Mínimo privilegio a nivel de BD: una credencial por servicio, cada una con solo
-- los permisos que necesita. Implementado en ITEM2/src/db/repository.js (GRANTS).
-- Los roles de APLICACIÓN (ADMINISTRADOR, SOPORTE, ...) están en
-- ITEM2/src/security/rbac.js; ver la matriz en el informe (npm run matriz).
-- =============================================================================

-- Nadie hereda permisos por defecto
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;

-- -----------------------------------------------------------------------------
-- Roles de base de datos (NOLOGIN = grupo; cada servicio tiene su usuario LOGIN)
-- -----------------------------------------------------------------------------
CREATE ROLE svc_app        NOLOGIN;  -- backend transaccional
CREATE ROLE svc_privacidad NOLOGIN;  -- seudónimos, jobs de anonimización
CREATE ROLE svc_etl        NOLOGIN;  -- carga hacia analitica
CREATE ROLE rol_analista   NOLOGIN;  -- consultas de negocio
CREATE ROLE rol_marketing  NOLOGIN;  -- exportación de suscriptores
CREATE ROLE rol_publico    NOLOGIN;  -- contenido público (reseñas)

GRANT USAGE ON SCHEMA public TO svc_app, svc_privacidad, svc_etl, rol_marketing, rol_publico;

-- -----------------------------------------------------------------------------
-- svc_app: operación diaria. SIN acceso a pseudo.* ni analitica.*
-- -----------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE         ON productos, personal, facturacion, orders, orders_invitado, envios TO svc_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON users, loyalty_accounts, suscripciones_marketing TO svc_app;
GRANT SELECT, INSERT                 ON order_items TO svc_app;
GRANT SELECT, INSERT, DELETE         ON historial_puntos, sesiones TO svc_app;
GRANT INSERT                         ON resenas TO svc_app;          -- lectura solo vía v_resenas_publicas
GRANT SELECT                         ON v_resenas_publicas TO svc_app;
GRANT SELECT, INSERT                 ON audit_log TO svc_app;        -- auditoría de solo inserción
-- Sin UPDATE/DELETE sobre audit_log para NINGÚN rol de aplicación.

-- -----------------------------------------------------------------------------
-- svc_privacidad: único rol con acceso a la tabla que revierte seudónimos
-- -----------------------------------------------------------------------------
GRANT USAGE ON SCHEMA pseudo TO svc_privacidad;
GRANT SELECT, INSERT, DELETE ON pseudo.pseudonimos TO svc_privacidad;
GRANT SELECT, UPDATE (nombre_invitado_cifrado, email_invitado_cifrado, telefono_invitado_cifrado, direccion_envio_cifrada)
      ON orders_invitado TO svc_privacidad;                          -- solo puede ANULAR columnas de contacto
GRANT EXECUTE ON FUNCTION pseudo.anonimizar_invitados_vencidos() TO svc_privacidad;

-- -----------------------------------------------------------------------------
-- svc_etl: lee lo mínimo de las tablas operativas, escribe solo en analitica
-- -----------------------------------------------------------------------------
GRANT SELECT (id, user_id, total_clp, comuna_envio, estado, created_at) ON orders TO svc_etl; -- sin dirección ni pago
GRANT SELECT ON order_items, productos TO svc_etl;
GRANT SELECT (user_id, delta, motivo, created_at) ON historial_puntos TO svc_etl;
GRANT USAGE ON SCHEMA analitica TO svc_etl;
GRANT SELECT, INSERT, DELETE ON analitica.compras, analitica.movimientos_puntos TO svc_etl;

-- -----------------------------------------------------------------------------
-- rol_analista: SOLO el esquema analitica (seudonimizado / agregado)
-- -----------------------------------------------------------------------------
GRANT USAGE ON SCHEMA analitica TO rol_analista;
GRANT SELECT ON analitica.compras, analitica.movimientos_puntos, analitica.v_ventas_por_comuna TO rol_analista;

-- -----------------------------------------------------------------------------
-- rol_marketing: SOLO la vista de exportación (consentimientos vigentes)
-- -----------------------------------------------------------------------------
GRANT SELECT ON v_export_marketing TO rol_marketing;

-- -----------------------------------------------------------------------------
-- rol_publico: SOLO reseñas públicas
-- -----------------------------------------------------------------------------
GRANT SELECT ON v_resenas_publicas TO rol_publico;

-- -----------------------------------------------------------------------------
-- Defensa en profundidad (propuesta para producción, no simulada en el prototipo):
-- Row-Level Security para que, aun con un bug en la aplicación, un cliente solo
-- lea sus filas. La aplicación fija app.usuario_id y app.rol al abrir cada transacción.
-- -----------------------------------------------------------------------------
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY orders_propietario ON orders FOR SELECT TO svc_app
    USING (current_setting('app.rol', true) <> 'CLIENTE'
           OR user_id = current_setting('app.usuario_id', true)::uuid);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY users_propietario ON users FOR ALL TO svc_app
    USING (current_setting('app.rol', true) <> 'CLIENTE'
           OR id = current_setting('app.usuario_id', true)::uuid);

-- -----------------------------------------------------------------------------
-- Llaves criptográficas: NO residen en la base de datos. Ningún rol de BD ni de
-- aplicación puede leerlas; solo el proceso de la aplicación las recibe del gestor
-- de secretos al iniciar. El DBA no administra llaves (separación de funciones).
-- -----------------------------------------------------------------------------
