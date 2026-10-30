# NortiShop — Protección de datos personales: minimización, RBAC, consentimiento, derechos, auditoría e incidentes

**Caso de estudio:** Plataforma de comercio electrónico NortiShop
**Integrantes:** Catalina Toledo · María Gerónimo · Pablo Lineros · Fabián Salinas

## 1. Descripción

Prototipo del backend de NortiShop, con un servidor HTTP y una pantalla web (el **Centro de privacidad**). Implementa en código las decisiones de diseño de los scripts SQL de la raíz del repositorio:

| Archivo | Contenido |
|---|---|
| [`00_esquema_original.sql`](../00_esquema_original.sql) | Esquema antes del rediseño, con sus riesgos marcados. |
| [`01_minimizacion.sql`](../01_minimizacion.sql) | Esquema rediseñado aplicando minimización. |
| [`02_seudonimizacion.sql`](../02_seudonimizacion.sql) | Seudonimización y anonimización. |
| [`03_rbac.sql`](../03_rbac.sql) | Roles y permisos en la base de datos. |
| [`04_consentimiento_derechos_auditoria.sql`](../04_consentimiento_derechos_auditoria.sql) | Consentimiento, derechos, auditoría sellada e incidentes. |

Documentos de diseño: [`INFORME_HITO2.md`](../INFORME_HITO2.md), [`INFORME_CONSENTIMIENTO_DERECHOS_AUDITORIA.md`](../INFORME_CONSENTIMIENTO_DERECHOS_AUDITORIA.md) y [`PLAN_RESPUESTA_INCIDENTES.md`](../PLAN_RESPUESTA_INCIDENTES.md).

### Controles de las etapas anteriores

1. **Minimización.** Cada operación declara qué campos acepta y rechaza el resto (`CAMPO_NO_PERMITIDO`). La base de datos también rechaza columnas fuera del esquema y texto plano en columnas protegidas.
2. **Protección de campos sensibles:**
   - bcrypt para contraseñas.
   - AES-256-GCM con contexto obligatorio (`<tabla>.<campo>:<id>`) para los datos personales.
   - Tokenización de la tarjeta; solo se guardan los últimos 4 dígitos.
   - HMAC con versión e historial para los NortiPuntos.
3. **Seudonimización y anonimización.**
   - Índice ciego para el login.
   - Seudónimos HMAC distintos para reseñas, analítica y marketing.
   - Reporte agregado con k = 5.
   - Los contactos de invitados se borran al vencer el plazo de conservación.
4. **RBAC.** Nueve roles con permisos en lista blanca y verificación de que el recurso pertenezca al usuario.
5. **Gestión de llaves.** Una llave por finalidad (ocho en total). Se retiran de `process.env` al cargarse y solo `src/crypto/` puede usarlas.

### Controles de esta etapa

6. **Consentimiento por finalidad.**
   - Cada finalidad (marketing, guardar tarjeta, analítica) tiene su propia decisión, con estado, versión del texto y fecha, y un historial de solo inserción.
   - La revocación tiene efecto inmediato en los procesos que dependen de ella.
   - Si cambia el texto, el titular debe renovar su consentimiento.
7. **Derechos de los titulares.**
   - Acceso, portabilidad (JSON), rectificación y supresión.
   - Verificación de identidad proporcional al riesgo: contraseña y, para acceso, portabilidad, supresión y cambio de correo, un código de un solo uso.
   - Flujo con fecha por etapa: recibida, verificada, en evaluación, cerrada.
   - La supresión deja una lápida HMAC, que impide que el titular reaparezca al restaurar un respaldo.
8. **Auditoría.**
   - Cada registro se sella con un HMAC encadenado al anterior; un disparador asigna la secuencia y el sello.
   - Solo inserción, con lectura exclusiva de `rol_auditor`.
   - Anclas y verificación que detectan modificación, borrado y truncamiento.
   - Retención de 24 meses con constancia de cada purga.
   - Sin datos personales.
9. **Detección y respuesta a incidentes.**
   - Seis reglas de detección.
   - Flujo de incidente con evidencia obligatoria antes de contener; contención efectiva (suspender un rol, deshabilitar cuentas, revocar sesiones, suspender exportaciones).
   - Recuperación con comprobaciones, evaluación de notificación según la Ley 21.719 y cierre con lecciones aprendidas.

> **Alcance:** proyecto académico. La base de datos, la pasarela de pago y el proveedor de correo son simulaciones en memoria. No acredita cumplimiento de PCI DSS ni de la Ley 21.719.

## 2. Estructura

```text
ITEM2/
├── public/                   # Centro de privacidad (HTML + CSS + JS, sin librerías)
├── scripts/
│   ├── generar-env.js        # Crea/completa .env con llaves aleatorias (no sobrescribe)
│   ├── entorno-pruebas.js    # Llaves efímeras para npm test
│   └── matriz-rbac.js        # Imprime la matriz RBAC desde el código
├── src/
│   ├── server.js             # Servidor HTTP: POST /api/<grupo>/<op>, CSP, límites
│   ├── api.js                # Endpoints: sesión + errores seguros
│   ├── config/
│   │   ├── env.js            # Configuración no secreta y plazos
│   │   └── finalidades.js    # Finalidades, bases de licitud y textos versionados
│   ├── crypto/               # llavero, AES-GCM, bcrypt, HMAC, seudónimos, tokenización
│   ├── db/repository.js      # BD simulada: esquema, tipos, GRANTS y disparadores
│   ├── infra/correo.js       # Proveedor de correo SIMULADO (bandeja en memoria)
│   ├── security/
│   │   ├── rbac.js           # Roles, permisos, matriz, autorizar() y suspensión de roles
│   │   ├── audit.js          # Auditoría sellada (disparador + categorías)
│   │   ├── detection.js      # Reglas de detección de eventos sospechosos
│   │   ├── logger.js         # Registros con redacción automática
│   │   ├── errors.js         # Errores con código y mensaje público
│   │   └── validation.js     # Lista blanca de campos, validaciones y enmascaramiento
│   ├── services/             # auth, user, order, loyalty, review, marketing, support,
│   │                         # logistics, catalog, admin, privacy, consent, rights,
│   │                         # audit, incident
│   ├── dev/escenario.js      # Datos SINTÉTICOS para demo y pruebas
│   ├── demo.js               # Demo: minimización, seudonimización, RBAC
│   └── demo-privacidad.js    # Demo: consentimiento, derechos, auditoría, incidentes
├── evidencias/               # Salidas de demo y pruebas para el informe
└── test/                     # 82 pruebas automatizadas
```

## 3. Requisitos

Node.js 20.6 o superior y npm 9 o superior.

## 4. Instalación

```bash
cd ITEM2
npm install
npm run generar-env
```

`generar-env` crea `.env` con ocho llaves aleatorias, una por finalidad. Si `.env` ya existe, solo agrega las que falten. **Si ya tenías un `.env` de una etapa anterior, vuelve a ejecutarlo**, porque esta etapa agregó `KEY_HMAC_AUDITORIA` y `KEY_HMAC_VERIFICACION`.

## 5. Ejecución

| Comando | Qué hace |
|---|---|
| `npm run servidor` | Levanta el **Centro de privacidad** en `http://127.0.0.1:3000/` con datos sintéticos. Cuenta de prueba: `ana.prueba@ejemplo.test` / `ClaveDePrueba#2026`. |
| `npm run demo:privacidad` | Demo por consola: consentimiento, derechos, auditoría, incidentes y controles no eludibles. |
| `npm start` | Demo por consola de las etapas anteriores: minimización, datos en reposo, seudonimización y RBAC. |
| `npm test` | Ejecuta las 82 pruebas con llaves efímeras (no usa las de `.env`). |
| `npm run matriz` | Imprime la matriz RBAC en Markdown, generada desde `src/security/rbac.js`. |

## 6. Consideraciones de seguridad

- `.env` no se versiona. `.env.example` solo trae los nombres de las variables, con las llaves vacías.
- Si una llave se expone, debe considerarse comprometida y rotarse. En producción, las llaves vendrían de un gestor de secretos o KMS, y el sello de la auditoría lo calcularía un servicio de auditoría separado.
- La demo, el servidor y las pruebas usan solo datos sintéticos (dominio `.test`). Nunca se deben usar datos reales en desarrollo.
- El servidor escucha solo en `127.0.0.1`, y la ruta `/api/dev/bandeja` (correo simulado) se desactiva con `NODE_ENV=production`.
