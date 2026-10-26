# NortiShop — Minimización, seudonimización, RBAC y controles criptográficos

**Caso de estudio:** Plataforma de comercio electrónico NortiShop
**Integrantes:** Catalina Toledo · María Gerónimo · Pablo Lineros · Fabián Salinas

## 1. Descripción

Prototipo del backend de NortiShop que implementa en código las decisiones de diseño de los scripts SQL de la raíz del repositorio:

| Archivo | Contenido |
|---|---|
| [`00_esquema_original.sql`](../00_esquema_original.sql) | Esquema antes del rediseño, con sus riesgos marcados. |
| [`01_minimizacion.sql`](../01_minimizacion.sql) | Esquema rediseñado aplicando minimización. |
| [`02_seudonimizacion.sql`](../02_seudonimizacion.sql) | Seudonimización y anonimización. |
| [`03_rbac.sql`](../03_rbac.sql) | Roles y permisos en la base de datos. |

Controles implementados:

1. **Minimización.** Cada operación declara qué campos acepta y rechaza el resto (`CAMPO_NO_PERMITIDO`). La base de datos simulada también rechaza columnas fuera del esquema y texto plano en columnas protegidas.
2. **Protección de campos sensibles:**
   - bcrypt para contraseñas.
   - AES-256-GCM con contexto obligatorio (`<tabla>.<campo>:<id>`) para los datos personales.
   - Tokenización de la tarjeta; solo se guardan los últimos 4 dígitos.
   - HMAC con versión e historial para los NortiPuntos.
3. **Seudonimización.** Índice ciego para el login y seudónimos HMAC distintos para reseñas, analítica y marketing. La tabla que permite revertirlos solo la lee el servicio de privacidad.
4. **Anonimización.** Reporte agregado con k = 5. Los contactos de invitados se borran al vencer el plazo de conservación. Hay una copia sintética para desarrollo.
5. **RBAC.** Ocho roles con permisos en lista blanca y verificación de que el recurso pertenezca al usuario. La auditoría registra accesos permitidos y denegados.
6. **Gestión de llaves.** Una llave por finalidad. Se retiran de `process.env` al cargarse y solo `src/crypto/` puede usarlas.
7. **Errores y registros seguros.** Mensajes de error genéricos y logs con redacción automática de datos personales.

> **Alcance:** proyecto académico. La base de datos y la pasarela de pago son simulaciones en memoria. No acredita cumplimiento de PCI DSS ni de la Ley 21.719.

## 2. Estructura

```text
ITEM2/
├── scripts/
│   ├── generar-env.js        # Crea/completa .env con llaves aleatorias (no sobrescribe)
│   ├── entorno-pruebas.js    # Llaves efímeras para npm test
│   └── matriz-rbac.js        # Imprime la matriz RBAC desde el código
├── src/
│   ├── api.js                # Endpoints del servidor: sesión + errores seguros
│   ├── config/env.js         # Configuración no secreta
│   ├── crypto/
│   │   ├── keyring.js        # Llavero: una llave por finalidad
│   │   ├── cipher.js         # AES-256-GCM con AAD obligatorio
│   │   ├── hashing.js        # bcrypt + política de contraseñas + señuelo anti-enumeración
│   │   ├── integrity.js      # HMAC-SHA256 (firma de saldos)
│   │   ├── pseudonymization.js # Índice ciego y seudónimos por finalidad
│   │   └── tokenization.js   # Bóveda de pagos simulada
│   ├── db/repository.js      # BD simulada: esquema, tipos protegidos y GRANTS por rol
│   ├── security/
│   │   ├── rbac.js           # Roles, permisos, matriz y autorizar()
│   │   ├── audit.js          # Auditoría (solo inserción)
│   │   ├── logger.js         # Registros con redacción automática
│   │   ├── errors.js         # Errores con código y mensaje público
│   │   └── validation.js     # Lista blanca de campos, validaciones y enmascaramiento
│   ├── services/             # auth, user, order, loyalty, review, marketing,
│   │                         # support, logistics, catalog, admin, privacy
│   ├── dev/escenario.js      # Datos SINTÉTICOS para demo y pruebas
│   └── demo.js               # Recorrido por consola de todos los controles
└── test/                     # 50 pruebas: criptografía, minimización,
                              # seudonimización, RBAC y registros
```

## 3. Requisitos

Node.js 20.6 o superior y npm 9 o superior.

## 4. Instalación

```bash
cd ITEM2
npm install
npm run generar-env
```

`generar-env` crea `.env` con seis llaves aleatorias, una por finalidad. Si `.env` ya existe, solo agrega las variables que falten y no modifica las demás. Las llaves no se imprimen en pantalla.

## 5. Ejecución

| Comando | Qué hace |
|---|---|
| `npm start` | Demo por consola: minimización, datos en reposo, seudonimización, RBAC, integridad y logs. |
| `npm test` | Ejecuta la batería de pruebas con llaves efímeras (no usa las de `.env`). |
| `npm run matriz` | Imprime la matriz RBAC en Markdown, generada desde `src/security/rbac.js`. |

## 6. Consideraciones de seguridad

- `.env` no se versiona. `.env.example` solo trae los nombres de las variables, con las llaves vacías.
- Si una llave se expone, debe considerarse comprometida y rotarse. En producción, las llaves vendrían de un gestor de secretos o KMS.
- La demo y las pruebas usan solo datos sintéticos (dominio `.test`). Nunca se deben usar datos reales en desarrollo.
