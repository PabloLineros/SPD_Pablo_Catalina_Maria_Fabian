# NortiShop: protección de datos personales en una tienda en línea

Proyecto integrador del curso **Seguridad y Protección de Datos** (Universidad del Desarrollo, Facultad de Ingeniería, 2026).

**Integrantes:** María Gerónimo · Pablo Lineros · Catalina Toledo · Fabián Salinas

## De qué trata

El curso combina dos líneas: la jurídica (Ley 19.628 y Ley 21.719 de protección de datos personales) y la técnica, donde cada exigencia legal se convierte en un control implementado en el software. El proyecto consiste en construir, entrega a entrega, un mismo sistema que cumpla esas exigencias.

El caso elegido es **NortiShop** (Caso 1), una tienda en línea chilena de tecnología con más de 50.000 clientes, un programa de puntos (NortiPuntos), un boletín de ofertas, pago con una pasarela externa, reseñas de productos y compras sin cuenta.

## Estructura del repositorio

| Carpeta | Contenido |
|---|---|
| [`entregas/`](entregas/) | Los informes **oficiales** de cada entrega, tal como se presentaron. |
| [`sistema/`](sistema/) | El prototipo funcional de NortiShop (Node.js), con sus pruebas automatizadas y evidencias. |
| [`base-de-datos/`](base-de-datos/) | El diseño de la base de datos en SQL (PostgreSQL), del esquema original a la trazabilidad. Documenta lo que el prototipo implementa; no se ejecuta. |
| [`docs/`](docs/) | El plan de respuesta a incidentes vigente. |

## Las entregas

| # | Entrega | Qué se pidió | Qué se hizo | Informe | En el sistema |
|---|---|---|---|---|---|
| 1 | Actores y riesgos | Mapa de actores, datos y atributo CIA en riesgo (mínimo 20 filas) | Tabla de actores, datos y riesgos de confidencialidad, integridad o disponibilidad | [`01-actores-y-riesgos`](entregas/01-actores-y-riesgos/) | — |
| 2 | Protección de campos sensibles | Elegir e implementar cifrado, hashing o tokenización para cada dato sensible | bcrypt para contraseñas, AES-256-GCM para datos personales, tokenización de la tarjeta y HMAC para los NortiPuntos | [`02-proteccion-de-campos-sensibles`](entregas/02-proteccion-de-campos-sensibles/) | `sistema/src/crypto/` |
| 3 | Hito 1: inventario y clasificación | Inventario de datos, mapa de flujos, clasificación por sensibilidad y base de licitud | Informe y presentación oral | [`03-hito1-inventario-y-clasificacion`](entregas/03-hito1-inventario-y-clasificacion/) | — |
| 4 | Minimización, seudonimización y RBAC | Rediseñar la base de datos y controlar el acceso por roles, en código | Esquema minimizado, seudónimos para reseñas, analítica y marketing, reportes anonimizados (k = 5) y 9 roles con mínimo privilegio | [`04-minimizacion-seudonimizacion-rbac`](entregas/04-minimizacion-seudonimizacion-rbac/) | `src/db/`, `src/security/rbac.js`, `base-de-datos/00` a `03` |
| 5 | Consentimiento, derechos, auditoría e incidentes | Consentimiento por finalidad, derechos del titular, auditoría y plan de incidentes | Consentimiento revocable por finalidad, auditoría sellada con HMAC encadenado, 6 alertas y plan de respuesta | [`05-consentimiento-derechos-auditoria`](entregas/05-consentimiento-derechos-auditoria/) | `consentService`, `audit.js`, `detection.js`, `incidentService`, `base-de-datos/04` |
| 6 | Ejercicio de derechos | Canal de solicitudes, verificación de identidad, acceso, portabilidad, rectificación, supresión y oposición o bloqueo | Solicitudes con folio y plazos, verificación con contraseña y código, copia de un solo uso, supresión con bloqueo legal y propagación a terceros | [`06-ejercicio-de-derechos`](entregas/06-ejercicio-de-derechos/) | `rightsService`, `restrictionService`, `base-de-datos/05` |
| 7 | Trazabilidad y plan de respuesta | Auditar sin guardar datos, proteger los registros, 3 alertas propias, plan de respuesta y simulacro | Catálogo de 37 eventos, 4 alertas propias, reconstrucción por titular, sesión u origen, y simulacro de un ataque | [`07-trazabilidad-y-respuesta`](entregas/07-trazabilidad-y-respuesta/) | `catalogoAuditoria.js`, `contexto.js`, `auditService`, `base-de-datos/06` |

## El sistema

`sistema/` contiene la parte interna de la tienda (servicios de usuarios, pedidos, puntos, reseñas, logística, soporte, consentimiento, derechos, auditoría e incidentes), un servidor HTTP y una página web, el **Centro de privacidad**, donde el cliente gestiona sus consentimientos y ejerce sus derechos.

Para que funcione sin infraestructura externa, la base de datos es una simulación en memoria que aplica permisos por rol, y el correo, la pasarela de pago y los terceros también están simulados. Solo se usan datos sintéticos: los clientes de prueba son Ana y Bruno, con dominio `.test`.

### Cómo ejecutarlo

Requiere Node.js 20.6 o superior. Desde la carpeta `sistema/`:

```bash
npm install
npm run generar-env
```

| Comando | Qué hace |
|---|---|
| `npm test` | Ejecuta las 106 pruebas automatizadas. |
| `npm run simulacro` | Simula un ataque (relleno de credenciales y toma de la cuenta de Ana), lo reconstruye desde la auditoría, ejecuta el plan de respuesta y compara el resultado con el guion del atacante. |
| `npm run servidor` | Abre el Centro de privacidad en `http://127.0.0.1:3000/` (cuenta de prueba: `ana.prueba@ejemplo.test` / `ClaveDePrueba#2026`). |
| `npm run demo:privacidad` | Demo por consola de consentimiento, derechos, auditoría e incidentes. |
| `npm start` | Demo por consola de minimización, datos en reposo, seudonimización y RBAC. |
| `npm run matriz` | Imprime la matriz de permisos por rol. |

Más detalle en [`sistema/README.md`](sistema/README.md).

### Pruebas

Cada control tiene pruebas que lo verifican, incluidos los casos que deben ser **rechazados**:

| Archivo (`sistema/test/`) | Qué comprueba | Entrega |
|---|---|---|
| `criptografia` | Una llave por finalidad, bcrypt, AES-256-GCM, HMAC y tokenización | 2 |
| `minimizacion` | Se rechazan datos innecesarios y nada sensible queda en texto plano | 4 |
| `seudonimizacion` | Reseñas y analítica sin identidad, anonimización k = 5, invitados anonimizados al vencer el plazo | 4 |
| `rbac`, `servidor`, `registros` | Cada rol accede solo a lo suyo, los controles no se eluden por el servidor ni por la base de datos, y los logs no contienen datos personales | 4 |
| `consentimiento` | Cada finalidad se decide por separado y la revocación tiene efecto inmediato | 5 |
| `derechos`, `ejercicio_derechos` | Cada derecho exige verificar la identidad; un solicitante no verificado no obtiene nada | 5 y 6 |
| `auditoria`, `incidentes` | La auditoría no guarda datos personales, detecta alteraciones, y el plan de respuesta se ejecuta completo | 5 |
| `trazabilidad` | Catálogo de eventos, alertas propias, conservación de registros y simulacro | 7 |

Las salidas de las pruebas, las demos y el simulacro están en `sistema/evidencias/`, junto con capturas y diagramas.

## Limitaciones

- Es un prototipo académico: la base de datos, el correo y la pasarela de pago son simulaciones en memoria.
- No hay segundo factor de autenticación (MFA). Es la principal medida preventiva pendiente que dejó el simulacro.
- La rotación de llaves es manual; en producción se usaría un gestor de secretos o KMS.
