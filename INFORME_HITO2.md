# Informe técnico — Minimización, seudonimización y control de acceso en NortiShop

**Caso:** Plataforma de comercio electrónico NortiShop
**Integrantes:** Catalina Toledo · María Gerónimo · Pablo Lineros · Fabián Salinas
**Código fuente:** carpeta `ITEM2/` y scripts SQL `00` a `03` de este repositorio

---

## 1. Introducción

En el Ítem I clasificamos los campos sensibles de NortiShop y en el Ítem II implementamos cifrado, hashing, tokenización y HMAC. El *Informe de Análisis de Datos Personales* (5 de octubre de 2026) concluyó que, pese a esos controles, quedaban brechas:

- Control de accesos insuficiente.
- Plazos de conservación "no indicados" para todos los datos.
- Sin procedimiento de supresión ni mecanismos para los derechos del titular.
- Dirección de despacho en texto plano dentro de las órdenes.

En esta etapa rediseñamos la base de datos para cerrar esas brechas, con tres objetivos:

1. Guardar solo lo necesario (**minimización**).
2. Reducir la exposición de lo que sí se guarda (**seudonimización y anonimización**).
3. Limitar quién puede acceder a cada dato y operación (**RBAC con mínimo privilegio**).

Todas las decisiones están implementadas en el código y verificadas con 50 pruebas automatizadas.

| Entregable | Dónde está |
|---|---|
| Esquema original | `00_esquema_original.sql` |
| Esquema rediseñado | `01_minimizacion.sql`, implementado en `ITEM2/src/db/repository.js` |
| Seudonimización y anonimización | `02_seudonimizacion.sql`, `src/crypto/pseudonymization.js`, `src/services/privacyService.js` |
| RBAC | `03_rbac.sql` (roles de base de datos), `src/security/rbac.js` (roles de aplicación) |
| Pruebas | `ITEM2/test/*.test.js` (`npm test`) y demo por consola (`npm start`) |

---

## 2. Parte 1 — Minimización de datos

### 2.1 Esquema original

Reconstruimos el esquema original (`00_esquema_original.sql`) solo a partir de tres fuentes previas: el inventario de datos del Informe de Análisis, la Tabla por Campo Sensible del Ítem I y el código v1. Cada tabla indica de qué fuente proviene. Sus principales problemas eran:

- **Datos redundantes:** la región, que se deriva de la comuna.
- **Datos obligatorios que no son indispensables:** teléfono (de clientes e invitados), tarjeta guardada siempre y datos de facturación sin distinguir boleta de factura.
- **Datos en exceso de detalle:** máscara completa de la tarjeta.
- **Texto plano:** la dirección de despacho dentro de la orden (`direccionDespachoDescifradaLogistica`), ya señalada en el inventario.
- **Datos financieros dentro de NortiShop:** la bóveda simulada guardaba un SHA-256 del número de tarjeta, el titular y el vencimiento.
- **Vínculos directos con la identidad:** reseñas con `user_id`.
- **Datos sin finalidad:** nombre de contacto en marketing y volcado del checkout de invitados.
- **Conservación indefinida:** todos los plazos figuraban como "No indicado" en el inventario.
- **Control de acceso insuficiente:** cualquier servicio leía y escribía todas las tablas y no había auditoría.

### 2.2 Esquema rediseñado

`01_minimizacion.sql` define el nuevo esquema. Las convenciones son:

- Columnas `*_cifrado` con AES-256-GCM y AAD `<tabla>.<campo>:<id>`, validadas por un dominio `CHECK`.
- Columnas `*_hmac` como índices ciegos.
- `tarjeta_last4` en lugar de la máscara.
- Tabla `personal` separada de `users`.
- Tablas `sesiones` y `audit_log` como soporte del control de acceso.

### 2.3 Tabla de decisiones

| Tabla y campo | Decisión | Justificación |
|---|---|---|
| users: `nombre` | Mantener, cifrado | Se necesita para la etiqueta de despacho, la boleta y la atención al cliente. Va cifrado con AAD; si se filtra la BD sin la llave, no es legible. |
| users: `email` | Mantener, cifrado + índice ciego | Es credencial y canal de notificación. Antes el login descifraba todos los correos; ahora busca por `email_hmac` = HMAC(K_indice, email) sin descifrar nada. |
| users: `password` | Mantener con protección adecuada | Necesaria para autenticar. Se guarda solo como bcrypt (costo 12, sal única). Se exigen al menos 12 caracteres y como máximo 72 bytes (bcrypt trunca en silencio sobre ese límite). |
| users: `telefono` | Opcional | El despacho funciona con dirección y correo. Si el cliente lo entrega, va cifrado y puede eliminarlo después desde su perfil. |
| users: `fecha_nacimiento`, `sexo`, `foto`, `rut` | No recolectar (decisión preventiva) | No estaban en el esquema original, pero son campos que un e-commerce suele agregar "por si acaso". Se deja explícito que no tienen finalidad y el servidor los rechaza si llegan. Si en el futuro se vendieran productos con restricción de edad, bastaría guardar `mayor_de_edad = true` y la fecha de verificación, no la fecha de nacimiento. El RUT solo se pide en `facturacion`. |
| users: `direccion_despacho` | Mantener, cifrado | Es indispensable para entregar. |
| users: `comuna` | Mantener en claro | Se usa para el costo de envío y para la analítica agregada. Su granularidad es baja comparada con la dirección exacta. |
| users: `region` | Eliminar | Es redundante: se deriva de la comuna. |
| users: `token_pago` | Opcional | Solo se guarda si el cliente marca "guardar medio de pago", que viene desmarcado por defecto. Una restricción `CHECK` impide guardar token o last4 sin ese consentimiento. |
| users: `mascara_tarjeta` | Reducir a `tarjeta_last4` | La máscara `************4582` revela el largo del número de tarjeta. Los 4 últimos dígitos bastan para que el cliente reconozca su tarjeta. |
| facturacion: `rut`, `razon_social`, `direccion` | Opcional a nivel de flujo, cifrado | Solo se aceptan con `tipo_documento = FACTURA`. Una boleta que trae estos datos se rechaza. Ante una supresión de la cuenta se bloquean en vez de borrarse, por la obligación tributaria. |
| orders: `total` | Mantener, calculado en el servidor | Antes lo enviaba el cliente, lo que permitía manipularlo. Ahora se calcula desde el catálogo. |
| orders: `direccion_despacho_descifrada_logistica` | Eliminar y reemplazar por `direccion_envio_cifrada` | Estaba en texto plano. Se guarda una copia cifrada con el contexto de la orden: es la dirección vigente al comprar, que no cambia si el cliente edita su perfil después. |
| orders: `mascara_tarjeta_usada` | Reducir a `tarjeta_last4` | Mismo motivo que en `users`. |
| orders: `transaccion_id`, `codigo_autorizacion` | Mantener | Se necesitan para conciliar con la pasarela y atender reclamos. No identifican a la persona. |
| orders: `items` (JSON libre) | Reemplazar por `order_items` | Se normaliza: solo id de producto, cantidad y precio. |
| orders_invitado: `nombre`, `email`, `direccion` | Mantener cifrados, con plazo | Se necesitan durante la vida del pedido. A los 90 días de entregado o cancelado se anonimizan (pasan a `NULL`). |
| orders_invitado: `telefono` | Opcional | Mismo criterio que en `users`. |
| orders_invitado: `datos_checkout_temporal` | Eliminar | La tarjeta va directo a la pasarela. Guardar el volcado del formulario no tiene finalidad y es un riesgo. |
| loyalty_accounts: `hmac_firma` | Mantener + agregar `version` | La firma sin versión permitía restaurar una fila antigua junto con su firma válida. |
| historial_puntos | Mantener, 2 años | Respalda el saldo y permite verificarlo. Pasados 2 años se elimina (propuesta). |
| resenas: `user_id` | Reemplazar | Se reemplaza por `autor_pseudo` (HMAC) y un alias elegido por el cliente (ver Parte 2). Así se concreta la seudonimización que el Ítem I proponía para las reseñas. |
| carritos | Mantener, temporal | Se eliminan tras 30 días sin actividad (propuesta). |
| suscripciones_marketing: `email` | Mantener, cifrado | Es lo único necesario para enviar un boletín. |
| suscripciones_marketing: `nombre_contacto` | Eliminar | El boletín funciona solo con el correo. |
| suscripciones_marketing: consentimiento | Agregar fecha, versión y revocación | El Ítem I exigía consentimiento explícito (opt-in), pero el esquema no tenía dónde registrarlo. Estas columnas sirven como prueba del consentimiento ante la Ley 21.719. |
| vault: `pan_hash`, `card_holder` | Eliminar de NortiShop | La custodia de la tarjeta es de la pasarela. Un SHA-256 sin sal de un número de tarjeta se revierte por fuerza bruta. |

### 2.4 Alternativas para reducir aún más

- **Verificación de edad:** guardar un booleano `mayor_de_edad` y la fecha de verificación en vez de la fecha de nacimiento.
- **Dirección:** si el negocio usara puntos de retiro, solo se necesitaría la comuna y el punto, no la dirección exacta.
- **Teléfono:** dejarlo solo en `orders` mientras el envío esté activo, sin copiarlo al perfil.
- **Analítica:** usar mes y rango de monto en lugar de fecha y monto exactos (ya implementado).

### 2.5 Aporte del nuevo diseño a la privacidad

- **Menos datos:** se eliminan o se sacan de NortiShop 6 campos (región, dirección en claro de la orden, volcado del checkout, nombre de contacto, huella y titular de la tarjeta), y otros 6 pasan a ser opcionales o se reducen. Menos datos significa menor impacto si hay una filtración y menos obligaciones de custodia.
- **Plazos definidos:** el inventario anterior tenía todos los plazos como "No indicado". Ahora hay plazos para invitados (90 días desde la entrega), carritos (30 días) e historial de puntos (2 años), y un procedimiento de supresión para el titular.
- **El código hace cumplir el diseño:**
  - `soloCampos()` rechaza en el servidor cualquier campo no previsto.
  - El repositorio rechaza columnas fuera del esquema (`BD_COLUMNA_NO_PERMITIDA`).
  - El repositorio también rechaza texto plano en columnas protegidas (`BD_TIPO_INVALIDO`), así un error de programación no puede guardar datos sin cifrar.
- **Los datos tienen fecha de término:** invitados, carritos e historial tienen plazos de conservación, y existe un procedimiento de supresión para el titular.

---

## 3. Parte 2 — Seudonimización y anonimización

### 3.1 Conceptos aplicados

- **Seudonimización:** reemplazamos identificadores directos por HMAC-SHA256 con una llave secreta por finalidad. Sin la llave o sin la tabla `pseudo.pseudonimos` no se puede volver al `user_id`. Con ellas sí, así que el dato sigue siendo personal y se protege como tal.
- **Anonimización:** transformamos los datos para que nadie pueda ser identificado razonablemente, ni cruzándolos con otras fuentes. Para eso agregamos, suprimimos grupos pequeños y borramos irreversiblemente los datos de contacto.

### 3.2 Dónde se aplica cada técnica

| Tabla / proceso | Técnica | Cómo se implementa | Qué protege | Por qué es adecuada |
|---|---|---|---|---|
| Login (`users.email_hmac`) | Seudonimización (índice ciego) | `indiceCiegoEmail()` = HMAC(K_indice, email normalizado) | El correo, que ya no se descifra para buscar al usuario | Hace falta una búsqueda exacta y determinista. Un hash sin llave sería vulnerable a diccionario. |
| Reseñas (`resenas.autor_pseudo`) | Seudonimización | HMAC(K_resenas, user_id) + alias público. La vista `v_resenas_publicas` no expone el seudónimo. | La identidad del autor frente al público y frente a quien lea la tabla | Hay que poder agrupar las reseñas de un mismo autor (moderación, spam) y atender derechos del titular, por lo que debe ser reversible para el oficial de privacidad. |
| Analítica (`analitica.compras`, `movimientos_puntos`) | Seudonimización + generalización | Un ETL (`ejecutarEtlAnalitica`) calcula HMAC(K_analitica, user_id) y usa mes en vez de fecha, rango en vez de monto, categoría en vez de producto y comuna en vez de dirección. Suprime ids de pedido, transacción, autorización, tarjeta y dirección. | Hábitos de compra vinculados a una persona | El análisis de recurrencia necesita seguir al mismo cliente en el tiempo, pero no saber quién es. |
| Reporte de ventas (`analitica.v_ventas_por_comuna`) | Anonimización (agregación + k-anonimato, k = 5) | `GROUP BY` comuna, mes y categoría, con `HAVING COUNT(DISTINCT cliente) >= 5` | Que una persona sea identificable en un grupo pequeño | Lo consumen roles amplios (administrador, marketing). No necesita reversibilidad. |
| Marketing (`v_export_marketing`) | Seudonimización | HMAC(K_marketing, user_id) + token de baja aleatorio. Solo se exportan consentimientos vigentes. | El `user_id` interno frente a la plataforma de correo (proveedor externo) | El proveedor necesita el correo para enviar, pero no el identificador interno. Los seudónimos de otras finalidades no se pueden cruzar con este. |
| Logística (`envios.ref_envio`) | Seudonimización (referencia aleatoria) | UUID v4 sin relación con el pedido. La etiqueta solo lleva nombre, dirección y comuna. | `order_id`, `user_id`, email, teléfono y monto frente al courier | El courier solo necesita saber dónde y a quién entregar. |
| Invitados (`orders_invitado`) | Anonimización | `anonimizarInvitadosVencidos()`: a los 90 días de entregado o cancelado, pone en `NULL` nombre, email, teléfono y dirección | El contacto de personas sin cuenta | Al vencer la finalidad no queda motivo para conservarlo. Se mantienen total y estado por la obligación contable. |
| Supresión de cuenta | Anonimización por desvinculación | Se borran el usuario y sus filas en `pseudo.pseudonimos`. Las reseñas y los datos analíticos quedan sin forma de atribuirse. | Al titular que ejerce su derecho de supresión | No se pierden las estadísticas, pero dejan de estar vinculadas a la persona. |
| Desarrollo y pruebas | Datos sintéticos / anonimización | `src/dev/escenario.js` (dominio `.test`) y `generarCopiaDesarrollo()`, que regenera ids y reemplaza la PII por datos ficticios, sin hashes, tokens ni criptogramas | Datos reales en ambientes menos protegidos | Los ambientes de desarrollo tienen más accesos y menos controles. |

### 3.3 Ejemplos concretos (salida de `npm start`)

**Reseña.** En la tabla se guarda solo el seudónimo y el alias; la vista pública muestra únicamente el alias:

```json
// Fila almacenada en resenas
{ "autor_pseudo": "566983cb…8db20", "alias_publico": "ana_p", "calificacion": 5,
  "comentario": "&#60;b&#62;Muy bueno&#60;&#47;b&#62;" }
// Vista pública
{ "alias_publico": "ana_p", "calificacion": 5, "comentario": "…", "fecha": "2026-10-25" }
```

**Analítica.** Lo único que ve el rol analista:

```json
{ "cliente_pseudo": "90fae728…be0e", "mes_compra": "2026-10-01", "rango_monto": "20-50k",
  "categoria_producto": "VESTUARIO", "comuna": "Antofagasta" }
```

**Reporte k = 5.** Cinco clientes de Antofagasta compraron en HOGAR y aparecen en el reporte. El único cliente de Calama se suprime.

**Invitado.** El mismo día de la entrega, el job anonimiza 0 registros. A los 91 días anonimiza 1, y la fila queda con `nombre`, `email` y `direccion` en `null`, conservando `total_clp` y `estado`.

### 3.4 Restricciones sobre la información que permite revertir la seudonimización

- **Separación de llaves:** las llaves K_indice, K_resenas, K_analitica y K_marketing son distintas (el llavero lo exige al cargar). Solo `src/crypto/` puede usarlas, y una prueba lo verifica revisando el código fuente. Ningún rol tiene el permiso `llaves:acceder`.
- **Separación de la tabla de equivalencias:** `pseudo.pseudonimos` vive en su propio esquema, con `REVOKE ALL FROM PUBLIC`. Solo el rol de BD `svc_privacidad` puede leerla. La prueba *"Tabla de equivalencias: solo svc_privacidad puede leerla"* confirma que `svc_app`, `svc_etl`, `rol_analista`, `rol_marketing` y `rol_publico` reciben `BD_PERMISO_DENEGADO`.
- **Reidentificación excepcional:**
  - Solo el rol `OFICIAL_PRIVACIDAD` tiene el permiso `seudonimos:revertir`; el administrador no lo tiene.
  - Se exige un motivo documentado de al menos 15 caracteres.
  - Cada reidentificación queda registrada en `audit_log`.

### 3.5 Registros de actividad, reportes, pruebas y desarrollo

- **Registros de actividad** (`src/security/logger.js`): la redacción es automática en dos niveles:
  - Por nombre de campo (`email`, `password`, `direccion`, `token`, `*_cifrado`…).
  - Por patrón dentro de textos libres (correos, números de tarjeta, hashes bcrypt, tokens, criptogramas).
  - Los logs identifican al usuario por su id interno y, en los fallos de login, por un prefijo del índice ciego, nunca por el correo.
- **Auditoría:** registra actor, rol, acción, recurso (tipo e id), resultado y motivo, sin contenido personal. La aplicación solo puede insertar en ella: no hay `UPDATE` ni `DELETE`.
- **Reportes:** los roles amplios solo acceden a la vista agregada con k = 5.
- **Pruebas:** usan llaves efímeras generadas en cada ejecución (`scripts/entorno-pruebas.js`) y datos sintéticos.
- **Desarrollo:** nunca se copia producción. Se usa `generarCopiaDesarrollo()`, que solo puede ejecutar el oficial de privacidad y queda auditada.

---

## 4. Parte 3 — Modelo RBAC

### 4.1 Roles y responsabilidades

| Rol | Responsabilidad |
|---|---|
| **ADMINISTRADOR** | Gestiona cuentas del personal y sus roles, revisa la auditoría y supervisa pedidos. No accede a PII completa ni a llaves. |
| **OFICIAL_PRIVACIDAD** (DPO) | Ejecuta los procesos de privacidad (ETL, anonimización, copia de desarrollo) y la reidentificación excepcional. |
| **SOPORTE** | Atiende reclamos. Ve datos enmascarados y puede revelar el contacto completo con ticket y motivo. |
| **LOGISTICA** | Prepara despachos: ve envíos pendientes, genera etiquetas y actualiza estados. |
| **CATALOGO** | Mantiene productos, precios y stock. |
| **MARKETING** | Envía campañas solo a suscriptores con consentimiento vigente. |
| **ANALISTA** | Analiza el negocio con datos seudonimizados y agregados. |
| **CLIENTE** | Usuario final: gestiona su perfil, pedidos, puntos, reseñas y consentimientos. |

Los clientes invitados no tienen rol: acceden solo a su pedido mediante un token de seguimiento aleatorio.

### 4.2 Matriz de permisos (generada con `npm run matriz`)

| Permiso | ADMINISTRADOR | OFICIAL_PRIVACIDAD | SOPORTE | LOGISTICA | CATALOGO | MARKETING | ANALISTA | CLIENTE |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `roles:gestionar` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `auditoria:leer` | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `perfil:propio:leer` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (solo propio) |
| `perfil:propio:editar` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (solo propio) |
| `cuenta:propia:suprimir` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (solo propio) |
| `pedido:crear` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| `pedidos:propios:leer` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (solo propio) |
| `puntos:propios` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (solo propio) |
| `resena:publicar` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| `consentimiento:propio` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (solo propio) |
| `clientes:buscar:enmascarado` | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `clientes:pii:revelar` | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `pedidos:gestionar` | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `envios:gestionar` | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `catalogo:gestionar` | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| `marketing:exportar` | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| `analitica:leer` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| `reportes:agregados` | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| `privacidad:procesos` | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `seudonimos:revertir` | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `llaves:acceder` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

La misma matriz, en el formato del enunciado:

| Acción o recurso | Administrador | Personal autorizado | Usuario final |
|---|---|---|---|
| Gestionar roles y permisos | Permitido; nunca sobre su propia cuenta | Denegado | Denegado |
| Consultar datos propios | Su cuenta de personal | Su cuenta de personal | Permitido |
| Consultar datos de otros usuarios | Solo la vista enmascarada | SOPORTE: enmascarado por defecto y completo con ticket y motivo (auditado). LOGISTICA: solo nombre y dirección en la etiqueta. Otros roles: denegado. | Denegado (se verifica que el recurso sea propio) |
| Modificar información sensible | Solo roles del personal | Según la función: LOGISTICA el estado de envío, CATALOGO precios y stock | Solo la propia: teléfono, dirección, medio de pago, supresión |
| Revertir seudónimos | Denegado | Solo OFICIAL_PRIVACIDAD, con motivo y auditoría | Denegado |
| Acceder a claves criptográficas | Denegado: solo el proceso de la aplicación, vía `src/crypto/` | Denegado | Denegado |

### 4.3 Accesos denegados explícitos

- **ADMINISTRADOR:** no puede revelar PII completa, revertir seudónimos, leer analítica fila a fila, ni cambiar su propio rol o desactivarse. Así se evita que acumule poder sin control (separación de funciones).
- **OFICIAL_PRIVACIDAD:** no puede gestionar roles, ver perfiles de clientes ni editar el catálogo.
- **SOPORTE:** no puede ver contraseñas, tokens de pago, puntos ni analítica, y no puede exportar suscriptores.
- **LOGISTICA:** no ve email, teléfono, monto, `order_id` ni `user_id`; solo `ref_envio` y los datos de la etiqueta.
- **MARKETING:** no ve `user_id`, nombre, dirección, ni a suscriptores que revocaron su consentimiento; tampoco la analítica fila a fila.
- **ANALISTA:** no accede a ninguna tabla operativa (`users`, `orders`…), ni a `pseudo`, ni a datos de contacto.
- **CLIENTE:** no accede a ningún recurso de otro cliente ni a operaciones del personal.

### 4.4 Control de acceso a información sensible y operaciones administrativas

1. **Autenticación** (`authService.js`):
   - Búsqueda por índice ciego.
   - Respuesta única "Credenciales inválidas", con bcrypt señuelo para no revelar por tiempo si el correo existe.
   - Bloqueo de 15 minutos tras 5 intentos fallidos.
   - Token de sesión de 256 bits, del que la BD guarda solo su SHA-256.
2. **Autorización en el servidor** (`rbac.js → autorizar()`): cada servicio la invoca antes de operar, sin depender de la interfaz.
   - Lista blanca: todo lo que no está concedido está denegado.
   - Para los permisos "propios" se verifica `propietarioId === sesion.usuarioId`.
   - Toda denegación se audita.
3. **Revocación inmediata:** el rol del personal se relee en cada solicitud. Cambiar o desactivar una cuenta afecta de inmediato a sus sesiones abiertas.
4. **Acceso privilegiado justificado:** revelar PII y revertir seudónimos exigen motivo (y ticket en soporte) y quedan auditados.
5. **Base de datos** (`03_rbac.sql` y `GRANTS` en `repository.js`): cada servicio tiene su propia credencial de BD:

| Rol de BD | Puede |
|---|---|
| `svc_app` | Operación diaria, sin acceso a `pseudo.*` ni `analitica.*`. Sobre `audit_log` solo puede insertar. |
| `svc_privacidad` | Única con acceso a `pseudo.pseudonimos`. En `orders_invitado` solo puede anular los campos de contacto. |
| `svc_etl` | Lee lo mínimo de las tablas operativas y escribe solo en `analitica`. |
| `rol_analista` | Solo el esquema `analitica`. |
| `rol_marketing` | Solo `v_export_marketing`. |
| `rol_publico` | Solo `v_resenas_publicas`. |

Como propuesta de defensa en profundidad para producción se incluye Row-Level Security sobre `users` y `orders`.

---

## 5. Parte 4 — Implementación en el código

### 5.1 Arquitectura

Las solicitudes entran por `API` (`src/api.js`), que equivale a los controladores HTTP del servidor. Desde ahí:

1. `resolverSesion()` valida el token.
2. El servicio llama a `autorizar()`, valida los datos con `soloCampos()` y luego los procesa.
3. Para leer o escribir usa una conexión con el rol de BD que le corresponde, y la base valida esquema, tipos y permisos.

Cualquier error se convierte en una respuesta `{ codigo, estado, mensaje }` segura.

### 5.2 Implementación por requisito

| Requisito | Implementación | Archivos |
|---|---|---|
| Validaciones para no almacenar datos innecesarios | `soloCampos()` declara campos obligatorios y opcionales por operación y rechaza el resto. Hay reglas condicionales (tarjeta solo con `guardarMedioPago`, facturación solo con `FACTURA`). La BD rechaza columnas fuera del esquema y texto plano en columnas protegidas. | `security/validation.js`, `services/userService.js`, `services/orderService.js`, `db/repository.js` |
| Protección de campos sensibles | AES-256-GCM con IV aleatorio y AAD obligatorio `<tabla>.<campo>:<id>`: copiar un criptograma a otro registro o columna hace fallar el descifrado. Tarjeta tokenizada, guardando solo `last4`. Saldos con HMAC + versión + historial. | `crypto/cipher.js`, `crypto/tokenization.js`, `services/loyaltyService.js` |
| Gestión de contraseñas | bcrypt (costo configurable de 10 a 16), política de 12 caracteres a 72 bytes, bcrypt señuelo y bloqueo por intentos. | `crypto/hashing.js`, `services/authService.js` |
| Gestión de llaves | Seis llaves de 256 bits, una por finalidad, que deben ser distintas entre sí. Se validan al iniciar y se eliminan de `process.env`. `.env.example` no contiene secretos. `npm run generar-env` las crea sin imprimirlas. | `crypto/keyring.js`, `scripts/generar-env.js` |
| Seudonimización y anonimización | Índice ciego, seudónimos por finalidad, ETL con generalización, reporte k = 5, job de invitados, supresión y copia de desarrollo. | `crypto/pseudonymization.js`, `services/privacyService.js`, `services/reviewService.js`, `services/marketingService.js` |
| Autenticación y autorización por roles | Sesiones con token aleatorio, `autorizar()` con matriz y verificación de propiedad, roles del personal releídos en cada solicitud. | `security/rbac.js`, `services/authService.js` |
| Restricciones en servidor y BD | Autorización en cada servicio y GRANTS por rol de BD en el repositorio y en `03_rbac.sql`. | `services/*`, `db/repository.js`, `03_rbac.sql` |
| Manejo seguro de errores y registros | `AppError` con mensaje público. Los errores internos devuelven un texto genérico y el detalle va redactado al log. Los mensajes de validación no repiten el dato ingresado. La auditoría no guarda contenido. | `security/errors.js`, `security/logger.js`, `security/audit.js`, `api.js` |

Fragmento clave: el punto único de autorización (`src/security/rbac.js`):

```js
export function autorizar(sesion, permiso, { propietarioId, recurso } = {}) {
  if (!sesion?.usuarioId || !sesion?.rol) throw errores.noAutenticado();
  let motivo = null;
  if (!tienePermiso(sesion.rol, permiso)) motivo = 'ROL_SIN_PERMISO';
  else if (PERMISOS_PROPIOS.has(permiso) && propietarioId !== sesion.usuarioId) motivo = 'RECURSO_AJENO';
  if (motivo) {
    registrarAuditoria({ sesion, accion: permiso, recurso, resultado: 'DENEGADO', motivo });
    throw errores.accesoDenegado();
  }
}
```

---

## 6. Evidencias de pruebas

`npm test` ejecuta 50 pruebas. Resultado: **50 aprobadas, 0 fallidas**.

| Archivo | Qué demuestra (casos destacados) |
|---|---|
| `criptografia.test.js` (7) | Llaves retiradas de `process.env` y `.env.example` sin secretos. bcrypt con sal, política y señuelo. AES-GCM: el criptograma de otro registro u otra columna falla, igual que uno alterado o con el tag truncado. La firma de puntos depende de la versión. Los seudónimos no se pueden cruzar entre finalidades. La tokenización no conserva el número de tarjeta. |
| `minimizacion.test.js` (7) | Se rechazan `fecha_nacimiento`, `sexo`, `rut` y `foto`. La tarjeta no se acepta sin consentimiento. Una boleta con RUT se rechaza. Un total enviado por el cliente se rechaza. La BD rechaza columnas extra y texto plano. El volcado físico no contiene ningún dato personal, contraseña ni número de tarjeta. El perfil no expone el token. |
| `seudonimizacion.test.js` (9) | Reseñas con seudónimo y XSS neutralizado. `pseudo` es inaccesible para 5 roles de BD. La reidentificación solo funciona para el DPO con motivo. Analítica generalizada. k = 5 suprime grupos pequeños. Anonimización de invitados a los 91 días. Supresión de cuenta completa. Copia de desarrollo sin datos reales. Ataques de repetición y manipulación de puntos detectados. |
| `rbac.test.js` (23) | 14 operaciones probadas contra los 8 perfiles: 112 combinaciones de acceso permitido o denegado. Además: sin sesión, recurso ajeno, auditoría de denegaciones, soporte enmascarado, logística mínima, prohibición de auto-escalamiento, revocación inmediata, login sin enumeración con bloqueo, y nadie con acceso a llaves. |
| `registros.test.js` (4) | La redacción funciona. Tras un flujo completo los logs no contienen datos personales. Un error interno devuelve un mensaje genérico. Los errores de validación no repiten el dato ingresado. |

Extracto de la ejecución de la demo (`npm start`), sección RBAC:

```text
⛔ ACCESO_DENEGADO   CLIENTE (Bruno) lee el perfil de Ana
✔ PERMITIDO         CLIENTE (Ana) lee su propio perfil
⛔ ACCESO_DENEGADO   ANALISTA intenta buscar un cliente por email
✔ PERMITIDO         SOPORTE busca cliente (vista enmascarada)  → { "nombre": "A. P. U.", "email": "a***@e***.test" }
⛔ DATO_INVALIDO     SOPORTE revela PII sin ticket válido
✔ PERMITIDO         SOPORTE revela PII con ticket y motivo
⛔ ACCESO_DENEGADO   ADMINISTRADOR intenta revelar PII
⛔ ACCESO_DENEGADO   ADMINISTRADOR se auto-asigna OFICIAL_PRIVACIDAD
⛔ ACCESO_DENEGADO   Misma sesión intenta exportar suscriptores (tras cambiar MARKETING → ANALISTA)
⛔ CREDENCIALES_INVALIDAS  Email inexistente
⛔ CREDENCIALES_INVALIDAS  Email existente, clave incorrecta
⛔ INTEGRIDAD_COMPROMETIDA Atacante restaura fila antigua con firma válida
```

*(Para la entrega se recomienda adjuntar capturas de `npm test` y de `npm start`.)*

---

## 7. Conclusión técnica

### Mejoras alcanzadas

- **Datos:** se eliminaron o sacaron de NortiShop 6 campos y se redujeron o volvieron opcionales otros 6. Ningún dato personal queda en texto plano en reposo, y el código impide reintroducirlos.
- **Brechas del informe anterior:** se cerraron las que señalaba el Informe de Análisis: control de accesos, plazos de conservación, procedimiento de supresión y dirección en texto plano.
- **Criptografía:**
  - Los criptogramas quedan amarrados a su registro y columna (AAD).
  - El login ya no descifra la base completa.
  - La firma de puntos resiste ataques de repetición.
  - Hay una llave por finalidad.
- **Seudonimización y anonimización:** la exposición se redujo para cada consumidor de datos (público, analistas, marketing, courier, desarrolladores), y la reidentificación está restringida al DPO y auditada.
- **RBAC:** 8 roles con mínimo privilegio aplicado en dos capas (servidor y BD), con revocación inmediata y auditoría de cada denegación.

### Limitaciones

- **Prototipo en memoria:** la BD y la pasarela son simulaciones. Los GRANTS se aplican por tabla; los permisos por columna y la RLS de `03_rbac.sql` no se simulan.
- **Llaves:** vienen de `.env`. En producción deben venir de un KMS o gestor de secretos con rotación, y el prototipo no implementa la re-cifra al rotar.
- **Detección de manipulación de puntos:** si un atacante con acceso de escritura borra filas del historial y además restaura la cuenta a esa versión, la manipulación no se detecta. Se requiere un ancla externa (log inmutable o WORM).
- **El registro revela si un correo existe:** un correo ya registrado produce un error distinto. Lo habitual es responder siempre "revise su correo".
- **Pedidos tras la supresión:** se conserva el `user_id` en los pedidos. Quien tenga K_resenas o K_analitica podría vincular las reseñas o la analítica de un titular suprimido con sus pedidos. Ninguno de ellos contiene datos de contacto.
- **No implementado:**
  - La cancelación no reembolsa ni repone stock.
  - No hay limpieza automática de carritos ni del historial.
  - Bloqueo y sesiones se guardan en memoria del proceso.

### Riesgos que deben mitigarse

1. Integrar un KMS con rotación de llaves y re-cifra planificada.
2. Agregar MFA para los roles del personal, al menos ADMINISTRADOR, SOPORTE y OFICIAL_PRIVACIDAD.
3. Llevar la auditoría a almacenamiento inmutable, con alertas ante revelaciones de PII anómalas.
4. Implementar los jobs de conservación pendientes (carritos a 30 días, historial a 2 años) y monitorear su ejecución.
5. Evaluar privacidad diferencial o k mayor si los reportes se publican externamente.
6. Revisar el flujo de registro para eliminar la enumeración de correos.
