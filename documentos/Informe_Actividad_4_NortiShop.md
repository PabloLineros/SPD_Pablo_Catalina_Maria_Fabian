# Actividad N.° 4 - Rediseño seguro de NortiShop

**Curso:** Seguridad y Protección de Datos
**Equipo:** Catalina Toledo, María Gerónimo y Pablo Lineros
**Fecha:** 25 de octubre de 2026

## 1. Resumen ejecutivo

NortiShop es una plataforma de comercio electrónico que procesa cuentas de clientes, pedidos, medios de pago, fidelización y reseñas. El rediseño aplica minimización, privacidad por defecto, cifrado autenticado, hashing de contraseñas, tokenización de pagos, seudonimización y RBAC.

La propuesta separa los datos operativos de los identificadores indirectos, conserva únicamente los datos necesarios para comprar y entregar, y elimina información que no tiene una finalidad funcional. La implementación ejecutable se encuentra en `ITEM2/src` y las decisiones SQL en `01_minimizacion.sql` y `02_seudonimizacion.sql`.

> El sistema es una demostración académica. La bóveda de pagos y la base de datos son simuladas y no constituyen certificación PCI DSS ni cumplimiento legal automático.

## 2. Esquema original y rediseñado

### 2.1 Esquema original analizado

El esquema anterior del caso contemplaba, entre otros elementos:

- `users`: nombre, correo, contraseña, dirección, RUT, fecha de nacimiento, sexo, foto, teléfono secundario y datos de tarjeta.
- `orders`: usuario, productos, monto, transacción, autorización, máscara de tarjeta y dirección de despacho en texto plano para logística.
- `vault`: PAN, titular, vencimiento, CVV y hash del PAN.
- `suscripciones_marketing`: correo y nombre de contacto.
- `resenas`: relación directa entre reseña y `user_id`.
- `loyalty_accounts`: saldo de puntos y datos de integridad.

El problema principal era mezclar identificadores directos, PII y datos operativos, además de conservar atributos que no eran necesarios para completar una compra.

### 2.2 Esquema rediseñado

El esquema implementado y documentado queda compuesto por:

- `users`: UUID, nombre cifrado, correo cifrado, índice ciego HMAC del correo, teléfono cifrado opcional, dirección de despacho cifrada, `password_hash`, token de pago opcional, marca y últimos cuatro dígitos.
- `facturacion`: RUT, razón social y dirección de facturación cifrados, solo cuando el cliente solicita factura.
- `orders` y `order_items`: referencias de usuario y productos, monto, transacción, autorización, estado, dirección de envío cifrada y últimos cuatro dígitos.
- `orders_invitado`: datos de contacto cifrados con fecha de eliminación obligatoria.
- `loyalty_accounts` e `historial_puntos`: saldo, versión, firma HMAC, motivo y fecha.
- `resenas`: autor seudonimizado y alias público; la vista pública no expone el identificador interno.
- `analitica.compras` y `analitica.movimientos_puntos`: datos generalizados por mes, rango de monto y categoría.
- `pseudo.pseudonimos`: tabla separada de equivalencias, accesible solo al servicio de privacidad.
- `envios`: referencia opaca para el operador logístico, sin `user_id`, correo o monto.

La definición completa se encuentra en [01_minimizacion.sql](../01_minimizacion.sql) y [02_seudonimizacion.sql](../02_seudonimizacion.sql).

### 2.3 Tabla de decisiones de minimización

| Tabla y campo | Decisión | Justificación y alternativa |
|---|---|---|
| `users.nombre` | Mantener y cifrar | Se necesita para atención, boleta y despacho. No debe estar en texto plano. |
| `users.email` | Mantener, cifrar y añadir HMAC | Es necesario para autenticación y notificaciones. El HMAC permite buscar sin descifrar toda la tabla. |
| `users.password` | Mantener como hash bcrypt | Es necesaria para autenticación; nunca se almacena en texto plano ni se cifra de forma reversible. |
| `users.direccion_despacho` | Mantener y cifrar | Es necesaria para entregar. Se descifra solo bajo demanda en el servicio autorizado. |
| `users.telefono` | Opcional y cifrado | Puede ayudar a coordinar la entrega, pero el sistema funciona con correo y dirección. |
| `users.fecha_nacimiento` | Eliminar | No es necesaria para comprar. Si se requiriera mayoría de edad, se conservaría solo un resultado booleano y fecha de verificación. |
| `users.sexo` | Eliminar | No tiene finalidad funcional para el comercio y aumenta el riesgo de discriminación o exposición. |
| `users.foto` | Eliminar | No es necesaria para comprar, autenticar ni entregar. |
| `users.RUT` | Eliminar del perfil general | Solo se requiere para facturación; debe estar en `facturacion` y cifrado, bajo solicitud de factura. |
| `users.medio_pago` | Opcional | Se guarda solo si el usuario opta explícitamente por guardar el medio de pago. |
| PAN y CVV | No almacenar en NortiShop | Se envían a una pasarela externa; NortiShop conserva un token opaco y no el PAN/CVV. |
| Máscara de tarjeta | Reducir a `last4` | Mostrar solo cuatro dígitos satisface la UX y reduce exposición del número. |
| `orders.direccionDespachoDescifradaLogistica` | Eliminar | La dirección plana no debe persistir. Se reemplaza por `direccion_envio_cifrada` y descifrado just-in-time. |
| `orders.transaccion_id` y autorización | Mantener | Son necesarios para conciliación, reclamos y auditoría; no contienen el PAN. |
| `suscripciones_marketing.nombre_contacto` | Eliminar | El boletín necesita el correo y el consentimiento, no el nombre. |
| Datos de invitado | Mantener temporalmente y anonimizar | Se requieren para entregar; se eliminan al vencer el plazo y cuando el pedido está entregado o cancelado. |
| Carritos | Mantener temporalmente | Se eliminan después de 30 días sin actividad. |

## 3. Seudonimización y anonimización

### 3.1 Seudonimización

La seudonimización sustituye identificadores directos por códigos, pero permite reidentificación controlada si se accede a la tabla de equivalencias.

Se aplica en:

- **Reseñas:** `autor_pseudo = HMAC(K_resenas, user_id)` y `alias_publico`. La vista `v_resenas_publicas` solo presenta producto, alias, calificación, comentario y fecha.
- **Analítica:** `cliente_pseudo = HMAC(K_analitica, user_id)`. Se elimina el `order_id`, la transacción, autorización, tarjeta y dirección exacta.
- **Marketing:** `suscriptor_pseudo = HMAC(K_marketing, user_id)` y token de desuscripción aleatorio.
- **Logística:** `ref_envio` aleatoria. El operador recibe solo esa referencia, nombre y dirección necesarios para la etiqueta.

Las claves `K_resenas`, `K_analitica` y `K_marketing` deben estar en un gestor de secretos. `pseudo.pseudonimos` no se expone a usuarios, analistas, marketing ni al operador logístico. Solo el servicio de privacidad puede resolver un seudónimo, con autorización, trazabilidad y finalidad determinada.

### 3.2 Anonimización

La anonimización busca impedir razonablemente la identificación, por lo que no se conserva una equivalencia utilizable.

- Los reportes de ventas se agregan por mes, comuna generalizada, categoría y rango de monto.
- Se aplica umbral `k = 5`: grupos con menos de cinco clientes distintos se suprimen.
- Los datos de contacto de invitados se establecen en `NULL` al vencer `eliminar_contacto_desde` y cuando el pedido está entregado o cancelado.
- Los reportes de desarrollo no deben contener correos, direcciones, PAN, tokens reales ni nombres reales; se emplean datos sintéticos.

La agregación con umbral reduce el riesgo de inferencia, pero no garantiza anonimización absoluta frente a fuentes externas. Por eso se debe revisar el riesgo de vinculación antes de publicar reportes.

## 4. Modelo RBAC

### 4.1 Roles

| Rol | Responsabilidad | Permisos | Restricciones |
|---|---|---|---|
| `customer` | Comprar y administrar su cuenta | Leer perfil propio, crear pedidos, consultar sus puntos | No puede leer otros perfiles, gestionar roles, consultar claves ni acceder a equivalencias. |
| `support` | Resolver consultas operativas | Leer perfiles y pedidos cuando la función lo justifique | No puede modificar roles, leer claves, ver PAN, consultar equivalencias ni exportar toda la base. |
| `admin` | Administración controlada | Gestionar usuarios/roles, consultar recursos operativos y autorizar operaciones | El acceso a claves se realiza mediante mecanismos técnicos autorizados; no se muestran indiscriminadamente. |
| `privacy-service` | Resolver seudónimos y ejecutar retención | Acceder a `pseudo.pseudonimos` y ejecutar anonimización | No debe usar la tabla para fines comerciales ni entregar la equivalencia a otros roles. |
| `analyst` | Analizar indicadores | Leer únicamente el esquema `analitica` | No puede consultar tablas operativas, PII ni la tabla de equivalencias. |
| `marketing` | Gestionar comunicaciones consentidas | Leer únicamente la vista de exportación vigente | No puede leer perfiles completos ni datos de pago. |

### 4.2 Matriz de permisos

| Acción o recurso | `admin` | `support` | `customer` | `analyst` | `marketing` |
|---|---:|---:|---:|---:|---:|
| Gestionar roles y permisos | Permitido | Denegado | Denegado | Denegado | Denegado |
| Consultar perfil propio | Permitido | Permitido | Permitido | Denegado | Denegado |
| Consultar perfil de otro usuario | Según función | Según función | Denegado | Denegado | Denegado |
| Crear pedido propio | Permitido | Denegado | Permitido | Denegado | Denegado |
| Consultar pedidos operativos | Permitido | Según función | Solo propios | Denegado | Denegado |
| Consultar datos analíticos agregados | Permitido | Denegado | Denegado | Permitido | Denegado |
| Acceder a exportación de marketing | Permitido | Denegado | Denegado | Denegado | Permitido |
| Acceder a `pseudo.pseudonimos` | Solo mediante servicio | Denegado | Denegado | Denegado | Denegado |
| Acceder a PAN/CVV | Denegado; lo gestiona la pasarela | Denegado | Denegado | Denegado | Denegado |
| Acceder a claves criptográficas | Mediante gestor autorizado | Denegado | Denegado | Denegado | Denegado |

La aplicación implementa `admin`, `support` y `customer` en [accessControl.js](../ITEM2/src/security/accessControl.js). Las restricciones de base de datos se documentan mediante `REVOKE`, vistas y separación de esquemas en `02_seudonimizacion.sql`.

## 5. Implementación en código

- **Contraseñas:** bcrypt con costo configurable y validado entre 10 y 16; las pruebas usan costo 12.
- **PII:** AES-256-GCM con IV aleatorio y etiqueta de autenticación.
- **Pagos:** tokenización simulada; el PAN, vencimiento y CVV no se almacenan en `users`.
- **Índice ciego:** HMAC con secreto de entorno para localizar el correo sin guardarlo como clave de búsqueda plana.
- **Órdenes:** dirección persistida como `direccion_envio_cifrada`; la antigua dirección plana no se genera.
- **Minimización:** solo se conserva `tarjeta_last4`; teléfono opcional; no se aceptan registros sin campos funcionalmente obligatorios.
- **RBAC:** `assertPermission` rechaza roles inválidos y accesos de un cliente a recursos de otro usuario.
- **Errores:** las operaciones devuelven errores genéricos de autorización y no imprimen secretos, PAN ni contraseñas.
- **Configuración:** las claves se leen desde `.env`, excluido por Git; las pruebas usan únicamente secretos sintéticos en `test/setup.js`.

## 6. Evidencias de pruebas

Desde `ITEM2`:

```bash
npm test
```

Resultado obtenido el 25-10-2026:

```text
7 tests, 7 pass, 0 fail
```

Los casos cubren:

1. Salting y verificación de bcrypt.
2. Cifrado AES-256-GCM y rechazo de ciphertext alterado.
3. Tokenización y aislamiento del PAN.
4. Rechazo de modificaciones al saldo protegido con HMAC.
5. Flujo completo con persistencia cifrada.
6. Acceso RBAC propio permitido y acceso cruzado denegado.
7. Perfil administrativo permitido y dirección de orden cifrada sin campo plano.

Las capturas de referencia entregadas por el equipo se encuentran en [Img](../Img). Deben incorporarse al documento final como evidencia visual de la ejecución y del sistema. El código de pruebas está en [security.test.js](../ITEM2/test/security.test.js).

## 7. Limitaciones y riesgos pendientes

- La base de datos y la bóveda son simulaciones en memoria; falta integración con PostgreSQL, un proveedor de pagos real y un gestor de secretos.
- La rotación de claves, recuperación ante desastre y revocación de sesiones requieren un diseño operativo adicional.
- El HMAC no reemplaza una política completa de control de acceso a la base de datos ni auditoría inmutable.
- Los reportes agregados deben someterse a revisión de riesgo de inferencia y vinculación antes de publicarse.
- Se requiere implementar rate limiting, MFA para roles privilegiados, gestión de sesiones, validación de entradas y monitoreo centralizado en un ambiente productivo.

## 8. Conclusión

El rediseño reduce la cantidad y el detalle de datos almacenados, separa finalidades, evita conservar PAN/CVV y elimina direcciones planas persistentes. La seudonimización limita la exposición en reseñas, analítica, marketing y logística, mientras que la anonimización elimina el vínculo cuando ya no existe una finalidad legítima. Finalmente, RBAC aplica mínimo privilegio y las pruebas demuestran accesos permitidos, accesos rechazados, cifrado, hashing, tokenización e integridad.
