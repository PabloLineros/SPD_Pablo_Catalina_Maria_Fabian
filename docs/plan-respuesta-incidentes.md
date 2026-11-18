# Plan de respuesta a incidentes de seguridad — NortiShop

**Caso:** Plataforma de comercio electrónico NortiShop
**Integrantes:** Catalina Toledo · María Gerónimo · Pablo Lineros · Fabián Salinas
**Implementación:** `sistema/src/security/detection.js`, `sistema/src/security/catalogoAuditoria.js`, `sistema/src/services/incidentService.js`, `sistema/src/services/auditService.js`
**Pruebas:** `sistema/test/incidentes.test.js`, `sistema/test/auditoria.test.js`, `sistema/test/trazabilidad.test.js`
**Simulacro:** `npm run simulacro` (`sistema/src/dev/simulacro.js`), salida en `sistema/evidencias/simulacro.txt`

> **Nota normativa.** Los artículos citados deben contrastarse con el texto oficial en bcn.cl antes de la entrega. La Ley 21.719 entra en vigencia el **1 de diciembre de 2026**. Hasta esa fecha rige la Ley 19.628, que no contempla un deber de notificar vulneraciones. El plan se diseña desde ya conforme a la Ley 21.719.

---

## 1. Alcance

El plan se aplica a cualquier evento que pueda comprometer la confidencialidad, integridad o disponibilidad de los datos personales que trata NortiShop:

- Cuentas de clientes: nombre, correo, teléfono y dirección.
- Pedidos, datos de facturación y NortiPuntos.
- Tokens de pago y últimos 4 dígitos de la tarjeta.
- Consentimientos y solicitudes de derechos.
- Registros de auditoría.
- Llaves criptográficas.

Riesgos priorizados según el análisis de los hitos anteriores:

| Riesgo | Ejemplo en NortiShop | Datos expuestos |
|---|---|---|
| Toma de cuentas | Fuerza bruta o relleno de credenciales en el login | Perfil, pedidos, medio de pago guardado (últimos 4 dígitos) |
| Abuso interno | Un agente de soporte revela datos completos sin ticket real | Identificación, contacto, dirección |
| Exportación indebida | Exportación masiva de suscriptores o de derechos | Correos de suscriptores, copia completa de un titular |
| Manipulación de datos | Alteración de saldos de NortiPuntos o de la auditoría | Integridad del programa y de la trazabilidad |
| Exposición de secretos | Una llave en un repositorio o un `.env` filtrado | Toda la PII cifrada con esa llave |
| Indisponibilidad | Caída de la pasarela de pago o de la base de datos | Disponibilidad de compras y de los derechos |

---

## 2. Preparación

### 2.1 Responsables

| Función | Rol en el sistema | Responsabilidad en el plan | Integrante (asignación del equipo) |
|---|---|---|---|
| Responsable de seguridad (líder del incidente) | `SEGURIDAD` | Revisa alertas, declara y dirige el incidente, preserva la evidencia, ejecuta la contención y la erradicación, y cierra el caso. | Pablo Lineros |
| Oficial de privacidad (DPO) | `OFICIAL_PRIVACIDAD` | Evalúa el impacto en los titulares, decide y autoriza las notificaciones y redacta el contenido. Responde consultas de titulares y de la Agencia. | Catalina Toledo |
| Administración del sistema | `ADMINISTRADOR` | Restablece la operación tras las comprobaciones, gestiona cuentas del personal y coordina respaldos y rotación de llaves. | Fabián Salinas |
| Desarrollo | (sin rol productivo) | Corrige la vulnerabilidad, despliega el parche y agrega pruebas de regresión. | Equipo de desarrollo |
| Comunicación | (sin rol productivo) | Publica los comunicados aprobados por el DPO y atiende el canal de consultas. | María Gerónimo |

La separación de funciones está implementada en el código:
- **SEGURIDAD** contiene, pero **no** restablece la operación ni autoriza notificaciones.
- **ADMINISTRADOR** restablece, pero **no** puede contener ni ver datos completos.
- **OFICIAL_PRIVACIDAD** autoriza la notificación, pero **no** ejecuta acciones técnicas.

### 2.2 Canales de reporte

| Origen | Canal |
|---|---|
| Detección automática | Alertas generadas por `detection.js` en la tabla `alertas`, revisadas por SEGURIDAD en cada turno (`API.seguridad.alertas`). |
| Personal interno | Correo `seguridad@nortishop.test` o ticket con prefijo `SEC-`. Ante sospecha de credenciales comprometidas, avisar de inmediato sin intentar "arreglarlo". |
| Clientes | Formulario de contacto y `privacidad@nortishop.test` (por ejemplo: "recibí un correo raro a nombre de NortiShop"). |
| Terceros | Pasarela de pago, operador logístico o plataforma de correo: aviso contractual a `seguridad@nortishop.test`. |

### 2.3 Recursos técnicos y procedimientos

| Recurso | Dónde |
|---|---|
| Auditoría encadenada con HMAC, de solo inserción, con anclas y verificación | `auditService.verificarCadena()`, `API.auditoria.verificar` |
| Catálogo de eventos auditados y campos de cada registro | `security/catalogoAuditoria.js` |
| Motor de detección con 10 reglas (6 genéricas + 4 propias de NortiShop) | `security/detection.js` |
| Reconstrucción de la línea de tiempo por origen, sesión, actor o titular | `API.auditoria.reconstruir` (SEGURIDAD y DPO, con motivo) |
| Preservación de evidencia con SHA-256 | `API.seguridad.preservarEvidencia` |
| Acciones de contención | `API.seguridad.contener`: revocar sesiones, deshabilitar una cuenta del personal, suspender un rol, suspender exportaciones |
| Comprobaciones de recuperación | `API.seguridad.recuperar` |
| Generador del borrador de notificación | `API.seguridad.autorizarNotificacion` |
| Reaplicar supresiones tras restaurar un respaldo | `API.privacidad.reaplicarSupresiones` |
| Rotación de llaves | Procedimiento manual: generar llave nueva con `npm run generar-env` en un entorno controlado, re-cifrar y retirar la anterior. Automatizar con un KMS es un pendiente (§9). |

---

## 3. Detección y análisis

### 3.1 Criterios de identificación (implementados)

| Regla | Criterio | Nivel inicial | Severidad |
|---|---|---|---|
| `FUERZA_BRUTA` | 5 o más inicios de sesión fallidos contra una misma cuenta en 15 minutos (además, la cuenta se bloquea 15 minutos) | Alerta | Media |
| `RELLENO_CREDENCIALES` | 10 o más cuentas distintas con login fallido en 10 minutos | Evento sospechoso | Alta |
| `DENEGACIONES_REPETIDAS` | 5 o más accesos denegados de un mismo usuario en 10 minutos (posible escalamiento de privilegios) | Evento sospechoso | Media |
| `REVELACIONES_PII_ANOMALAS` | 5 o más revelaciones de datos completos por un mismo agente en 1 hora | Evento sospechoso | Alta |
| `EXPORTACION_ANOMALA` | 3 o más exportaciones masivas o de derechos por un mismo actor en 24 horas | Evento sospechoso | Media |
| `INTEGRIDAD_COMPROMETIDA` | Firma de NortiPuntos inválida o cadena de auditoría rota | Evento sospechoso | Crítica |

**Alertas propias de NortiShop** (usan los campos de trazabilidad: sesión, origen seudonimizado, titular y datos tocados):

| Regla | Qué la dispara | Por qué es propia de NortiShop | Nivel | Severidad |
|---|---|---|---|---|
| `TOMA_DE_CUENTA` | Un cliente inicia sesión desde un **origen nunca visto** para su cuenta y, **en esa misma sesión** y dentro de 1 hora: cambia la dirección o el teléfono, **compra con la tarjeta guardada** o pide una copia de sus datos | Es el fraude típico del comercio electrónico: desviar un despacho pagado con la tarjeta tokenizada del cliente | Evento sospechoso | Alta |
| `ETIQUETAS_ANOMALAS` | LOGISTICA genera la etiqueta de un envío **ya entregado o cancelado** (no la necesita), o **15 o más etiquetas en 1 hora** | La etiqueta es el único punto donde logística ve nombre y dirección en claro | Evento sospechoso | Media |
| `TICKET_REUTILIZADO` | Un mismo ticket `TCK-` se usa para revelar los datos completos de **3 o más clientes distintos** en 24 horas | Revelar exige ticket y motivo; un ticket corresponde a un caso de un cliente | Evento sospechoso | Alta |
| `ACCESO_FUERA_DE_HORARIO` | Personal revela datos, genera etiquetas, revierte seudónimos o exporta **fuera de lun-sáb 08:00-21:00** (hora de Chile) | El personal de NortiShop no tiene turnos nocturnos ni dominicales | Alerta | Media |

**Respuesta inicial por alerta propia (playbook):**

| Regla | Primeros pasos de SEGURIDAD |
|---|---|
| `TOMA_DE_CUENTA` | Reconstruir por `sesionRef` (o por el `origen` de la alerta de relleno, si existe); preservar evidencia; `REVOCAR_SESIONES` del titular; `CANCELAR_PEDIDO` para cada compra no despachada de esa sesión; forzar cambio de contraseña. |
| `ETIQUETAS_ANOMALAS` | Reconstruir por `actorId`; confirmar con el jefe de despacho si hubo reimpresiones legítimas; si no, `DESHABILITAR_CUENTA_PERSONAL` y revisar los titulares de las etiquetas. |
| `TICKET_REUTILIZADO` | Reconstruir por `actorId`; contrastar los titulares revelados con el ticket real; si no corresponden, `SUSPENDER_ROL SOPORTE` o deshabilitar la cuenta y tratarlo como abuso interno. |
| `ACCESO_FUERA_DE_HORARIO` | Confirmar con la jefatura si había una autorización; si no, tratar la cuenta como posiblemente comprometida (`REVOCAR_SESIONES`) y reconstruir por `actorId`. |

Criterios manuales, que reporta una persona:
- Credenciales o llaves expuestas, por ejemplo un `.env` en un repositorio público o una contraseña del personal en una filtración.
- Reclamos de clientes por cambios que no hicieron.
- Aviso de un tercero.

### 3.2 Alerta, evento sospechoso e incidente confirmado

| Nivel | Definición | Quién decide | Registro |
|---|---|---|---|
| **Alerta** | Señal aislada que puede ser benigna (por ejemplo, alguien olvidó su contraseña). | Automático | `alertas` (nivel `ALERTA`) |
| **Evento sospechoso** | Patrón que no se explica por el uso normal y exige análisis. | Automático | `alertas` (nivel `EVENTO_SOSPECHOSO`) |
| **Incidente confirmado** | Evento con compromiso real o altamente probable de datos personales o de la operación. | **Solo SEGURIDAD**, al abrir y confirmar el análisis | `incidentes` + `incidente_acciones` |

Una alerta se **descarta** con un motivo documentado (`descartarAlerta`) o se **escala** a un incidente (`abrirIncidente`). Un incidente puede terminar **descartado** si el análisis concluye que fue un falso positivo (`analizar` con `confirmado: false`).

### 3.3 Evaluación del alcance, la gravedad y el impacto

Antes de registrar el alcance, SEGURIDAD **reconstruye** lo ocurrido con `API.auditoria.reconstruir`, partiendo del sujeto de la alerta (un origen, una sesión, un actor o un titular). La reconstrucción:
1. Toma los eventos del pivote y agrega todos los de las sesiones que aparecen en ellos (lo que el atacante hizo dentro de una cuenta queda ligado a su sesión).
2. Entrega las cuentas probadas, las cuentas comprometidas, los titulares afectados y, por titular, los **campos** expuestos o cambiados y su **tipo de dato** (identificación, contacto, dirección, credenciales, financieros, historial).
3. Lista los cambios (dirección, compras, exportaciones) y los intentos que los controles frenaron.
4. Verifica la cadena de sellos: si no está íntegra, la reconstrucción no es confiable y se escala como `INTEGRIDAD_COMPROMETIDA`.

El resultado alimenta directamente el análisis (`API.seguridad.analizar`), donde se registran:
- El período en que ocurrió (desde y hasta).
- Los **tipos de datos** comprometidos: identificación, contacto, dirección, credenciales, datos financieros, historial de compras, datos sensibles o datos de menores.
- El **número de titulares** afectados.
- La severidad ajustada.

| Severidad | Criterio |
|---|---|
| Baja | Sin datos personales comprometidos (por ejemplo, un intento de fuerza bruta bloqueado). |
| Media | Pocos titulares, datos de identificación o contacto, exposición contenida. |
| Alta | Dirección, credenciales o historial de compras; o más de 100 titulares; o abuso interno. |
| Crítica | Datos financieros (incluido el uso no autorizado de la tarjeta guardada), sensibles o de menores de 14 años; llaves comprometidas; integridad de la auditoría o de los saldos rota; o más de 1.000 titulares. |

El sistema aplica estos criterios como **severidad mínima** (`severidadMinima` en `incidentService.js`): al registrar el análisis, quien analiza puede subir la severidad, pero no dejarla por debajo de lo que exigen los tipos de datos y el número de titulares. Si la eleva, el ajuste queda en la bitácora.

### 3.4 Criterios de escalamiento

| Severidad | Escalar a | Plazo interno |
|---|---|---|
| Crítica | SEGURIDAD, DPO y ADMINISTRADOR de inmediato | Abrir incidente en menos de 1 hora |
| Alta | SEGURIDAD y DPO | Menos de 4 horas |
| Media | SEGURIDAD | En el turno |
| Baja | SEGURIDAD (revisión) | En 24 horas |

Además, siempre se escala al DPO cuando hay datos personales comprometidos, y a la pasarela de pago cuando hay datos financieros.

---

## 4. Contención

Antes de cualquier acción de contención es **obligatorio** preservar la evidencia. El sistema lo exige: `contener` responde `CONFLICTO` si no se ejecutó antes `preservarEvidencia`.

Preservar la evidencia hace tres cosas:
1. Copia los eventos de auditoría del período.
2. Verifica la cadena de sellos y registra un ancla.
3. Calcula el SHA-256 de todo el paquete.

Así, revocar sesiones o deshabilitar cuentas no borra rastros.

Además, mientras el incidente esté abierto rige la **retención extendida**: la purga por plazo no borra registros de auditoría ni logs de aplicación posteriores a 24 horas antes del inicio del incidente (`retencionExtendidaDesde` en la respuesta de la purga).

| Acción | Cuándo | Efecto | Responsable |
|---|---|---|---|
| `REVOCAR_SESIONES` | Toma de cuenta (de cliente o del personal) | Invalida todos los tokens de sesión del usuario. | SEGURIDAD |
| `DESHABILITAR_CUENTA_PERSONAL` | Credenciales del personal comprometidas o abuso interno | `activo = false` y sesiones revocadas. **No se borra la cuenta** (es evidencia). | SEGURIDAD |
| `SUSPENDER_ROL` | Abuso que puede repetirse desde otras cuentas del mismo rol | El rol pierde todos sus permisos hasta la recuperación. No se puede suspender el rol SEGURIDAD. | SEGURIDAD |
| `SUSPENDER_EXPORTACIONES` | Exportación anómala | Bloquea la exportación de marketing. Los derechos de los titulares siguen disponibles. | SEGURIDAD |
| `CANCELAR_PEDIDO` | Compra hecha por quien tomó una cuenta | Cancela el pedido antes del despacho y queda en la bitácora del incidente (y, por lo tanto, en las medidas de la notificación). | SEGURIDAD |
| Rotación de llave | Llave expuesta | Procedimiento manual (§2.3). | ADMINISTRADOR + SEGURIDAD |
| Aislamiento de un componente | Proveedor comprometido | Revocar su API key y desconectar la integración. | ADMINISTRADOR |

Reglas para no destruir evidencia:
- **No** reiniciar ni restaurar sistemas antes de preservar la evidencia.
- **No** borrar cuentas, registros ni alertas.
- Toda acción queda en `incidente_acciones` y en la auditoría.

---

## 5. Erradicación y recuperación

**Erradicación** (`API.seguridad.erradicar`, SEGURIDAD con desarrollo):
1. Documentar la **causa raíz**. El sistema la exige.
2. Corregir la vulnerabilidad: parche, cambio de configuración o nuevo umbral.
3. Rotar las credenciales y llaves afectadas.
4. Agregar una prueba automática que reproduzca el ataque.

**Recuperación** (`API.seguridad.recuperar`, solo ADMINISTRADOR). El sistema solo restablece la operación si pasan **todas** estas comprobaciones:

| Comprobación | Cómo se verifica |
|---|---|
| Auditoría íntegra | `verificarCadena()`: sin registros modificados, eliminados ni truncados |
| Saldos de NortiPuntos íntegros | HMAC + versión + historial de todas las cuentas |
| Sin alertas críticas abiertas sin revisar | Tabla `alertas` |
| Causa raíz documentada | Campo `causa_raiz` |

Si alguna falla, la respuesta es `CONFLICTO` con la lista de lo pendiente. Si todas pasan:
1. Se levantan los controles de contención del incidente (roles y exportaciones).
2. Se ancla la auditoría.
3. Se registra la recuperación.

Si fue necesario **restaurar un respaldo**, se ejecuta `reaplicarSupresiones` antes de reabrir el servicio. Así ningún titular que pidió la supresión "revive" con el respaldo.

---

## 6. Notificación y comunicación

### 6.1 Quién evalúa y autoriza

El **Oficial de Privacidad** evalúa (`evaluarNotificacion`) y autoriza (`autorizarNotificacion`). La decisión, con su justificación, queda registrada incluso cuando se decide **no** notificar. El incidente no se puede cerrar sin esa decisión. Comunicación publica solo el texto aprobado.

### 6.2 Criterios y plazos según la normativa aplicable

| Destinatario | Cuándo corresponde | Plazo | Fundamento |
|---|---|---|---|
| **Agencia de Protección de Datos Personales** | Vulneración de las medidas de seguridad que cause la destrucción, filtración, pérdida o alteración accidental o ilícita de datos personales, o el acceso o comunicación no autorizados, cuando exista un riesgo razonable para los derechos y libertades de los titulares | "Por los medios más expeditos posibles y sin dilaciones indebidas". La ley **no fija un número de horas**. Meta interna: dentro de 72 horas desde la confirmación. | Ley 21.719, deber de reportar vulneraciones (art. 14 sexies) |
| **Titulares afectados** | Cuando la vulneración afecte datos **sensibles**, datos de **niños y niñas menores de 14 años**, o datos relativos a **obligaciones económicas, financieras, bancarias o comerciales** (por ejemplo, medios de pago). Comunicación en lenguaje claro y sencillo, que singularice los datos afectados, las posibles consecuencias y las medidas adoptadas. | Sin dilaciones indebidas, a cada titular afectado. Si no es posible, mediante un aviso en un medio de comunicación social masivo y de alcance nacional. | Ley 21.719 (art. 14 sexies) |
| **Titulares, por buena práctica** | Credenciales comprometidas, aunque no sea legalmente obligatorio | Junto con la notificación a la Agencia | Decisión del DPO |
| **Pasarela de pago y, por su intermedio, las marcas de tarjetas** | Cualquier compromiso de tokens o de datos de transacciones | De inmediato, según el contrato | PCI DSS v4.0 (req. 12.10) y contrato con la pasarela |
| **CSIRT Nacional** | Solo si NortiShop fuera calificado como prestador de servicios esenciales u operador de importancia vital. **Hoy no aplica.** | Alerta temprana en 3 horas, actualización en 72 horas e informe final en 15 días | Ley 21.663, Marco de Ciberseguridad |
| **Policía de Investigaciones o Fiscalía** | Delito informático (Ley 21.459) | Según la evaluación legal | Ley 21.459 |

Lo implementado en `evaluarNotificacion`:
- Si hay datos personales comprometidos y titulares afectados, recomienda notificar a la Agencia.
- Si se trata de datos sensibles, de menores o financieros, recomienda comunicar también a los titulares.
- Si hay credenciales, recomienda comunicar a los titulares como buena práctica.
- Si hay datos financieros, indica que se debe avisar a la pasarela de pago.

### 6.3 Contenido de la notificación

El borrador que genera `autorizarNotificacion` incluye los 7 contenidos exigidos:

| Contenido exigido | Campo del borrador |
|---|---|
| Descripción clara del incidente | `descripcion` |
| Fecha de detección y período en que ocurrió | `fecha_deteccion`, `periodo` |
| Tipos de datos potencialmente afectados | `datos_afectados` (y `titulares_afectados`) |
| Posibles consecuencias o riesgos | `posibles_consecuencias` |
| Medidas de contención y mitigación | `medidas_adoptadas` (tomadas de la bitácora: acciones de contención y medidas de erradicación). El art. 14 sexies exige además registrar las medidas adoptadas para gestionar la vulneración y precaver incidentes futuros. |
| Recomendaciones para reducir los riesgos | `recomendaciones` (por tipo de dato, por ejemplo "cambie su contraseña") |
| Canal de contacto | `contacto` (`privacidad@nortishop.test`) |

---

## 7. Lecciones aprendidas y cierre

El cierre (`API.seguridad.cerrar`, SEGURIDAD) exige:
1. Estado **RECUPERADO**.
2. **Decisión de notificación** registrada por el DPO.
3. **Lecciones aprendidas** (mínimo 30 caracteres) y **medidas preventivas**.

En la reunión posterior al incidente, dentro de los 10 días hábiles siguientes, se documenta:
- **Causas:** la causa raíz técnica y los factores organizacionales que contribuyeron (por ejemplo, falta de MFA).
- **Medidas correctivas:** lo que se arregló.
- **Medidas preventivas:** lo que evita que se repita.
- **Mejoras a la detección:** si algún umbral debe ajustarse, si faltó una regla o si la alerta llegó tarde. Los cambios a `REGLAS` se versionan en el repositorio y se prueban.

La bitácora (`incidente_acciones`) conserva la secuencia completa de fases, con fecha, actor y detalle, para la rendición de cuentas.

---

## 8. Ejemplos ejecutados (evidencia)

### 8.1 Abuso interno (etapa anterior)

`npm run demo:privacidad` (sección 4) y `test/incidentes.test.js`: un agente de soporte revela datos completos 5 veces en una hora (`REVELACIONES_PII_ANOMALAS`); el incidente recorre las 7 fases, con suspensión del rol SOPORTE y notificación a la Agencia.

### 8.2 Simulacro de esta etapa: relleno de credenciales y toma de cuenta

`npm run simulacro` (salida en `sistema/evidencias/simulacro.txt`) y `test/trazabilidad.test.js`:

1. **Ataque** (desde un único origen, IP de documentación): prueba 11 correos de una lista filtrada; entra a la cuenta de Ana con su contraseña reutilizada; ve su perfil, cambia la dirección de despacho, compra con la tarjeta guardada e intenta pedir la portabilidad sin el código del correo.
2. **Detección:** `RELLENO_CREDENCIALES` (sujeto = seudónimo del origen) y `TOMA_DE_CUENTA` (sujeto = Ana).
3. **Análisis:** reconstrucción desde el origen de la alerta: 11 cuentas probadas (una real, Bruno, sin éxito), 1 comprometida (Ana), sus campos expuestos y los dos cambios (dirección y compra con `medio=TOKEN_GUARDADO`); la portabilidad aparece como frenada.
4. **Retención extendida:** una purga lanzada con el incidente abierto no borra nada.
5. **Contención:** evidencia preservada (SHA-256), sesiones de Ana revocadas (`REVOCAR_SESIONES`) y pedido fraudulento cancelado antes del despacho (`CANCELAR_PEDIDO`). La severidad sube de alta a **crítica** en el análisis, porque se usó la tarjeta guardada (datos financieros).
6. **Erradicación, recuperación, notificación y cierre:** la evaluación indica notificar a la Agencia y también a la titular (hay datos financieros), y avisar a la pasarela de pago.
7. **Comprobación:** las 11 comprobaciones entre lo reconstruido y el guion del atacante son correctas, la cadena está íntegra y la auditoría no contiene correos, nombres, direcciones, contraseñas ni IPs.

---

## 9. Limitaciones y pendientes

- **Simulaciones:** la detección corre en memoria del proceso y el correo es simulado. En producción, las alertas deben llegar a un canal de guardia (paging) y la auditoría a un almacenamiento inmutable (WORM).
- **Rotación de llaves:** es manual. Falta un KMS con rotación y re-cifrado automáticos.
- **MFA:** no está implementado para el personal. Es la principal medida preventiva pendiente.
- **Ejercicios:** el plan debe probarse con un ejercicio de mesa (*tabletop*) cada 6 meses y actualizarse con sus resultados. El simulacro técnico (`npm run simulacro`) se ejecuta en cada cambio como prueba automática.
- **Orígenes conocidos:** la regla `TOMA_DE_CUENTA` guarda en memoria los orígenes de cada cuenta; en producción deben persistirse (solo seudónimos) para no perder la línea base al reiniciar.
