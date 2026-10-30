# Plan de respuesta a incidentes de seguridad — NortiShop

**Caso:** Plataforma de comercio electrónico NortiShop
**Integrantes:** Catalina Toledo · María Gerónimo · Pablo Lineros · Fabián Salinas
**Implementación:** `ITEM2/src/security/detection.js`, `ITEM2/src/services/incidentService.js`, `ITEM2/src/services/auditService.js`
**Pruebas:** `ITEM2/test/incidentes.test.js`, `ITEM2/test/auditoria.test.js`

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
| Motor de detección con 6 reglas y umbrales | `security/detection.js` |
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

En el análisis (`API.seguridad.analizar`) se registran:
- El período en que ocurrió (desde y hasta).
- Los **tipos de datos** comprometidos: identificación, contacto, dirección, credenciales, datos financieros, historial de compras, datos sensibles o datos de menores.
- El **número de titulares** afectados.
- La severidad ajustada.

| Severidad | Criterio |
|---|---|
| Baja | Sin datos personales comprometidos (por ejemplo, un intento de fuerza bruta bloqueado). |
| Media | Pocos titulares, datos de identificación o contacto, exposición contenida. |
| Alta | Dirección, credenciales o historial de compras; o más de 100 titulares; o abuso interno. |
| Crítica | Datos financieros, sensibles o de menores; llaves comprometidas; integridad de la auditoría o de los saldos rota; o más de 1.000 titulares. |

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

| Acción | Cuándo | Efecto | Responsable |
|---|---|---|---|
| `REVOCAR_SESIONES` | Toma de cuenta (de cliente o del personal) | Invalida todos los tokens de sesión del usuario. | SEGURIDAD |
| `DESHABILITAR_CUENTA_PERSONAL` | Credenciales del personal comprometidas o abuso interno | `activo = false` y sesiones revocadas. **No se borra la cuenta** (es evidencia). | SEGURIDAD |
| `SUSPENDER_ROL` | Abuso que puede repetirse desde otras cuentas del mismo rol | El rol pierde todos sus permisos hasta la recuperación. No se puede suspender el rol SEGURIDAD. | SEGURIDAD |
| `SUSPENDER_EXPORTACIONES` | Exportación anómala | Bloquea la exportación de marketing. Los derechos de los titulares siguen disponibles. | SEGURIDAD |
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
| **Titulares afectados** | Cuando la vulneración afecte datos **sensibles**, datos de **niños, niñas y adolescentes**, o datos relativos a **obligaciones económicas, financieras, bancarias o comerciales** (por ejemplo, medios de pago). Comunicación en lenguaje claro y sencillo. | Sin dilaciones indebidas. Si no es posible individualizarlos, mediante un aviso público destacado. | Ley 21.719 (art. 14 sexies) |
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
| Medidas de contención y mitigación | `medidas_adoptadas` (tomadas de la bitácora de contención) |
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

## 8. Ejemplo ejecutado (evidencia)

`npm run demo:privacidad` (sección 4) y `test/incidentes.test.js` recorren un incidente real de punta a punta:

1. Un agente de soporte revela datos completos 5 veces en una hora, lo que genera la alerta `REVELACIONES_PII_ANOMALAS` (Alta).
2. SEGURIDAD abre el incidente desde la alerta y confirma el alcance: identificación, contacto y dirección, 1 titular.
3. El intento de contener sin evidencia es rechazado. Se preserva la evidencia con SHA-256 y verificación de la cadena.
4. Contención: se suspende el rol SOPORTE y se deshabilita la cuenta comprometida, cuyas sesiones quedan revocadas.
5. Erradicación con causa raíz documentada.
6. SEGURIDAD intenta recuperar y es denegado. El ADMINISTRADOR intenta recuperar con una alerta crítica abierta y es rechazado. Tras revisar la alerta, la recuperación procede y los controles se levantan.
7. El DPO evalúa (corresponde notificar a la Agencia) y autoriza; se genera el borrador con los 7 contenidos.
8. Cierre con lecciones aprendidas. La bitácora contiene las 7 fases.

---

## 9. Limitaciones y pendientes

- **Simulaciones:** la detección corre en memoria del proceso y el correo es simulado. En producción, las alertas deben llegar a un canal de guardia (paging) y la auditoría a un almacenamiento inmutable (WORM).
- **Rotación de llaves:** es manual. Falta un KMS con rotación y re-cifrado automáticos.
- **MFA:** no está implementado para el personal. Es la principal medida preventiva pendiente.
- **Ejercicios:** el plan debe probarse con un ejercicio de mesa (*tabletop*) cada 6 meses y actualizarse con sus resultados.
