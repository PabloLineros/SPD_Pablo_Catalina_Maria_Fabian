# Notas para la siguiente actividad — NortiShop

Estado del proyecto al cierre de la **Actividad 7 (Trazabilidad y plan de respuesta)**, 13 de noviembre de 2026: dónde está cada cosa, cómo extender el sistema sin romper lo hecho, cómo se arma el informe en Word y qué quedó pendiente.

---

## 1. Estado del repositorio

| Rama | Contenido |
|---|---|
| `main` (y `origin/main`) | Hasta la Actividad 6 (commit `f38e058 Actividad 6`). |
| `actividad-7` | Creada desde `origin/main`. Contiene todo lo de la Actividad 7. **Sin commit al 13-11-2026**: hay que hacer commit y PR hacia `main`. |
| `fs-dev`, `fisd` | Ramas antiguas, **atrasadas** respecto de `main` (no tienen Hito 5 ni Actividad 6). No trabajar sobre ellas. |

- `documentos/` no está versionado: ahí están los `.docx` entregados, incluido **`Informe Act 6 (1).docx`**, que es la **plantilla** de formato de los informes.
- `ITEM2/.env` es local y no se versiona. Si falta una llave, el sistema no arranca: ejecutar `npm run generar-env`, que solo agrega las que falten.

## 2. Dónde está cada actividad

| Actividad | SQL | Documento de diseño | Código principal | Pruebas |
|---|---|---|---|---|
| Hito 2: minimización, seudonimización, RBAC | `01`, `02`, `03` | `INFORME_HITO2.md` | `crypto/`, `security/rbac.js`, `db/repository.js` | `minimizacion`, `seudonimizacion`, `rbac`, `criptografia` |
| Hito 5: consentimiento, derechos, auditoría sellada e incidentes | `04_consentimiento_derechos_auditoria.sql` | `INFORME_CONSENTIMIENTO_DERECHOS_AUDITORIA.md`, `PLAN_RESPUESTA_INCIDENTES.md` | `consentService`, `rightsService`, `audit.js`, `detection.js`, `incidentService` | `consentimiento`, `derechos`, `auditoria`, `incidentes` |
| Actividad 6: ejercicio de derechos | `05_ejercicio_derechos.sql` | `documentos/Informe Act 6 (1).docx` | `rightsService`, `restrictionService` | `ejercicio_derechos` |
| **Actividad 7: trazabilidad** | `06_trazabilidad.sql` | `INFORME_TRAZABILIDAD.md` (fuente del .docx) y `PLAN_RESPUESTA_INCIDENTES.md` (actualizado) | `security/catalogoAuditoria.js`, `security/contexto.js`, `detection.js`, `auditService.js`, `dev/simulacro.js` | `trazabilidad` (13 pruebas) |

- Inventario de datos (Tarea 2): `ITEM1/Tarea 2 Tabla por Campo Sensible.pdf`. Las actividades piden "partir del inventario": conviene cruzarlo siempre en el informe (en la Actividad 7 es la Tabla 3).
- Enunciados y material del curso: `documentos/Casos_Proyecto_Integrador.docx`, `documentos/Seguridad y Proteccion de Datos - PR - 0*.pptx`.

## 3. Números vigentes

Para no contradecirse entre informes:

- **106 pruebas**, todas aprobadas (`npm test`). La Actividad 6 terminó con 93; la 7 agregó 13.
- **9 llaves**, una por finalidad. La Actividad 7 agregó `KEY_HMAC_ORIGEN`.
- **Catálogo de auditoría:** 37 eventos más las denegaciones; 17 campos por registro.
- **10 reglas de detección:** 6 genéricas (Hito 5) y 4 propias de NortiShop (Actividad 7): `TOMA_DE_CUENTA`, `ETIQUETAS_ANOMALAS`, `TICKET_REUTILIZADO` y `ACCESO_FUERA_DE_HORARIO`.
- **9 roles.** La matriz se genera con `npm run matriz` (en `evidencias/matriz_rbac.md`).
- **Plazos:**
  - auditoría y alertas: 24 meses;
  - evidencias de incidentes: 5 años desde el cierre;
  - logs de aplicación: 90 días;
  - contacto de invitados: 90 días;
  - respuesta a derechos: 30 días;
  - facturación bloqueada: 6 años.

## 4. Cómo extender el sistema sin romper lo hecho

### 4.1 Flujo de una operación

`server.js` (abre `conOrigen(ip)`) → `api.js` (`enSolicitud`, `resolverSesion`, `fijarSesion`) → servicio → `autorizar()` (si deniega, audita) → operación → `registrarAuditoria()` → `audit_log`, sellado por un disparador → `detection.js` (suscrito a cada evento).

### 4.2 Checklist al agregar una operación que toca datos personales

1. Autorizar con `autorizar(sesion, PERMISOS.X, { propietarioId, recurso })`. Si el permiso es nuevo, agregarlo a `PERMISOS` y `MATRIZ` en `rbac.js` y regenerar la matriz.
2. Auditar con `registrarAuditoria({ sesion, accion, recurso, titular, datos?, resultado, motivo? })`:
   - `datos` lleva solo **nombres** de campos del vocabulario `CAMPOS_DATOS`, nunca valores;
   - `motivo` no debe llevar datos personales (igual se redacta).
3. Agregar la acción a `EVENTOS` en `catalogoAuditoria.js`. Si no, queda como `NO_CATALOGADO` y falla la prueba 1 de `trazabilidad.test.js`. Si la acción es nueva, agregarla también al flujo amplio de esa prueba.
4. Si se crea una tabla: declararla en `ESQUEMA` y en `GRANTS` de `db/repository.js`, y en el script SQL de la etapa.
5. Si se agrega una llave: actualizar `crypto/keyring.js` (`FINALIDADES` y `VARIABLES`), `scripts/generar-env.js`, `scripts/entorno-pruebas.js`, `.env.example` y el conteo en `test/criptografia.test.js`.
6. Usar datos sintéticos (dominio `.test`) e IPs de documentación (RFC 5737: `192.0.2.x`, `198.51.100.x`, `203.0.113.x`).

### 4.3 Detalles que conviene conocer

- `prepararEscenario()` (`src/dev/escenario.js`) **reinicia la BD**: no sirve para acumular eventos entre escenarios.
- Las denegaciones de un usuario ya suprimido no llegan a `autorizar` (la sesión deja de existir); dan `NO_AUTENTICADO`.
- La severidad del incidente tiene un **mínimo** según los datos (`severidadMinima` en `incidentService.js`): se puede subir, no bajar.
- Las medidas de la notificación salen de la **bitácora** (contención y erradicación). Toda medida debe ejecutarse como acción del incidente para que aparezca, por ejemplo `CANCELAR_PEDIDO`.
- Los eventos del actor `SISTEMA` no heredan la sesión ni el origen de la solicitud, pero sí su correlación.
- Las demos (`demo.js`, `demo-privacidad.js`) imprimen colores ANSI fijos. Al guardarlas en `evidencias/` hay que limpiarlas: `| sed 's/\x1b\[[0-9;]*m//g'`.

## 5. Comandos (desde `ITEM2/`)

| Comando | Para qué |
|---|---|
| `npm test` | 106 pruebas con llaves efímeras |
| `npm run simulacro` | Simulacro de la Actividad 7 (salida en `evidencias/simulacro.txt`) |
| `npm run demo:privacidad` / `npm start` | Demos de etapas anteriores |
| `npm run servidor` | Centro de privacidad en `http://127.0.0.1:3000` |
| `npm run matriz` | Matriz RBAC en Markdown |
| `node scripts/capturas-trazabilidad.mjs` | Capturas `30_*` a `34_*` (no toca las anteriores) |
| `node scripts/capturas.mjs` | Regenera **todas** las capturas 01-24 (las borra antes) |
| `node scripts/diagramas.mjs <informe.md> <nombre1,nombre2>` | Bloques Mermaid a PNG. Sin argumentos regenera D1-D4. Requiere internet. |

## 6. Cómo se arma el informe en Word

Formato del grupo, tomado de `Informe Act 6`:
- portada UDD con título, "NortiShop", integrantes y fecha;
- índice, índice de tablas e índice de figuras;
- títulos numerados;
- leyenda **antes** de cada tabla o figura y "*Fuente:* …" después;
- texto breve y directo, con tablas y viñetas.

Proceso, que es el que se usó en la Actividad 7:

1. Escribir el informe en Markdown en la raíz (`INFORME_<TEMA>.md`) con estas convenciones:
   - `## Título` es un título 1 numerado;
   - `Tabla: <leyenda>` va justo antes de una tabla Markdown;
   - `![<leyenda de la figura>](ruta.png)` es una figura;
   - un bloque ```` ```mermaid ```` seguido de `<!-- img: ruta.png | leyenda -->` es un diagrama (el PNG se genera con `diagramas.mjs`);
   - `*Fuente: …*` va después de cada tabla o figura;
   - `**negrita**` y `*cursiva*`; las viñetas usan `- `.
2. Construir el .docx con la plantilla:
   ```
   python herramientas_informe/construir_docx.py SALIDA.docx INFORME_<TEMA>.md "documentos/Informe Act 7 - Trazabilidad y plan de respuesta.docx" "Trazabilidad y plan de respuesta" "<Título nuevo>" "13 de noviembre de 2026" "<fecha nueva>" "Trazabilidad y plan de respuesta" "<texto del encabezado nuevo>"
   ```
   Requiere `pip install python-docx pymupdf pillow`; pymupdf sirve para revisar el PDF.
3. Actualizar índices y numeración, y exportar el PDF de revisión, con Word (COM):
   ```
   powershell -File herramientas_informe/actualizar_en_word.ps1 -Entrada SALIDA.docx -Salida "documentos/Informe Act N - ....docx" -Pdf revision.pdf
   ```
   **Problemas conocidos:**
   - **Word se cuelga** si el .docx trae `<w:updateFields>`, porque espera un aviso invisible. `construir_docx.py` ya no lo agrega.
   - Si el archivo de salida está abierto en Word, el guardado falla. Cerrarlo antes.
   - Ejecutar el script con un límite de tiempo. Si se cuelga, cerrar **solo** las instancias `WINWORD` sin ventana que abrió el script, nunca las del usuario.
4. Revisar el PDF (pymupdf → PNG): anchos de tablas, que no se corten palabras y que los índices tengan número de página.

## 7. Decisiones y hallazgos de la Actividad 7 (para no repetir errores)

- **Revisión externa del Informe 7.** Hallazgos ya corregidos:
  - la severidad del simulacro contradecía los criterios del plan;
  - las medidas adoptadas en la notificación estaban incompletas;
  - no se nombraban las cuatro comprobaciones de la recuperación ni las fases en el texto;
  - la frase de las cuentas probadas era ambigua;
  - el origen de las reglas genéricas estaba mal atribuido ("etapa anterior" en vez de Hito 5);
  - faltaba explicar qué pasa con la auditoría tras una supresión;
  - faltaba justificar que el administrador lea la auditoría;
  - "menores" debía ser "menores de 14 años", y faltaba el aviso en un medio de alcance nacional;
  - el simulacro registraba como medida adoptada un segundo factor que no existe, mientras la conclusión decía que faltaba. Las medidas de erradicación ahora son solo las que se toman (contraseña forzada y bloqueo del origen, manuales), y el segundo factor figura como medida preventiva pendiente en el cierre.
- **Regla:** nunca declarar como "medida adoptada" algo que el prototipo no implementa. Las medidas de erradicación pasan textualmente al borrador de la notificación.
- **Lección general:** cada criterio que el informe declara debe cumplirse en el simulacro y, si es posible, en el código. Los evaluadores cruzan las tablas con las capturas.
- **Brecha que se detectó tarde:** NortiPuntos y reseñas no se auditaban, aunque están en el inventario. Hay que cruzar siempre contra la Tarea 2 antes de dar por cubierto un punto.
- Las capturas de terminal se leen chicas impresas (figuras 3 a 6). Si importa, generar capturas más angostas o partirlas.

## 8. Pendientes y limitaciones conocidas

- **El administrador puede leer la auditoría que registra sus propias acciones.** Solo está justificado, no controlado. Una mejora sería que sus consultas excluyan sus propios eventos o requieran revisión de SEGURIDAD.
- **No hay segundo factor (MFA)** para el personal ni ante un origen nuevo. Es la principal medida preventiva pendiente y aparece en el cierre del simulacro.
- **Orígenes conocidos de cada cuenta** (regla `TOMA_DE_CUENTA`): viven en memoria; en producción deben persistirse como seudónimos.
- **La rotación de llaves es manual.** Falta un KMS.
- **Simulaciones:** la base de datos, el correo, la pasarela y el operador logístico son simulados en memoria. La auditoría no está en un almacenamiento WORM real.
- **Carrito:** está en el inventario, pero no existe en el prototipo.
- **Representantes:** las solicitudes de derechos de representantes se atienden de forma manual (Actividad 6).

## 9. Referencias legales verificadas

- **Ley 21.719, art. 14 sexies.** Texto verificado en el Diario Oficial del 13-12-2024 (núm. 44.023, CVE 2583630):
  - reportar a la Agencia "por los medios más expeditos posibles y sin dilaciones indebidas" (la ley **no fija horas**; las 72 h son una meta interna);
  - el responsable debe **registrar** las comunicaciones, con la naturaleza de la vulneración, sus efectos, las categorías de datos, el número aproximado de titulares y **"las medidas adoptadas para gestionarlas y precaver incidentes futuros"**;
  - también se comunica **a los titulares** cuando se trata de datos sensibles, **"datos relativos a niños y niñas menores de catorce años"** u obligaciones económicas, financieras, bancarias o comerciales;
  - esa comunicación debe ser en lenguaje claro, singularizando los datos, las consecuencias y las medidas;
  - va dirigida a **cada titular** y, si no es posible, mediante un aviso en un **"medio de comunicación social masivo y de alcance nacional"**.
- **Vigencia:** la Ley 21.719 rige desde el **1 de diciembre de 2026**; hasta entonces rige la Ley 19.628.
- **Otras referencias usadas en el plan:**
  - PCI DSS v4.0, req. 12.10 (aviso a la pasarela);
  - Ley 21.663, Marco de Ciberseguridad (hoy no aplica a NortiShop);
  - Ley 21.459, delitos informáticos;
  - Código Tributario, art. 17 (facturación, 6 años).
- Cuando se cite un artículo nuevo, verificarlo en el texto oficial (Diario Oficial o bcn.cl) antes de entregar.

## 10. Equipo y roles en el plan de incidentes

| Integrante | Rol en el plan |
|---|---|
| Pablo Lineros | SEGURIDAD (líder del incidente) |
| Catalina Toledo | OFICIAL_PRIVACIDAD (DPO) |
| Fabián Salinas | ADMINISTRADOR |
| María Gerónimo | Comunicación |

Orden de los integrantes en la portada de los informes: María Gerónimo, Pablo Lineros, Catalina Toledo, Fabián Salinas.
