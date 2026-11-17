from zipfile import ZIP_DEFLATED, ZipFile
from xml.etree import ElementTree as ET

SOURCE = 'documentos/Informe_Actividad_4_NortiShop_v2.docx'
OUTPUT = 'documentos/Informe_Actividad_4_NortiShop_Final.docx'
W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
NS = {'w': W}
ET.register_namespace('w', W)


def replace_element_text(element, old, new):
    nodes = element.findall('.//w:t', NS)
    current = ''.join(node.text or '' for node in nodes)
    if old not in current or not nodes:
        return False
    updated = current.replace(old, new)
    nodes[0].text = updated
    for node in nodes[1:]:
        node.text = ''
    return True


def replace_everywhere(root, replacements):
    changes = []
    for element in root.iter():
        if not (element.tag.endswith('}p') or element.tag.endswith('}tc')):
            continue
        for old, new in replacements:
            if replace_element_text(element, old, new):
                changes.append(old)
    return changes


replacements = [
    (
        'Todas las pruebas y capturas utilizan datos sintéticos.',
        'Todas las pruebas y capturas utilizan datos sintéticos. Las figuras incorporadas corresponden principalmente a avances del Hito 3 y se presentan como evidencia parcial de los controles criptográficos ya explorados; el diseño RBAC, la minimización y la separación de accesos de esta actividad se documentan adicionalmente en las secciones siguientes.',
    ),
    (
        'La demostración se ejecuta desde el directorio ITEM2 con el comando npm start, utilizando únicamente datos sintéticos. Las Figuras 5 a 9 muestran los resultados de cada parte de la actividad.',
        'La demostración y los pantallazos se ejecutan desde el directorio ITEM2 con el comando npm start, utilizando únicamente datos sintéticos. Las Figuras 5 a 9 corresponden principalmente a avances del Hito 3 y sirven como evidencia parcial de hashing, cifrado, tokenización e integridad; no sustituyen la especificación completa de los controles de esta Actividad 4.',
    ),
    (
        'Fuente: ejecución de npm start.',
        'Fuente: avances y capturas de ejecución del Hito 3; evidencia complementaria para esta actividad.',
    ),
    (
        'La base de datos se ejecuta con un esquema declarado en los scripts 00_esquema_original.sql, 01_minimizacion.sql y 02_seudonimizacion.sql',
        'La propuesta de base de datos se documenta en 01_minimizacion.sql y 02_seudonimizacion.sql; el esquema original se presenta en la Figura 1 y en la comparación de este informe',
    ),
    (
        'La Figura 1 muestra el esquema original definido en 00_esquema_original.sql.',
        'La Figura 1 muestra el esquema original reconstruido a partir del caso y de los artefactos disponibles.',
    ),
    (
        'users: identificador UUID; nombre, correo, teléfono opcional y dirección cifrados con AES-256-GCM y datos autenticados adicionales (AAD); índice ciego email_hmac único; comuna; guardar_medio_pago falso por defecto, y solo los últimos cuatro dígitos de la tarjeta.',
        'users: identificador, nombre, correo, teléfono opcional y dirección cifrados con AES-256-GCM; índice ciego email_hmac; token de pago y solo los últimos cuatro dígitos de la tarjeta. En el código ejecutable el identificador mantiene el prefijo usr_ y el campo AAD no está implementado.',
    ),
    (
        'orders: identificador UUID, total_clp calculado en el servidor, dirección de envío cifrada, comuna de envío y tipo de documento (boleta o factura).',
        'orders: identificador, total de compra recibido por el flujo actual, dirección de envío cifrada, transacción, autorización, estado y últimos cuatro dígitos. El cálculo server-side del total queda como control pendiente.',
    ),
    (
        'personal y audit_log: cuentas del personal con su rol interno, y registro de auditoría con rol del actor, acción, recurso, resultado y motivo, sin datos personales.',
        'El diseño SQL propone cuentas de personal y audit_log sin datos personales; el código ejecutable actual implementa RBAC en memoria para customer, support y admin, pero todavía no implementa persistencia de personal ni audit_log.',
    ),
    (
        'Las claves K_resenas, K_analitica y K_marketing se cargan desde el entorno, una por finalidad, y se retiran de process.env tras su lectura.',
        'El diseño SQL reserva una clave por finalidad para K_resenas, K_analitica y K_marketing. En el código ejecutable actual se valida y utiliza CONFIG.HMAC_SECRET para el índice de correo y la integridad; la separación de claves por finalidad queda pendiente.',
    ),
    (
        'El control de acceso se aplica en dos capas. En el servidor, cada solicitud pasa por la misma secuencia, representada en la Figura 4: el servicio de autenticación resuelve la sesión buscando el hash SHA-256 del token y relee el rol vigente, de modo que un cambio o revocación de rol tiene efecto inmediato sobre las sesiones abiertas. Luego, la función autorizar() verifica el permiso y, cuando corresponde, que el recurso pertenezca al usuario. Si el acceso se deniega, se responde 403 ACCESO_DENEGADO y se registra el motivo en audit_log; si se permite, soloCampos() rechaza los datos no necesarios antes de consultar la base.',
        'En el código ejecutable, cada operación protegida invoca assertPermission() antes de acceder al recurso. La función valida el rol, el permiso y la propiedad del recurso; el cliente solo consulta su propio perfil y un acceso cruzado es rechazado. La persistencia SQL propone una segunda capa con GRANT, REVOKE y vistas, pero esa base no está desplegada en esta demostración. Sesiones con tokens, 403, audit_log y soloCampos() quedan como controles pendientes.',
    ),
    (
        'La Tabla 4 resume cada control, su mecanismo y la evidencia que lo respalda.',
        'La Tabla 4 distingue los controles implementados en ITEM2 de los controles definidos como propuesta SQL o pendientes de una integración productiva.',
    ),
    (
        'Una llave de 256 bits por finalidad (cifrado, integridad, índice, reseñas, analítica y marketing), cargada desde el entorno y retirada de process.env. El archivo .env está excluido de Git.',
        'AES-256 y HMAC se cargan desde variables de entorno validadas; .env está excluido de Git. La separación de llaves por finalidad y su retirada de process.env quedan pendientes.',
    ),
    (
        'AES-256-GCM con IV aleatorio y AAD obligatorio amarrado al registro.',
        'AES-256-GCM con IV aleatorio y etiqueta de autenticación. AAD obligatorio amarrado al registro queda como mejora pendiente.',
    ),
    (
        'Tokenización que valida Luhn y CVV, devuelve solo last4 y no conserva el PAN.',
        'Tokenización simulada que valida formato de PAN y CVV, devuelve token, marca y máscara; el registro de NortiShop solo conserva token y last4. La validación Luhn no está implementada.',
    ),
    (
        'Lista blanca de campos: se rechazan fecha de nacimiento, sexo, foto, tarjeta sin consentimiento de guardado y datos de facturación en boletas.',
        'El registro ejecutable exige nombre, correo, contraseña y dirección; el teléfono es opcional y no se persisten fecha de nacimiento, sexo ni foto. Rechazo explícito de campos adicionales, consentimiento de guardado y facturación aún requieren implementación.',
    ),
    (
        'Lista blanca de columnas y tipos protegidos: se rechazan columnas fuera del esquema y texto plano en columnas cifradas.',
        'El repositorio en memoria solo guarda el objeto construido por UserService y OrderService; controles SQL de columnas y tipos protegidos están definidos en la propuesta, no ejecutados en una base real.',
    ),
    (
        'El total se calcula en el servidor; un total enviado por el cliente se rechaza.',
        'El flujo actual recibe totalAmount como parámetro del servicio; el cálculo desde precios persistidos y el rechazo de totales manipulados quedan como control pendiente.',
    ),
    (
        'HMAC por finalidad, vistas públicas, ETL generalizado, umbral k = 5 y anonimización programada de invitados.',
        'El esquema SQL define HMAC por finalidad, vistas, ETL generalizado, umbral k = 5 y anonimización programada. En ITEM2 esas tablas y jobs no están ejecutados; se presentan como diseño.',
    ),
    (
        'Sesiones con token hasheado, relectura del rol en cada solicitud y función autorizar() por permiso y propietario.',
        'RBAC ejecutable mediante assertPermission(), con roles admin, support y customer y validación de propietario. Sesiones persistentes, tokens hasheados y relectura del rol no están implementados.',
    ),
    (
        'HMAC sobre usuario, versión y saldo, con historial de movimientos.',
        'HMAC protege usuario y saldo; la versión y el historial de movimientos están definidos en SQL, pero no forman parte del repositorio en memoria actual.',
    ),
    (
        'Mensajes genéricos al cliente, redacción automática de registros y auditoría sin datos personales.',
        'La autenticación devuelve mensajes genéricos y el código no imprime secretos en las respuestas de registro. Redacción automática y audit_log persistente quedan pendientes.',
    ),
    (
        'El servidor rechaza con el código CAMPO_NO_PERMITIDO cualquier dato que no sea necesario para la operación, y la capa de datos aplica una segunda validación con el código BD_COLUMNA_NO_PERMITIDA. Así, aunque un error en el servidor dejara pasar un campo, la base no lo almacenaría (Figura 5).',
        'El servidor valida los campos mínimos del registro y construye una lista controlada de campos persistentes. No existe todavía una segunda capa SQL desplegada con códigos CAMPO_NO_PERMITIDO y BD_COLUMNA_NO_PERMITIDA; debe implementarse junto con la base productiva.',
    ),
    (
        'Los campos personales se cifran con AES-256-GCM y AAD. Como muestra la Figura 6, un atacante con acceso a la base solo observa criptogramas, hashes y tokens.',
        'Los campos personales se cifran con AES-256-GCM. Como muestra la Figura 6, un atacante con acceso al repositorio observa criptogramas, hashes y tokens; el AAD por registro queda pendiente.',
    ),
    (
        'Cada operación invoca la función autorizar() antes de acceder a los datos. Los resultados se expresan mediante códigos estandarizados (NO_AUTENTICADO, ACCESO_DENEGADO, DATO_INVALIDO, CREDENCIALES_INVALIDAS e INTEGRIDAD_COMPROMETIDA), acompañados de mensajes que no revelan información sobre el sistema ni sobre los datos almacenados.',
        'Las operaciones de perfil y pedido invocan assertPermission() antes de acceder a los datos. Los accesos no autorizados devuelven un error genérico de acceso denegado; una taxonomía completa de códigos y middleware de sesiones queda pendiente.',
    ),
    (
        'La Figura 10 muestra el resultado obtenido el 25 de octubre de 2026: 50 pruebas ejecutadas, 50 aprobadas y ninguna fallida.',
        'La Figura 10 muestra el resultado obtenido el 25 de octubre de 2026: 7 pruebas ejecutadas, 7 aprobadas y ninguna fallida.',
    ),
    (
        'Una llave de 256 bits por finalidad, retirada de process.env; .env.example sin secretos utilizables; ningún rol accede a las llaves.',
        'Llaves AES/HMAC validadas desde el entorno; .env.example documenta la configuración y .env está excluido de Git. La separación completa por finalidad y el acceso mediante gestor de secretos quedan pendientes.',
    ),
    (
        'bcrypt con sal única y costo configurado; AES-256-GCM con IV aleatorio y AAD; HMAC del saldo con versión; tokenización con validación Luhn/CVV.',
        'bcrypt con sal y costo 12; AES-256-GCM con IV aleatorio; HMAC del saldo; tokenización con validación de formato y CVV. Luhn, AAD y versión en la firma quedan pendientes.',
    ),
    (
        'Rechazo de fecha de nacimiento, sexo, RUT y foto; teléfono y tarjeta opcionales; boleta sin datos de facturación; monto calculado en el servidor; columnas fuera del esquema rechazadas; datos en reposo sin texto plano.',
        'Campos mínimos obligatorios, teléfono opcional, tarjeta reducida a last4 y datos en reposo sin contraseña, correo ni dirección en texto plano. Rechazo explícito de todos los campos no permitidos, facturación, cálculo de monto y validación SQL quedan pendientes.',
    ),
    (
        'Verificación de los permisos de cada rol sobre las acciones de la Tabla 3.',
        'Pruebas de cliente sobre recurso propio, cliente sobre recurso ajeno y consulta administrativa. Los roles adicionales de la matriz SQL aún no tienen pruebas ejecutables.',
    ),
    (
        'Sin sesión o con token inválido; cliente sobre datos de otro cliente; administrador que intenta auto-asignarse roles o desactivarse.',
        'Cliente sobre datos de otro cliente es rechazado. Las pruebas de sesión inválida y de autoasignación administrativa aún no existen en ITEM2.',
    ),
    (
        'Revocación de rol con efecto inmediato; inicio de sesión sin enumeración y bloqueo tras intentos fallidos.',
        'El login devuelve razones genéricas para credenciales inválidas y valida la contraseña con bcrypt. Revocación de roles, sesiones y bloqueo por intentos aún no están implementados.',
    ),
    (
        'Las 50 pruebas automatizadas demuestran el correcto funcionamiento de los accesos permitidos y denegados, del cifrado, del hashing, de la tokenización y de los controles de integridad.',
        'Las 7 pruebas automatizadas demuestran hashing, cifrado, tokenización, integridad, persistencia protegida, acceso propio permitido, acceso cruzado denegado y lectura administrativa permitida. Los controles SQL y roles aún no implementados deben probarse al desplegar la base real.',
    ),
]

with ZipFile(SOURCE, 'r') as source_zip:
    document = ET.fromstring(source_zip.read('word/document.xml'))
    changes = replace_everywhere(document, replacements)
    with ZipFile(OUTPUT, 'w', ZIP_DEFLATED) as output_zip:
        for item in source_zip.infolist():
            data = ET.tostring(document, encoding='utf-8', xml_declaration=True) if item.filename == 'word/document.xml' else source_zip.read(item.filename)
            output_zip.writestr(item, data)

print(f'Correcciones aplicadas: {len(changes)}')
print(OUTPUT)
