from zipfile import ZIP_DEFLATED, ZipFile
from xml.etree import ElementTree as ET

SOURCE = 'documentos/Informe_SPD_NortiShop_Formateado.docx'
OUTPUT = 'documentos/Informe_SPD_NortiShop_Formateado_Final.docx'
W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
NS = {'w': W}
ET.register_namespace('w', W)


def text_nodes(element):
    return element.findall('.//w:t', NS)


def replace_element_text(element, old, new):
    nodes = text_nodes(element)
    current = ''.join(node.text or '' for node in nodes)
    if old not in current:
        return False
    updated = current.replace(old, new)
    if nodes:
        nodes[0].text = updated
        for node in nodes[1:]:
            node.text = ''
    return True


def replace_everywhere(root, replacements):
    changes = []
    for element in root.iter():
        if not element.tag.endswith('}p') and not element.tag.endswith('}tc'):
            continue
        for old, new in replacements:
            if replace_element_text(element, old, new):
                changes.append((old, new))
    return changes


with ZipFile(SOURCE, 'r') as source_zip:
    document = ET.fromstring(source_zip.read('word/document.xml'))

    replacements = [
        ('Grupo: [nombre o número del grupo]', 'Grupo: NortiShop'),
        ('Actividad N.º 2, Ítem I', 'Ítem 1'),
        ('Anexo A: Actividad N.º 1', 'Anexo A: Ítem 1'),
        ('Anexo B: Actividad N.º 2', 'Anexo B: Ítem 2'),
        ('Tabla de facturación cifrada (Ítem I)', 'Tabla de facturación contemplada en el caso y el Ítem 1; no implementada en el Ítem 2'),
        ('Operador logístico* como mandatario (art. 8)', 'Operador logístico* externo, sujeto a contrato y uso limitado a la entrega'),
        ('Consentimiento (Ley 19.628, art. 4).', 'Autorización informada conforme a la Ley 19.628, art. 4.'),
        ('Consentimiento (compra) y ley (D.L. 825, arts. 52 y 53; Código Tributario, art. 17).', 'Autorización informada conforme a la Ley 19.628, art. 4, más obligaciones legales aplicables al respaldo tributario y comercial.'),
        ('Consentimiento (compra) y ley tributaria', 'Autorización informada y obligaciones tributarias aplicables'),
        ('Consentimiento; el operador actúa como mandatario (Ley 19.628, art. 8).', 'Autorización informada para la entrega; el operador debe estar sujeto a contrato y limitar el uso a esa finalidad.'),
        ('El mandato debe constar por escrito y limitar el uso a la entrega; no se comparten correo ni historial.', 'La relación contractual debe documentar el uso limitado a la entrega; no se comparten correo ni historial.'),
        ('A la fecha de este informe, 5 de octubre de 2026, debe considerarse la Ley N.º 19.628 como referencia vigente. La Ley N.º 21.719 tiene prevista su entrada en vigor para el 1 de diciembre de 2026. Esa ley amplía las fuentes de licitud más allá del consentimiento, incorporando, entre otras, la ejecución de un contrato con el titular y el cumplimiento de una obligación legal. Desde esa fecha, los flujos de registro, cobro y despacho podrían fundarse en la ejecución del contrato, mientras que el boletín, el medio de pago guardado y NortiPuntos seguirían requiriendo consentimiento.',
        'A la fecha de este informe, 5 de octubre de 2026, debe considerarse la Ley N.º 19.628 como referencia vigente. La Ley N.º 21.719 tiene prevista su entrada en vigor para el 1 de diciembre de 2026. Esa ley amplía las fuentes de licitud más allá del consentimiento, incorporando, entre otras, la ejecución de un contrato con el titular y el cumplimiento de una obligación legal. Desde esa fecha, los flujos de registro, cobro y despacho podrían fundarse en la ejecución del contrato. El boletín, el medio de pago guardado y NortiPuntos deberán contar igualmente con una base de licitud documentada; en este informe se propone consentimiento separado cuando se trate de tratamientos opcionales.'),
        ('Los plazos de la Tabla 1 aplican el principio de que los datos deben eliminarse cuando su almacenamiento carezca de fundamento legal o hayan caducado (Ley 19.628, artículo 6).', 'Los plazos de la Tabla 1 se proponen como criterios referenciales. La Ley 19.628, artículo 6, exige eliminar o cancelar los datos cuando su almacenamiento carezca de fundamento legal o hayan caducado; los plazos concretos deben validarse según obligaciones tributarias, contractuales y operativas.'),
        ('El PAN se sustituye por un token, una máscara y la marca. El CVV se valida y se descarta. El PAN no llega a DB.users.', 'El PAN se recibe temporalmente en memoria, se sustituye por un token, una máscara y la marca, y no llega a DB.users. La bóveda simulada conserva un hash SHA-256 del PAN y datos asociados; el CVV se valida y se descarta.'),
    ]

    changes = replace_everywhere(document, replacements)

    with ZipFile(OUTPUT, 'w', ZIP_DEFLATED) as output_zip:
        for item in source_zip.infolist():
            data = ET.tostring(document, encoding='utf-8', xml_declaration=True) if item.filename == 'word/document.xml' else source_zip.read(item.filename)
            output_zip.writestr(item, data)

print(f'Correcciones aplicadas: {len(changes)}')
print(OUTPUT)