"""Construye un informe .docx a partir de un Markdown, usando un informe anterior como plantilla
(estilos, portada, índices, encabezado y pie). Ver herramientas_informe/README en NOTAS_SIGUIENTE_ACTIVIDAD.md.

Uso:
  python herramientas_informe/construir_docx.py SALIDA.docx INFORME.md PLANTILLA.docx       "Título anterior de portada" "Título nuevo" "fecha anterior" "fecha nueva" "texto encabezado anterior" "texto encabezado nuevo"
"""
import io, os, re, shutil, struct, sys, zipfile
from xml.sax.saxutils import escape

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SALIDA, MD, PLANTILLA = (os.path.abspath(a) for a in sys.argv[1:4])
TITULO_ANT, TITULO, FECHA_ANT, FECHA, ENC_ANT, ENC = sys.argv[4:10]
TMP = os.path.join(os.path.dirname(SALIDA), 'build_tmp')

shutil.rmtree(TMP, ignore_errors=True)
with zipfile.ZipFile(PLANTILLA) as z:
    z.extractall(TMP)
for root, dirs, files in os.walk(TMP):  # paquete de terceros: sin enlaces simbólicos
    for f in files:
        if os.path.islink(os.path.join(root, f)):
            os.remove(os.path.join(root, f))

doc_path = os.path.join(TMP, 'word', 'document.xml')
rels_path = os.path.join(TMP, 'word', '_rels', 'document.xml.rels')
doc = io.open(doc_path, encoding='utf-8').read()
rels = io.open(rels_path, encoding='utf-8').read()

# ---------- portada y encabezado ----------
doc = doc.replace(TITULO_ANT, TITULO, 1)
doc = doc.replace(FECHA_ANT, FECHA, 1)
for h in ('header1.xml', 'header2.xml'):
    p = os.path.join(TMP, 'word', h)
    t = io.open(p, encoding='utf-8').read().replace(ENC_ANT, ENC)
    io.open(p, 'w', encoding='utf-8').write(t)

# ---------- quitar imágenes antiguas ----------
for m in re.findall(r'<Relationship Id="rIdImg\d+"[^>]*Target="(media/[^"]+)"/>', rels):
    try:
        os.remove(os.path.join(TMP, 'word', m))
    except FileNotFoundError:
        pass
rels = re.sub(r'<Relationship Id="rIdImg\d+"[^>]*/>', '', rels)

# ---------- generación de XML ----------
def runs(texto, extra_rpr=''):
    """Markdown en línea mínimo: **negrita** y `código` (como texto normal)."""
    out = []
    for parte in re.split(r'(\*\*[^*]+\*\*|\*[^*\s][^*]*\*)', texto):
        if not parte:
            continue
        negrita = parte.startswith('**') and parte.endswith('**')
        cursiva = not negrita and len(parte) > 2 and parte.startswith('*') and parte.endswith('*')
        t = parte[2:-2] if negrita else parte[1:-1] if cursiva else parte
        t = t.replace('`', '')
        rpr = ('<w:b/><w:bCs/>' if negrita else '') + ('<w:i/><w:iCs/>' if cursiva else '') + extra_rpr
        out.append(f'<w:r>{f"<w:rPr>{rpr}</w:rPr>" if rpr else ""}<w:t xml:space="preserve">{escape(t)}</w:t></w:r>')
    return ''.join(out)


def parrafo(texto, estilo=None, ppr_extra=''):
    ppr = (f'<w:pStyle w:val="{estilo}"/>' if estilo else '') + ppr_extra
    return f'<w:p>{f"<w:pPr>{ppr}</w:pPr>" if ppr else ""}{runs(texto)}</w:p>'


bm = [200]
def titulo1(texto, primero):
    bm[0] += 1
    extra = '' if primero else '<w:pageBreakBefore w:val="0"/><w:spacing w:before="560"/>'
    return (f'<w:p><w:pPr><w:pStyle w:val="Ttulo1"/>{extra}</w:pPr><w:bookmarkStart w:id="{bm[0]}" w:name="_Toc2439{bm[0]:05d}"/>'
            f'{runs(texto)}<w:bookmarkEnd w:id="{bm[0]}"/></w:p>')


def leyenda(tipo, texto):
    b = '<w:rPr><w:b/><w:bCs/></w:rPr>'
    return ('<w:p><w:pPr><w:pStyle w:val="Descripcin"/><w:keepNext/></w:pPr>'
            f'<w:r>{b}<w:t xml:space="preserve">{tipo} </w:t></w:r>'
            f'<w:r>{b}<w:fldChar w:fldCharType="begin"/></w:r><w:r>{b}<w:instrText xml:space="preserve"> SEQ {tipo} \\* ARABIC </w:instrText></w:r>'
            f'<w:r>{b}<w:fldChar w:fldCharType="separate"/></w:r><w:r><w:rPr><w:b/><w:bCs/><w:noProof/></w:rPr><w:t>1</w:t></w:r>'
            f'<w:r>{b}<w:fldChar w:fldCharType="end"/></w:r><w:r>{b}<w:t xml:space="preserve">.</w:t></w:r>'
            f'<w:r><w:t xml:space="preserve"> {escape(texto)}</w:t></w:r></w:p>')


def fuente(texto):
    t = texto.strip().strip('*').strip()
    assert t.startswith('Fuente:'), t
    return ('<w:p><w:pPr><w:pStyle w:val="Notadetablaofigura"/></w:pPr><w:r><w:rPr><w:i/><w:iCs/></w:rPr><w:t xml:space="preserve">Fuente:</w:t></w:r>'
            f'{runs(t[len("Fuente:"):])}</w:p>')


def celdas(linea):
    return [c.strip() for c in linea.strip().strip('|').split('|')]


def tabla(filas):
    cab, cuerpo = filas[0], filas[2:]
    n = len(cab)
    largo = [max(len(f[i].replace('`', '')) for f in [cab] + cuerpo) for i in range(n)]
    peso = [max(8, min(l, 90)) ** 0.8 for l in largo]
    total = 9073
    # mínimo: que la palabra más larga de la columna quepa sin cortarse (~105 twips por carácter a 9 pt)
    ancho_palabra = lambda w: len(w) * (140 if w.isupper() else 105)
    minimo = [max(ancho_palabra(w) for f in [cab] + cuerpo for w in re.split(r'[\s_]+', f[i].replace('`', '')) if w) + 200 for i in range(n)]
    anchos = [int(total * p / sum(peso)) for p in peso]
    for _ in range(10):
        falta = sum(max(0, m - a) for a, m in zip(anchos, minimo))
        if not falta:
            break
        holgura = [max(0, a - m) for a, m in zip(anchos, minimo)]
        anchos = [max(a, m) - (int(falta * h / sum(holgura)) if sum(holgura) else 0) for a, m, h in zip(anchos, minimo, holgura)]
    anchos[-1] += total - sum(anchos)
    borde = '<w:tblBorders><w:top w:val="single" w:sz="12" w:space="0" w:color="000000"/><w:left w:val="single" w:sz="4" w:space="0" w:color="000000"/><w:bottom w:val="single" w:sz="12" w:space="0" w:color="000000"/><w:right w:val="single" w:sz="4" w:space="0" w:color="000000"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="000000"/><w:insideV w:val="single" w:sz="4" w:space="0" w:color="000000"/></w:tblBorders>'
    x = [f'<w:tbl><w:tblPr><w:tblW w:w="{total}" w:type="dxa"/><w:jc w:val="center"/>{borde}<w:tblLayout w:type="fixed"/>'
         '<w:tblCellMar><w:top w:w="57" w:type="dxa"/><w:left w:w="85" w:type="dxa"/><w:bottom w:w="57" w:type="dxa"/><w:right w:w="85" w:type="dxa"/></w:tblCellMar>'
         '<w:tblLook w:val="0620" w:firstRow="1" w:lastRow="0" w:firstColumn="0" w:lastColumn="0" w:noHBand="1" w:noVBand="1"/></w:tblPr><w:tblGrid>']
    x += [f'<w:gridCol w:w="{a}"/>' for a in anchos]
    x.append('</w:tblGrid>')
    for k, fila in enumerate([cab] + cuerpo):
        enc = k == 0
        x.append(f'<w:tr><w:trPr><w:cantSplit/>{"<w:tblHeader/>" if enc else ""}<w:jc w:val="center"/></w:trPr>')
        for i, c in enumerate(fila):
            tcb = '<w:tcBorders><w:bottom w:val="single" w:sz="12" w:space="0" w:color="000000"/></w:tcBorders>' if enc else ''
            estilo = 'Encabezadodetabla' if enc else 'Textodetabla'
            x.append(f'<w:tc><w:tcPr><w:tcW w:w="{anchos[i]}" w:type="dxa"/>{tcb}<w:vAlign w:val="center"/></w:tcPr>'
                     f'<w:p><w:pPr><w:pStyle w:val="{estilo}"/>{"<w:keepNext/>" if enc else ""}</w:pPr>{runs(c.replace("_", "_​"))}</w:p></w:tc>')
        x.append('</w:tr>')
    x.append('</w:tbl>')
    return ''.join(x)


def tam_png(ruta):
    with open(ruta, 'rb') as f:
        cab = f.read(24)
    return struct.unpack('>II', cab[16:24])


img_n = [0]
def figura(ruta_rel):
    ruta = os.path.join(REPO, ruta_rel.replace('/', os.sep))
    img_n[0] += 1
    nombre = f'traz{img_n[0]}.png'
    destino = os.path.join(TMP, 'word', 'media', nombre)
    from PIL import Image
    im = Image.open(ruta).convert('RGB')
    if im.getpixel((5, im.height - 5)) == (12, 12, 12):  # captura de terminal: recortar el fondo vacío de la derecha
        gris = im.convert('L').point(lambda v: 255 if v > 40 else 0)
        caja = gris.crop((0, 40, im.width, im.height)).getbbox()
        if caja:
            im = im.crop((0, 0, min(im.width, caja[2] + 24), im.height))
    im.save(destino)
    ruta = destino
    rid = f'rIdImg{img_n[0]}'
    global rels
    rels = rels.replace('</Relationships>', f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/{nombre}"/></Relationships>')
    w, h = tam_png(ruta)
    max_w, max_h = 5760720, 6900000
    cx = max_w
    if w * 9525 < max_w * 0.9 and w < 1300:  # imágenes angostas: tamaño natural a 2x
        cx = min(max_w, int(w * 9525 * 0.75))
    cy = int(cx * h / w)
    if cy > max_h:
        cy = max_h
        cx = int(cy * w / h)
    did = 9000 + img_n[0]
    return ('<w:p><w:pPr><w:pStyle w:val="Figura"/><w:keepNext/></w:pPr><w:r><w:rPr><w:noProof/></w:rPr><w:drawing>'
            f'<wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="{cx}" cy="{cy}"/><wp:effectExtent l="0" t="0" r="0" b="0"/>'
            f'<wp:docPr id="{did}" name="Imagen {did}"/><wp:cNvGraphicFramePr><a:graphicFrameLocks xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" noChangeAspect="1"/></wp:cNvGraphicFramePr>'
            '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
            f'<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="0" name="{nombre}"/><pic:cNvPicPr><a:picLocks noChangeAspect="1" noChangeArrowheads="1"/></pic:cNvPicPr></pic:nvPicPr>'
            f'<pic:blipFill><a:blip r:embed="{rid}"/><a:srcRect/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
            f'<pic:spPr bwMode="auto"><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic>'
            '</a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>')


# ---------- recorrer el Markdown ----------
lineas = io.open(MD, encoding='utf-8').read().replace('\r\n', '\n').split('\n')
partes = []
i = 0
primero = True
pendiente_tabla = None
while i < len(lineas):
    l = lineas[i]
    s = l.strip()
    if not s or s.startswith('# ') or s.startswith('**Caso 1:**') or s.startswith('**Integrantes:**'):
        i += 1
        continue
    if s.startswith('## '):
        partes.append(titulo1(s[3:], primero)); primero = False; i += 1; continue
    if s.startswith('Tabla: '):
        pendiente_tabla = s[len('Tabla: '):]; i += 1; continue
    if s.startswith('|'):
        filas = []
        while i < len(lineas) and lineas[i].strip().startswith('|'):
            filas.append(celdas(lineas[i])); i += 1
        assert pendiente_tabla, filas[0]
        partes.append(leyenda('Tabla', pendiente_tabla)); pendiente_tabla = None
        partes.append(tabla(filas)); continue
    if s.startswith('```mermaid'):
        while not lineas[i].strip() == '```':
            i += 1
        i += 1
        m = re.match(r'<!-- img: (\S+) \| (.+) -->', lineas[i].strip())
        assert m, lineas[i]
        partes.append(leyenda('Figura', m.group(2))); partes.append(figura(m.group(1)))
        partes.append(fuente('Fuente: elaboración propia a partir del modelo implementado.'))
        i += 1; continue
    m = re.match(r'!\[(.+)\]\((.+)\)', s)
    if m:
        partes.append(leyenda('Figura', m.group(1))); partes.append(figura(m.group(2))); i += 1; continue
    if s.startswith('*Fuente:'):
        partes.append(fuente(s)); i += 1; continue
    if s.startswith('- '):
        while i < len(lineas) and lineas[i].strip().startswith('- '):
            partes.append(f'<w:p><w:pPr><w:pStyle w:val="Listaconvietas"/><w:numPr><w:ilvl w:val="0"/><w:numId w:val="2"/></w:numPr></w:pPr>{runs(lineas[i].strip()[2:])}</w:p>')
            i += 1
        continue
    partes.append(parrafo(s)); i += 1

cuerpo = ''.join(partes)
ini = doc.index('<w:p><w:pPr><w:pStyle w:val="Ttulo1"/>')
fin = doc.rindex('<w:sectPr')
doc = doc[:ini] + cuerpo + doc[fin:]
io.open(doc_path, 'w', encoding='utf-8').write(doc)
io.open(rels_path, 'w', encoding='utf-8').write(rels)

# NO se agrega <w:updateFields>: con ese aviso, Word automatizado (COM) queda colgado esperando
# una respuesta invisible. Los índices y la numeración los actualiza actualizar_en_word.ps1.
sp = os.path.join(TMP, 'word', 'settings.xml')
st = re.sub(r'<w:updateFields[^>]*/>', '', io.open(sp, encoding='utf-8').read())
io.open(sp, 'w', encoding='utf-8').write(st)

if os.path.exists(SALIDA):
    os.remove(SALIDA)
with zipfile.ZipFile(SALIDA, 'w', zipfile.ZIP_DEFLATED) as z:
    ct = os.path.join(TMP, '[Content_Types].xml')
    z.write(ct, '[Content_Types].xml')
    for root, dirs, files in os.walk(TMP):
        for f in files:
            full = os.path.join(root, f)
            arc = os.path.relpath(full, TMP).replace(os.sep, '/')
            if arc != '[Content_Types].xml':
                z.write(full, arc)
shutil.rmtree(TMP)
print('ok', SALIDA, img_n[0], 'imágenes')
