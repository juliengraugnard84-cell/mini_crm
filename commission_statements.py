"""Monthly commission statements and billing schedules from stored revenue snapshots."""
from collections import OrderedDict
from datetime import date
from decimal import Decimal
from io import BytesIO
from xml.sax.saxutils import escape
from zipfile import ZipFile, ZIP_DEFLATED

from commissions import commission_values

ENERGIES = {'electricite': 'Électricité', 'gaz': 'Gaz', 'electricite_gaz': 'Électricité et gaz'}
PARTNERS = {'ade': 'ADE', 'direct': 'Fournisseur en direct'}


def payment_date(signed_on):
    # November -> January, according to the agreed business rule.
    month_index = signed_on.year * 12 + signed_on.month - 1 + 2
    return date(month_index // 12, month_index % 12 + 1, 1)


def build_statement(rows, mode, month, scope):
    if mode not in ('monthly', 'billing'):
        raise ValueError('Type de relevé invalide.')
    try:
        period = date.fromisoformat(month + '-01')
    except (ValueError, TypeError):
        raise ValueError('Choisissez un mois au format AAAA-MM.')
    groups = OrderedDict()
    missing_signature = pending = incomplete = 0
    for raw in rows:
        row = dict(raw)
        signed = row.get('signed_on')
        if not signed:
            missing_signature += 1
            continue
        due = payment_date(signed)
        selected = signed if mode == 'monthly' else due
        if (selected.year, selected.month) != (period.year, period.month):
            continue
        values = commission_values(row)
        if values is None:
            pending += 1
            if mode == 'billing':
                continue
        if not row.get('supplier_name') or not row.get('energy_type') or row.get('initial_amount') is None:
            incomplete += 1
        name = row.get('commercial') or 'Non attribué'
        group = groups.setdefault(name, dict(name=name, rows=[], gross=Decimal('0'), net=Decimal('0'),
                                            commission=Decimal('0'), missing_gross=0))
        # Whitelist export fields: no configuration rates or admin-only balance.
        item = dict(id=row['id'], dossier=row.get('client_name') or row.get('dossier') or 'Sans dossier',
                    signed_on=signed, payable_on=due, supplier=row.get('supplier_name') or 'Non renseigné',
                    energy=ENERGIES.get(row.get('energy_type'), 'Non renseignée'),
                    partner=PARTNERS.get(row.get('revenue_source'), 'Non renseigné'),
                    gross=Decimal(str(row['initial_amount'])) if row.get('initial_amount') is not None else None,
                    net=Decimal(str(row['montant'])), commission=values[0] if values else None)
        group['rows'].append(item)
        group['net'] += item['net']
        group['commission'] += item['commission'] or 0
        if item['gross'] is None:
            group['missing_gross'] += 1
        else:
            group['gross'] += item['gross']
    for group in groups.values():
        group['rows'].sort(key=lambda row: (row['signed_on'], row['id']))
    return dict(mode=mode, month=month, scope=scope, groups=list(groups.values()),
                title='Relevé mensuel de commissions' if mode == 'monthly' else 'Relevé de commissions à facturer',
                missing_signature=missing_signature, pending=pending, incomplete=incomplete,
                total=sum((g['commission'] for g in groups.values()), Decimal('0')))


def statement_notes(statement):
    notes = ['Paiement prévisionnel au début du deuxième mois suivant la signature (novembre -> janvier).',
             'CA prestataire = somme initiale avant retenue ; CA net = après retenue ; commission = montant du commercial.',
             "Relevé justificatif à joindre à la facture. Il ne constate pas un paiement effectué."]
    if statement['missing_signature']:
        notes.append(f"{statement['missing_signature']} revenu(s) sans date de signature exclus (ensemble du périmètre).")
    if statement['pending']:
        notes.append(f"{statement['pending']} commission(s) non calculée(s) sur la période, exclues du total à facturer.")
    if statement['incomplete']:
        notes.append(f"{statement['incomplete']} ligne(s) avec fournisseur, énergie ou CA prestataire manquant : à compléter avant facturation.")
    return notes


HEADERS = ['Dossier', 'Signature', 'Payable dès', 'Partenaire', 'Énergie', 'Fournisseur signé',
           'CA prestataire', 'CA net', 'Commission']


def detail_values(row):
    return [row['dossier'], row['signed_on'].strftime('%d/%m/%Y'), row['payable_on'].strftime('%d/%m/%Y'),
            row['partner'], row['energy'], row['supplier'], row['gross'], row['net'], row['commission']]


def pdf_statement(statement):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    stream = BytesIO()
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='CellSmall', fontName='Helvetica', fontSize=8, leading=11))
    styles.add(ParagraphStyle(name='HeadSmall', fontName='Helvetica-Bold', fontSize=8, leading=11, textColor=colors.white))
    doc = SimpleDocTemplate(stream, pagesize=landscape(A4), rightMargin=28, leftMargin=28,
                            topMargin=30, bottomMargin=32, title=statement['title'], author='Aléo Conseils')
    story = []
    def paragraph(text, style='CellSmall'):
        return Paragraph(escape(str(text)), styles[style])
    def money(value):
        return 'Non calculée' if value is None else f'{value:,.2f} EUR'.replace(',', ' ')
    for index, group in enumerate(statement['groups'] or [None]):
        if index:
            story.append(PageBreak())
        story.extend([paragraph('ALÉO CONSEILS', 'Heading2'), paragraph(statement['title'], 'Title'),
                      paragraph(f"Période : {statement['month']} | Commercial : {group['name'] if group else statement['scope']}", 'Heading3')])
        for note in statement_notes(statement):
            story.append(paragraph(note))
        story.append(Spacer(1, 14))
        if group is None:
            story.append(paragraph('Aucune commission pour cette sélection.'))
            continue
        data = [[paragraph(h, 'HeadSmall') for h in HEADERS]]
        for row in group['rows']:
            values = detail_values(row)
            data.append([paragraph(money(v) if i >= 6 and v is not None else ('Non renseigné' if i == 6 and v is None else 'Non calculée' if v is None else v)) for i, v in enumerate(values)])
        data.append([paragraph('TOTAL'), '', '', '', '', '', paragraph(money(group['gross']) + (' *' if group['missing_gross'] else '')),
                     paragraph(money(group['net'])), paragraph(money(group['commission']))])
        table = Table(data, colWidths=[153, 56, 56, 75, 66, 110, 92, 88, 89], repeatRows=1)
        table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#173750')),
                                  ('ROWBACKGROUNDS', (0, 1), (-1, -2), [colors.white, colors.HexColor('#F0F5F8')]),
                                  ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#DCEAEF')),
                                  ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                                  ('LEFTPADDING', (0, 0), (-1, -1), 6), ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                                  ('TOPPADDING', (0, 0), (-1, -1), 7), ('BOTTOMPADDING', (0, 0), (-1, -1), 7)]))
        story.append(table)
        if group['missing_gross']:
            story.append(paragraph('* Total CA prestataire partiel : montants historiques non renseignés.'))
    def footer(canvas, document):
        canvas.setFont('Helvetica', 8)
        canvas.drawString(28, 16, 'Aléo Conseils | Relevé de commissions | Montants en EUR')
        canvas.drawRightString(landscape(A4)[0] - 28, 16, f'Page {document.page}')
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    stream.seek(0)
    return stream


def xlsx_statement(statement):
    """Portable XLSX export for the deployed Flask server, with no desktop runtime dependency."""
    # Strings are inline cells (never formulas), including user-supplied dossier names.
    ns = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
    rows = [[statement['title']], [f"Période : {statement['month']} | {statement['scope']}"]]
    rows += [[note] for note in statement_notes(statement)]
    rows += [[], ['Commercial'] + HEADERS]
    header_row = len(rows)
    for group in statement['groups']:
        for row in group['rows']:
            rows.append([group['name']] + detail_values(row))
    last_detail = len(rows)
    rows += [[], ['TOTAL COMMISSIONS (EUR)', statement['total']]]
    data = []
    for number, values in enumerate(rows, 1):
        cells = []
        for column, value in enumerate(values):
            ref = f'{chr(65 + column)}{number}'
            style = 1 if number == header_row else 2 if isinstance(value, Decimal) else 3 if number == 1 else 0
            if isinstance(value, Decimal):
                cells.append(f'<c r="{ref}" s="{style}"><v>{value}</v></c>')
            else:
                value = 'Non renseigné / non calculé' if value is None else str(value)
                value = ''.join(c for c in value if ord(c) >= 32 or c in '\n\t')
                cells.append(f'<c r="{ref}" s="{style}" t="inlineStr"><is><t xml:space="preserve">{escape(value)}</t></is></c>')
        data.append(f'<row r="{number}" ht="{32 if number >= header_row else 25}" customHeight="1">{"".join(cells)}</row>')
    widths = [22, 46, 15, 15, 26, 23, 30, 20, 20, 20]
    columns = ''.join(f'<col min="{i}" max="{i}" width="{width}" customWidth="1"/>' for i, width in enumerate(widths, 1))
    merges = ''.join(f'<mergeCell ref="A{i}:J{i}"/>' for i in range(1, header_row - 1))
    sheet = f'''<worksheet xmlns="{ns}"><sheetViews><sheetView workbookViewId="0"><pane ySplit="{header_row}" topLeftCell="A{header_row + 1}" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><cols>{columns}</cols><sheetData>{''.join(data)}</sheetData><autoFilter ref="A{header_row}:J{max(header_row, last_detail)}"/><mergeCells count="{header_row - 2}">{merges}</mergeCells><pageMargins left="0.3" right="0.3" top="0.5" bottom="0.5" header="0.2" footer="0.2"/><pageSetup orientation="landscape" paperSize="9" fitToWidth="1" fitToHeight="0"/></worksheet>'''
    styles = f'''<styleSheet xmlns="{ns}"><numFmts count="1"><numFmt numFmtId="164" formatCode='#,##0.00 &quot;EUR&quot;'/></numFmts><fonts count="3"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font><font><b/><sz val="16"/><name val="Calibri"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF173750"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border/></borders><cellStyleXfs count="1"><xf/></cellStyleXfs><cellXfs count="4"><xf fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf><xf fontId="1" fillId="2" borderId="0" xfId="0" applyAlignment="1"><alignment wrapText="1"/></xf><xf fontId="0" fillId="0" borderId="0" xfId="0" numFmtId="164" applyNumberFormat="1"/><xf fontId="2" fillId="0" borderId="0" xfId="0"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>'''
    stream = BytesIO()
    with ZipFile(stream, 'w', ZIP_DEFLATED) as archive:
        archive.writestr('[Content_Types].xml', '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>')
        archive.writestr('_rels/.rels', '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        archive.writestr('xl/workbook.xml', f'<workbook xmlns="{ns}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Relevé de commissions" sheetId="1" r:id="rId1"/></sheets></workbook>')
        archive.writestr('xl/_rels/workbook.xml.rels', '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
        archive.writestr('xl/styles.xml', styles)
        archive.writestr('xl/worksheets/sheet1.xml', sheet)
    stream.seek(0)
    return stream
