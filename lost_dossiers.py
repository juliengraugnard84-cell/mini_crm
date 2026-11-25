"""Printable, complete recovery files for lost opportunities."""
from datetime import date, datetime
from io import BytesIO
from xml.sax.saxutils import escape


LABELS = {
    'name': 'Nom du dossier', 'email': 'E-mail', 'phone': 'Téléphone',
    'address': 'Adresse', 'commercial': 'Commercial renseigné',
    'commercial_name': 'Commercial', 'gerant_nom': 'Nom du gérant',
    'siret': 'SIRET', 'notes': 'Notes / commentaires',
    'created_at': 'Date de création', 'date_creation': 'Date de création',
    'date_contact': 'Date de contact', 'contact_date': 'Date de contact',
    'update_date': 'Date du suivi', 'commentaire': 'Commentaire',
    'date_negociation': 'Date de négociation', 'date_echeance': "Date d’échéance",
    'pdl_pce': 'PDL / PCE', 'pce': 'PCE', 'reference_code': 'Référence PDL / PCE',
    'site_label': 'Site', 'energy_type': 'Énergie', 'energie_type': 'Énergie',
    'supplier': 'Fournisseur', 'follow_up_date': 'Date de relance',
    'follow_up_time': 'Heure de relance', 'status': 'Statut',
    'dossier_category': 'Catégorie du dossier', 'date': 'Date',
    'montant': 'Montant (EUR)', 'client_name': 'Nom du client',
}
INTERNAL_FIELDS = {
    'id', 'client_id', 'owner_id', 'created_by', 'is_read', 'commercial_id',
    'cotation_id', 'calendar_event_id', 'client_group_id', 'sort_order',
    'delivery_points', 'delivery_points_count', 'delivery_points_summary',
    'owner_name',
}


def display(value):
    if isinstance(value, datetime):
        return value.strftime('%d/%m/%Y %H:%M')
    if isinstance(value, date):
        return value.strftime('%d/%m/%Y')
    return str(value)


def pdf_lost_dossiers(dossiers, scope, generated_on=None):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak

    stream = BytesIO()
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle('Field', parent=styles['BodyText'], fontSize=9,
                              leading=13, spaceAfter=5, splitLongWords=True))
    story = []

    def paragraph(value, style='Field'):
        story.append(Paragraph(escape(display(value)).replace('\n', '<br/>'), styles[style]))

    def fields(record):
        for key, value in record.items():
            if key in INTERNAL_FIELDS or value is None or value == '' or value == []:
                continue
            label = LABELS.get(key, key.replace('_', ' ').capitalize())
            # Separate flowables let even very long comments span pages.
            paragraph(label, 'Heading4')
            paragraph(value)

    paragraph('Dossiers perdus', 'Title')
    paragraph(scope, 'Heading2')
    paragraph(f"Export du {display(generated_on or date.today())} - {len(dossiers)} dossier(s)")
    paragraph('Archive de travail pour une reprise de contact. Les documents sont inventoriés ; '
              'leurs contenus ne sont pas joints au PDF. Seules les informations renseignées sont reprises.')
    if not dossiers:
        paragraph('Aucun dossier perdu dans ce périmètre.')
    for dossier in dossiers:
        story.append(PageBreak())
        client = dossier['client']
        paragraph(f"Dossier n°{client['id']} - {client['name']}", 'Heading1')
        paragraph(f"Commercial : {client.get('owner_name') or client.get('commercial') or 'Non attribué'}", 'Heading2')
        if not (client.get('date_contact') or client.get('contact_date')):
            paragraph('Date de contact : non renseignée. La date de création et les dates de '
                      'négociation / suivi ci-dessous ne constituent pas une date de contact confirmée.')
        fields(client)
        paragraph('Documents en notre possession', 'Heading2')
        documents = dossier['documents']
        if documents is None:
            paragraph('Inventaire indisponible : impossible de vérifier les documents lors de cet export.')
        elif not documents:
            paragraph('Aucun document enregistré pour ce dossier.')
        else:
            paragraph(f'{len(documents)} document(s) enregistré(s)')
            for document in documents:
                paragraph(document['name'], 'Heading4')
                paragraph(f"Emplacement : {document['key']}")
                paragraph(f"Taille : {document['size']} octets")
                if document.get('modified'):
                    paragraph(f"Dernière modification du fichier : {display(document['modified'])}")
        for key, title in [('cotations', 'Cotations et commentaires'),
                           ('updates', 'Historique des mises à jour et commentaires'),
                           ('followups', 'Relances et notes'), ('revenues', 'Revenus rattachés')]:
            records = dossier.get(key, [])
            if not records:
                continue
            paragraph(title, 'Heading2')
            for record in records:
                paragraph(f"{title.split(' et ')[0]} - n°{record['id']}", 'Heading3')
                fields(record)
                for index, point in enumerate(record.get('delivery_points', []), 1):
                    paragraph(f'Point de livraison {index}', 'Heading3')
                    fields(point)
        story.append(Spacer(1, 10))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.HexColor('#64748b'))
        canvas.drawString(42, 25, 'CRM - Dossiers perdus - Usage interne')
        canvas.drawRightString(A4[0] - 42, 25, f'Page {doc.page}')
        canvas.restoreState()

    SimpleDocTemplate(stream, pagesize=A4, rightMargin=42, leftMargin=42,
                      topMargin=40, bottomMargin=45, title='Dossiers perdus',
                      author='CRM').build(story, onFirstPage=footer, onLaterPages=footer)
    stream.seek(0)
    return stream
