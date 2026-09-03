from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether

OUT = r"C:\mini_crm\output\pdf\rapport_verification_plan_analyse_energie.pdf"

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="TitleCRM", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=21, leading=26, textColor=colors.HexColor("#123646"), alignment=TA_CENTER, spaceAfter=10))
styles.add(ParagraphStyle(name="Sub", parent=styles["Normal"], fontSize=10, leading=14, alignment=TA_CENTER, textColor=colors.HexColor("#536470"), spaceAfter=24))
styles.add(ParagraphStyle(name="H1CRM", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=14, leading=18, textColor=colors.HexColor("#123646"), spaceBefore=14, spaceAfter=7))
styles.add(ParagraphStyle(name="H2CRM", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=colors.HexColor("#2f6cab"), spaceBefore=9, spaceAfter=4))
styles.add(ParagraphStyle(name="BodyCRM", parent=styles["BodyText"], fontSize=9.2, leading=13.2, spaceAfter=6))
styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=7.8, leading=10.4))

def P(text, style="BodyCRM"):
    return Paragraph(text, styles[style])

def table(rows, widths):
    converted = [[P(str(c), "Small") for c in row] for row in rows]
    t = Table(converted, colWidths=widths, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123646")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5df")),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f7fafc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f7fafc"), colors.white]),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return t

def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#cbd5df"))
    canvas.line(1.7 * cm, 1.35 * cm, A4[0] - 1.7 * cm, 1.35 * cm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#536470"))
    canvas.drawString(1.7 * cm, 0.9 * cm, "Mini CRM - Rapport de verification du plan d'analyse energie")
    canvas.drawRightString(A4[0] - 1.7 * cm, 0.9 * cm, f"Page {doc.page}")
    canvas.restoreState()

story = []
story += [Spacer(1, 2.1 * cm), P("Rapport de verification", "TitleCRM"), P("Plan d'integration du module d'analyse de contrats, factures et comparatifs d'energie", "Sub")]
story += [P("Statut de la verification", "H1CRM"), P("Inspection realisee en lecture seule. Aucun fichier applicatif, aucune configuration, aucune base de donnees et aucun document n'ont ete modifies."),
          table([["Point", "Constat"], ["Depot Git", "Branche main propre : aucune modification locale non validee detectee."], ["Perimetre", "Code serveur, templates, scripts de lancement, dependances, routes, stockage et schema PostgreSQL declares ont ete examines."], ["Resultat", "Le plan est realisable, a condition de separer les donnees extraites, les referentiels reglementaires et les calculs." ]], [4.1*cm, 12.0*cm]),
          P("Conclusion", "H1CRM"), P("Le plan recommande est coherent avec le CRM existant et protege la regle centrale : l'IA extrait et justifie ; le serveur valide et calcule ; un humain autorise toute ecriture dans le CRM."),
          P("Architecture constatee", "H1CRM"), table([["Composant", "Verification"], ["Serveur", "Flask monolithique dans app.py ; routes HTTP et logique metier concentrees dans un seul fichier."], ["Interface", "Templates Jinja et Bootstrap dans templates/, CSS et JavaScript dans static/."], ["Donnees", "PostgreSQL via psycopg2 et variable DATABASE_URL. Aucun ORM ni migrations versionnees."], ["Stockage", "S3 prive en production. Les documents clients sont identifies par cle S3, sans table de metadonnees documentaire."], ["Executables", "run_local.bat en local ; gunicorn app:app --timeout 120 en production."], ["Tests", "Aucune suite Python. npm test est intentionnellement non configure." ]], [4.1*cm, 12.0*cm])]

story.append(PageBreak())
story += [P("Modeles existants et ecarts", "H1CRM"), table([["Besoin cible", "Etat actuel", "Decision de plan"], ["Client", "crm_clients", "Conserver et relier les nouvelles entites par client_id."], ["Site", "Nom/adresse places dans cotations", "Creer energy_sites : identite stable, adresse, client."], ["Compteur", "cotation_delivery_points sans identite metier", "Creer energy_meters : energie, PDL/PRM ou PCE, site."], ["Contrat", "Champs melanges dans cotations", "Creer energy_contracts, avec periode et fournisseur."], ["Offre", "Aucun modele dedie", "Creer energy_offers, sans ecraser le contrat."], ["Comparatif", "Aucun moteur", "Creer energy_comparisons et resultats calcules." ]], [3.1*cm, 5.0*cm, 8.0*cm]),
          P("Formulaires et ecrans commerciaux", "H1CRM"), P("La fiche client est le bon point d'entree : elle contient deja l'historique des cotations, les documents et le formulaire de nouvelle demande. Le module ajoutera un onglet Analyse energie, un depot de PDF, une revue des preuves et une action explicite de creation de cotation."),
          P("Donnees deja presentes", "H2CRM"), P("Les formulaires actuels couvrent partiellement l'electricite (C2, C4, C5, puissance, Pointe, HPH, HCH, HPR, HCE) et le gaz (PCE, T1, T2, T3, CAR). Ils ne portent pas les prix, taxes, budgets, sources documentaires, T4, ni une representation fiable des postes C5 quatre postes."),
          P("Stockage documentaire", "H1CRM"), P("Le nouveau module devra conserver le PDF original dans un prefixe S3 dedie, une empreinte SHA-256, le type detecte et son rattachement client. Il ne devra jamais se fonder sur le seul nom du fichier. La restriction actuelle du mode local sur les uploads clients devra etre traitee lors de l'implementation."),
          P("Compatibilite", "H1CRM"), P("Le module sera ajoute sous forme de blueprint Flask isole. Cette isolation limite le risque sur les routes, sessions, CSRF, droits admin/commercial et formulaires de cotation existants.")]

story.append(PageBreak())
story += [P("Flux de controle obligatoire", "H1CRM"), table([["Etape", "Garantie verifiee"], ["1. Depot", "PDF uniquement, taille limitee, antivirus si disponible, SHA-256 et stockage prive."], ["2. Extraction", "Appel serveur OpenAI Responses avec JSON Schema strict. Aucun appel depuis le navigateur."], ["3. Preuve", "Chaque valeur conserve valeur, statut, fichier, page et extrait court."], ["4. Controle", "Formats, sommes, HT + TVA = TTC, doublons, chevauchements et comparaison CRM."], ["5. Revue humaine", "Ecran avec PDF, champs proposes, erreurs, conflits et choix explicites."], ["6. Validation", "Journal d'audit de la personne, date, decisions et justifications."], ["7. Ecriture", "Creation ou mise a jour autorisee seulement apres validation. Aucun ecrasement silencieux."], ["8. Calcul", "Moteur Python deterministe utilisant uniquement valeurs valides et referentiels dates."], ["9. Commercial", "Creation controlee d'une cotation ou d'un comparatif depuis les donnees validees." ]], [3.5*cm, 12.6*cm]),
          P("Classification de chaque valeur", "H1CRM"), table([["Statut", "Definition appliquee"], ["verified", "Valeur explicitement ecrite dans le PDF, avec page et extrait."], ["calculated_exactly", "Valeur obtenue par formule deterministe a partir de valeurs verified, avec formule versionnee."], ["missing", "Valeur absente ou non lisible. Elle reste nulle et ne peut pas etre devinee."], ["inconsistent", "Deux preuves, le CRM ou un controle mathematique se contredisent. Validation humaine obligatoire." ]], [4.1*cm, 12.0*cm]),
          P("Schema d'extraction valide", "H1CRM"), P("Le schema racine contiendra document, customer, sites[], meters[], contract, electricity, gas, document_totals et document_issues[]. Chaque champ metier utilisera la meme enveloppe : value, normalized_value, unit, status, source_file, source_page et evidence. Le JSON Schema interdira les proprietes non prevues et imposera les enumerations de statut et d'energie.")]

story.append(PageBreak())
story += [P("Donnees et calculs a isoler", "H1CRM"), table([["Groupe", "Tables prevues", "Regle"], ["Document et IA", "energy_documents, energy_analysis_runs, energy_analysis_fields", "Conserver original, empreinte, reponse brute versionnee et preuves."], ["Modele metier", "energy_sites, energy_meters, energy_contracts, energy_offers", "Representer les entites metier, jamais dans une seule cotation."], ["Reglementation", "energy_regulatory_sources, energy_regulatory_values", "Source, URL ou document, date de publication, periode d'effet, unite."], ["Controle", "energy_validation_issues, energy_review_changes", "Erreurs et arbitrages humains auditables."], ["Resultats", "energy_comparisons et resultats calcules", "Separer resultats de la donnee contractuelle et des taux." ]], [3.0*cm, 6.8*cm, 5.8*cm]),
          P("Calculs autorises", "H1CRM"), P("Le serveur calculera les budgets energie, acheminement, HTVA et TTC. Les calculs n'utiliseront que les consommations, prix et parametres verifies ou valides, ainsi que les taux reglementaires applicables a la date de fourniture. L'IA ne proposera ni taux, ni TURPE, ni ATRD/ATRT, ni taxe, ni budget final."),
          P("Controles a couvrir par tests", "H1CRM"), P("C2, C4, C5 standard, C5 quatre postes, gaz T1, T2, T3 et T4 ; PDL/PRM/PCE ; SIREN/SIRET ; doublons par empreinte et par metier ; chevauchement de contrats ; coherence des consommations ; HT + TVA = TTC ; conflit avec les donnees CRM ; interdiction d'ecrasement ; version et date du referentiel."),
          P("Routes prevues", "H1CRM"), P("GET /clients/<id>/energy-analysis ; POST /clients/<id>/energy-analysis/documents ; POST /energy-analysis/<id>/extract ; GET /energy-analysis/<id>/review ; POST /energy-analysis/<id>/review/fields ; POST /energy-analysis/<id>/validate ; POST /energy-analysis/<id>/apply ; GET /energy-analysis/<id>/comparison ; POST /energy-analysis/<id>/comparison/create.")]

story.append(PageBreak())
story += [P("Ordre recommande des travaux", "H1CRM"), table([["Ordre", "Lot", "Critere de sortie"], ["1", "Referentiels et regles metier", "Sources reglementaires autorisees, dates d'effet et regles de validation ecrites."], ["2", "Migration PostgreSQL", "Tables normalisees, contraintes et index poses sans toucher aux donnees cotations."], ["3", "Documents", "Depot PDF, stockage prive, SHA-256, droits et audit fonctionnels."], ["4", "Extraction structuree", "Reponse JSON Schema validee, stockee, sans ecriture CRM."], ["5", "Validation", "Tous les controles bloquants et conflits CRM sont visibles et testes."], ["6", "Revue humaine", "Validation explicite et journalisee pour chaque proposition."], ["7", "Calcul", "Resultats reproductibles a partir d'entrees et referentiels versions."], ["8", "Integration CRM", "Creation controlee de sites, compteurs, contrats, puis cotations."], ["9", "Comparatifs", "Ecran commercial fonde uniquement sur des valeurs validees."], ["10", "Recette", "Jeux de PDF anonymises et non-regression des cotations existantes." ]], [1.1*cm, 5.0*cm, 9.5*cm]),
          P("Risques et mesures", "H1CRM"), table([["Risque", "Mesure"], ["Monolithe app.py", "Blueprint et services isoles ; tests de routes existantes avant fusion."], ["Absence de migrations/test", "SQL versionne, sauvegarde, tests unitaires et d'integration ajoutes avant ecriture CRM."], ["PDF ambigus", "Statut missing ou inconsistent ; revue humaine obligatoire."], ["Tarifs evolutifs", "Referentiel date, source obligatoire ; aucun taux en dur dans contrat ou code."], ["Conflit CRM", "Comparaison explicite et choix humain historise."], ["Donnees sensibles", "API cote serveur, S3 prive, droits existants et journalisation." ]], [4.1*cm, 12.0*cm]),
          P("Point bloquant avant implementation", "H1CRM"), P("Le plan est pret, mais aucun calcul exact ne peut etre active tant que la source reglementaire de reference n'est pas designee pour TURPE, ATRD/ATRT, CTA, accise/TICGN, CPB et leurs dates d'effet. Cette decision doit preciser l'organisme ou fournisseur de donnees autorise, la frequence de mise a jour et la preuve a archiver."),
          P("Decision de verification", "H1CRM"), P("Plan valide sous reserve de cette designation de referentiel. Aucune modification du CRM n'est recommandee avant cet accord metier.")]

doc = SimpleDocTemplate(OUT, pagesize=A4, rightMargin=1.7*cm, leftMargin=1.7*cm, topMargin=1.5*cm, bottomMargin=1.75*cm, title="Rapport de verification - Analyse energie")
doc.build(story, onFirstPage=footer, onLaterPages=footer)
print(OUT)
