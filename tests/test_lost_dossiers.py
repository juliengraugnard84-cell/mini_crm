import os
import unittest
from datetime import date
from io import BytesIO
from unittest.mock import MagicMock, patch

os.environ['LOCAL_MODE'] = '1'
import app as crm
from lost_dossiers import pdf_lost_dossiers


class LostDossiersTests(unittest.TestCase):
    def setUp(self):
        active_session = patch.object(crm, 'session_user_is_active', return_value=True)
        active_session.start()
        self.addCleanup(active_session.stop)

    def client(self, role='admin', user_id=1):
        client = crm.app.test_client()
        with client.session_transaction() as session:
            session['user'] = dict(id=user_id, role=role, username='Alice')
        return client

    def test_access_and_owner_filter(self):
        url = '/dossiers-perdus/export.pdf'
        self.assertEqual(crm.app.test_client().get(url).status_code, 302)
        self.assertEqual(self.client('other').get(url).status_code, 403)
        self.assertEqual(self.client('commercial').get(url + '?commercial_id=2').status_code, 403)
        self.assertEqual(self.client().get(url + '?commercial_id=wrong').status_code, 400)
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = dict(username='Alice')
        cur.fetchall.return_value = []
        with patch.object(crm, 'get_db', return_value=conn):
            response = self.client('commercial').get(url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.mimetype, 'application/pdf')
            self.assertEqual(response.headers['Cache-Control'], 'private, no-store')
            query, params = cur.execute.call_args.args
            self.assertIn("= 'perdu'", query)
            self.assertIn('c.owner_id = %s', query)
            self.assertEqual(params, (1,))
            self.client().get(url)
            self.assertEqual(cur.execute.call_args.args[1], ())
            self.client().get(url + '?commercial_id=2')
            self.assertEqual(cur.execute.call_args.args[1], (2,))
            cur.fetchone.return_value = None
            self.assertEqual(self.client().get(url + '?commercial_id=999').status_code, 404)

    def test_related_records_and_document_inventory(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        client = dict(id=10, name='Entreprise', status='perdu', owner_id=1)
        cotation = dict(id=3, client_id=10, commentaire='Commentaire cotation')
        update = dict(id=4, client_id=10, commentaire='Rappeler plus tard')
        items = [dict(Key='clients/10/facture.pdf', Size=123),
                 dict(Key='clients/ancien_nom_10/contrat.pdf', Size=456),
                 dict(Key='clients/11/autre.pdf', Size=999)]
        with patch.object(crm, 'get_db', return_value=conn), \
             patch.object(crm, 'ensure_hot_followups_schema'), \
             patch.object(crm, 'enrich_cotations_with_delivery_points', side_effect=lambda conn, rows: rows), \
             patch.object(crm, 'list_local_storage_objects', return_value=items) as inventory, \
             patch('lost_dossiers.pdf_lost_dossiers', return_value=BytesIO(b'%PDF-test')) as render:
            cur.fetchall.side_effect = [[client], [cotation], [update], [], []]
            self.assertEqual(self.client().get('/dossiers-perdus/export.pdf').status_code, 200)
            dossier = render.call_args.args[0][0]
            self.assertEqual(dossier['cotations'], [cotation])
            self.assertEqual(dossier['updates'], [update])
            self.assertEqual(len(dossier['documents']), 2)
            inventory.assert_called_once_with('clients/')
            inventory.side_effect = OSError('storage unavailable')
            cur.fetchall.side_effect = [[client], [], [], [], []]
            self.client().get('/dossiers-perdus/export.pdf')
            self.assertIsNone(render.call_args.args[0][0]['documents'])

    def test_pdf_long_comments_and_empty_inventory(self):
        from pypdf import PdfReader
        dossier = dict(client=dict(id=1, name='Société <test> & associés',
                                   created_at=date(2026, 11, 25),
                                   notes=('Commentaire détaillé à conserver.\n' * 180) + 'FIN-COMMENTAIRE'),
                       documents=[dict(name='facture.pdf', key='clients/1/facture.pdf', size=12)],
                       cotations=[dict(id=4, date_negociation=date(2026, 11, 24),
                                       delivery_points=[dict(reference_code='PDL-123', commentaire='Site annexe')])])
        reader = PdfReader(pdf_lost_dossiers([dossier], 'Alice'))
        text = '\n'.join(page.extract_text() for page in reader.pages)
        for expected in ['FIN-COMMENTAIRE', 'Société <test> & associés', '25/11/2026',
                         '24/11/2026', 'PDL-123', 'Site annexe', 'facture.pdf',
                         'Date de contact : non renseignée']:
            self.assertIn(expected, text)
        self.assertGreater(len(reader.pages), 3)
        for i, page in enumerate(reader.pages, 1):
            self.assertIn(f'Page {i}', page.extract_text())
        for documents, expected in [(None, 'Inventaire indisponible'),
                                    ([], 'Aucun document enregistré')]:
            dossier['documents'] = documents
            text = '\n'.join(p.extract_text() for p in PdfReader(pdf_lost_dossiers([dossier], 'Alice')).pages)
            self.assertIn(expected, text)
        empty = PdfReader(pdf_lost_dossiers([], 'Tous'))
        self.assertIn('Aucun dossier perdu', empty.pages[0].extract_text())


if __name__ == '__main__':
    unittest.main()
