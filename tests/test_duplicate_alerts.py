import os
import unittest
from unittest.mock import MagicMock, patch

os.environ['LOCAL_MODE'] = '1'
from duplicate_detection import match_reasons, normalize_reference
import app as crm


class DuplicateTests(unittest.TestCase):
    def test_name_ignores_case_accents_and_punctuation(self):
        self.assertEqual(match_reasons({'names': ['Société Énergie, SAS']},
                                      {'names': ['SOCIETE ENERGIE SAS']}), ['Raison sociale'])

    def test_empty_fields_do_not_match(self):
        self.assertEqual(match_reasons({'names': [''], 'sirets': [None], 'references': ['']},
                                      {'names': [None], 'sirets': [''], 'references': ['']}), [])

    def test_siret_and_multisite_references(self):
        self.assertEqual(match_reasons({'sirets': ['123 456 789 00012'],
                                       'references': ['001 234', '009876']},
                                      {'sirets': ['12345678900012'], 'references': ['001234']}),
                         ['SIRET', 'PDL/PCE : 001234'])
        self.assertEqual(normalize_reference('001 234'), '001234')

    def test_distinct_names_and_references(self):
        self.assertEqual(match_reasons({'names': ['ABC'], 'references': ['123']},
                                      {'names': ['ABCD'], 'references': ['124']}), [])

    def test_lost_entry_skips_detection(self):
        conn = MagicMock()
        crm.record_dossier_duplicates(conn, 'ABC', '', status='perdu')
        conn.cursor.assert_not_called()

    def test_lost_source_quotation_skips_detection(self):
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value.fetchone.return_value = {'status': 'perdu'}
        with patch.object(crm, 'ensure_duplicate_alerts_schema') as ensure:
            crm.record_dossier_duplicates(conn, 'ABC', '', client_id=1)
            ensure.assert_not_called()

    def test_detection_excludes_own_dossier_and_records_owner(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        cur.fetchall.side_effect = [[
            dict(id=1, name='ABC', siret='', owner_id=1, status='en_cours', owner_name='Alice'),
            dict(id=2, name='ABC', siret='', owner_id=2, status='gagne', owner_name='Bob'),
        ], []]
        cur.fetchone.return_value = [12]
        with crm.app.test_request_context('/clients/1/edit'):
            crm.session['user'] = {'id': 1, 'username': 'Alice', 'role': 'commercial'}
            with patch.object(crm, 'ensure_cotation_schema'), \
                 patch.object(crm, 'ensure_cotation_delivery_points_schema'), \
                 patch.object(crm, 'ensure_duplicate_alerts_schema'):
                crm.record_dossier_duplicates(conn, 'ABC', '', client_id=1, status='en_cours')
        import json
        sql, args = cur.execute.call_args.args
        self.assertIn('INSERT INTO dossier_duplicate_alerts', sql)
        details = json.loads(args[-1])
        self.assertEqual([d['id'] for d in details], [2])
        self.assertEqual(details[0]['owner_name'], 'Bob')
        self.assertEqual(args[:2], (1, 'Alice'))
        self.assertIn("'gagne'", cur.execute.call_args_list[0].args[0])
        self.assertNotIn("'perdu'", cur.execute.call_args_list[0].args[0])

    def test_templates_compile(self):
        crm.app.jinja_env.get_template('base.html')
        crm.app.jinja_env.get_template('duplicate_alerts.html')

    def test_commercial_cannot_read_another_attempt(self):
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value.fetchone.return_value = {
            'actor_id': 2, 'details': [], 'actor_name': 'Other'}
        with crm.app.test_request_context('/alertes-doublons/1'):
            crm.session['user'] = {'id': 1, 'username': 'Sales', 'role': 'commercial'}
            with patch.object(crm, 'get_db', return_value=conn), \
                 patch.object(crm, 'ensure_duplicate_alerts_schema'):
                from werkzeug.exceptions import NotFound
                with self.assertRaises(NotFound):
                    crm.dossier_duplicate_alert(1)

    def test_commercial_receives_no_attempt_identity(self):
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value.fetchone.return_value = {
            'actor_id': 1, 'details': [], 'actor_name': 'Secret', 'attempted_name': 'ABC'}
        with crm.app.test_request_context('/alertes-doublons/1'):
            crm.session['user'] = {'id': 1, 'username': 'Sales', 'role': 'commercial'}
            with patch.object(crm, 'get_db', return_value=conn), \
                 patch.object(crm, 'ensure_duplicate_alerts_schema'), \
                 patch.object(crm, 'render_template', return_value='ok') as render:
                crm.dossier_duplicate_alert(1)
                self.assertEqual(render.call_args.kwargs['alerts'], [{'details': []}])


if __name__ == '__main__':
    unittest.main()
