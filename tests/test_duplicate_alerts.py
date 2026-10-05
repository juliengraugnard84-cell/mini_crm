import os
import unittest
from unittest.mock import MagicMock, patch

os.environ['LOCAL_MODE'] = '1'
from duplicate_detection import match_reasons, normalize_reference, is_blocking_match
import app as crm


class DuplicateTests(unittest.TestCase):
    def test_extended_name_warns_without_counting_as_identical_name(self):
        candidate = dict(names=['Societe Energie - Site Paris'], sirets=['123'], references=['001'])
        existing = dict(names=['Societe Energie'], sirets=['123'], references=['001'])
        reasons = match_reasons(candidate, existing)
        self.assertIn('Nom du dossier complété', reasons)
        self.assertFalse(is_blocking_match(reasons))
        self.assertEqual(match_reasons(dict(names=['ABCD']), dict(names=['ABC'])), [])

    def test_validation_is_admin_only_and_csrf_protected(self):
        response = self.api_client().post('/admin/alertes-doublons/8/valider',
                                         data={'csrf_token': 'test-token'})
        self.assertEqual(response.status_code, 403)
        response = self.api_client('admin').post('/admin/alertes-doublons/8/valider')
        self.assertEqual(response.status_code, 403)

    def test_admin_can_validate_and_validation_is_audited(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = [8]
        with patch.object(crm, 'get_db', return_value=conn), \
             patch.object(crm, 'ensure_duplicate_alerts_schema'):
            response = self.api_client('admin').post('/admin/alertes-doublons/8/valider',
                data={'csrf_token': 'test-token'}, headers={'Accept': 'application/json'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json['validated'])
        self.assertIn('validated_by', cur.execute.call_args.args[0])
        self.assertEqual(cur.execute.call_args.args[1], (1, 8))
        conn.commit.assert_called_once()

    def test_validated_attempt_is_allowed_and_consumed_only_on_save(self):
        for preflight in (True, False):
            with self.subTest(preflight=preflight):
                conn = MagicMock()
                cur = conn.cursor.return_value.__enter__.return_value
                cur.fetchall.side_effect = [[dict(id=2, name='ABC', siret='123', owner_id=2,
                    status='gagne', owner_name='Bob')], [dict(client_id=2, entreprise_nom='ABC',
                    siret='123', pdl_pce='001', pce=None, reference_code=None)]]
                cur.fetchone.return_value = [8]
                with crm.app.test_request_context('/clients/create'):
                    crm.session['user'] = dict(id=1, username='Alice', role='commercial')
                    with patch.object(crm, 'ensure_cotation_schema'), \
                         patch.object(crm, 'ensure_cotation_delivery_points_schema'), \
                         patch.object(crm, 'ensure_duplicate_alerts_schema'):
                        result = crm.record_dossier_duplicates(conn, 'ABC', '123', references=['001'],
                            status='en_cours', flash_warning=not preflight)
                self.assertIsNone(result)
                statements = [call.args[0] for call in cur.execute.call_args_list]
                self.assertFalse(any('INSERT INTO dossier_duplicate_alerts' in sql for sql in statements))
                self.assertEqual(any('SET authorization_used = TRUE' in sql for sql in statements), not preflight)

    def test_all_three_criteria_are_required(self):
        from itertools import product
        existing = dict(names=['ABC'], sirets=['123'], references=['001'])
        for name_matches, siret_matches, reference_matches in product([False, True], repeat=3):
            with self.subTest(name=name_matches, siret=siret_matches, reference=reference_matches):
                candidate = dict(names=['ABC' if name_matches else 'XYZ'],
                                 sirets=['123' if siret_matches else '456'],
                                 references=['001' if reference_matches else '002'])
                self.assertEqual(is_blocking_match(match_reasons(candidate, existing)),
                                 name_matches and siret_matches and reference_matches)
                self.assertEqual(bool(match_reasons(candidate, existing)),
                                 name_matches or siret_matches or reference_matches)

    def test_missing_criterion_does_not_block(self):
        existing = dict(names=['ABC'], sirets=['123'], references=['001'])
        for key in existing:
            for missing_value in ([], [''], [None]):
                with self.subTest(key=key, missing=missing_value):
                    candidate = dict(existing, **{key: missing_value})
                    self.assertFalse(is_blocking_match(match_reasons(candidate, existing)))
                    self.assertFalse(is_blocking_match(match_reasons(existing, candidate)))

    def test_criteria_on_different_dossiers_do_not_block(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        cur.fetchone.side_effect = [None, [12]]
        cur.fetchall.side_effect = [[
            dict(id=2, name='ABC', siret='123', owner_id=2, status='gagne', owner_name='Bob'),
            dict(id=3, name='Other', siret='456', owner_id=3, status='en_cours', owner_name='Charlie'),
        ], [dict(client_id=3, entreprise_nom='Other', siret='456',
                 pdl_pce='001', pce=None, reference_code=None)]]
        with crm.app.test_request_context('/clients/create'):
            crm.session['user'] = {'id': 1, 'username': 'Alice', 'role': 'commercial'}
            with patch.object(crm, 'ensure_cotation_schema'), \
                 patch.object(crm, 'ensure_cotation_delivery_points_schema'), \
                 patch.object(crm, 'ensure_duplicate_alerts_schema'):
                result = crm.record_dossier_duplicates(conn, 'ABC', '123', references=['001'], status='en_cours')
        self.assertFalse(result['blocked'])
        self.assertEqual(len(result['dossiers']), 2)
        self.assertTrue(any('INSERT INTO dossier_duplicate_alerts' in call.args[0]
                            for call in cur.execute.call_args_list))

    def test_name_ignores_case_accents_and_punctuation(self):
        self.assertEqual(match_reasons({'names': ['Société Énergie, SAS'], 'sirets': ['123'], 'references': ['001']},
                                      {'names': ['SOCIETE ENERGIE SAS'], 'sirets': ['123'], 'references': ['001']}),
                         ['Raison sociale', 'SIRET', 'PDL/PCE : 001'])

    def test_empty_fields_do_not_match(self):
        self.assertEqual(match_reasons({'names': [''], 'sirets': [None], 'references': ['']},
                                      {'names': [None], 'sirets': [''], 'references': ['']}), [])

    def test_siret_and_multisite_references(self):
        self.assertEqual(match_reasons({'names': ['ABC'], 'sirets': ['123 456 789 00012'],
                                       'references': ['001 234', '009876']},
                                      {'names': ['ABC'], 'sirets': ['12345678900012'], 'references': ['001234']}),
                         ['Raison sociale', 'SIRET', 'PDL/PCE : 001234'])
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
            dict(id=1, name='ABC', siret='123', owner_id=1, status='en_cours', owner_name='Alice'),
            dict(id=2, name='ABC', siret='123', owner_id=2, status='gagne', owner_name='Bob'),
        ], [dict(client_id=2, entreprise_nom='ABC', siret='123', pdl_pce='001', pce=None, reference_code=None)]]
        cur.fetchone.side_effect = [None, [12]]
        with crm.app.test_request_context('/clients/1/edit'):
            crm.session['user'] = {'id': 1, 'username': 'Alice', 'role': 'commercial'}
            with patch.object(crm, 'ensure_cotation_schema'), \
                 patch.object(crm, 'ensure_cotation_delivery_points_schema'), \
                 patch.object(crm, 'ensure_duplicate_alerts_schema'):
                crm.record_dossier_duplicates(conn, 'ABC', '123', client_id=1, references=['001'], status='en_cours')
        import json
        sql, args = cur.execute.call_args.args
        self.assertIn('INSERT INTO dossier_duplicate_alerts', sql)
        details = json.loads(args[4])
        self.assertEqual([d['id'] for d in details], [2])
        self.assertEqual(details[0]['owner_name'], 'Bob')
        self.assertEqual(args[:2], (1, 'Alice'))
        self.assertIn("'gagne'", cur.execute.call_args_list[0].args[0])
        self.assertNotIn("'perdu'", cur.execute.call_args_list[0].args[0])

    def test_templates_compile(self):
        crm.app.jinja_env.get_template('base.html')
        crm.app.jinja_env.get_template('duplicate_alerts.html')

    def api_client(self, role='commercial'):
        client = crm.app.test_client()
        with client.session_transaction() as session:
            session['user'] = {'id': 1, 'username': 'Alice', 'role': role}
            session['csrf_token'] = 'test-token'
        return client

    def test_prevalidation_blocks_commercial_without_exposing_details(self):
        client = self.api_client()
        result = dict(id=5, blocked=True, dossiers=[{'owner_name': 'Secret'}])
        with patch.object(crm, 'get_db', return_value=MagicMock()), \
             patch.object(crm, 'record_dossier_duplicates', return_value=result):
            response = client.post('/api/dossiers/check-duplicates', data={
                'csrf_token': 'test-token', 'duplicate_kind': 'create', 'name': 'ABC'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['dossiers'], [])
        self.assertTrue(response.json['blocked'])
        self.assertEqual(response.json['message'], "dossier bloqué, voir avec l'administrateur")

    def test_prevalidation_requires_csrf(self):
        response = self.api_client().post('/api/dossiers/check-duplicates', data={'duplicate_kind': 'create'})
        self.assertEqual(response.status_code, 403)

    def test_prevalidation_checks_dossier_access(self):
        with patch.object(crm, 'get_db', return_value=MagicMock()), \
             patch.object(crm, 'can_access_client', return_value=False):
            response = self.api_client().post('/api/dossiers/check-duplicates', data={
                'csrf_token': 'test-token', 'duplicate_kind': 'edit', 'duplicate_client_id': 8})
        self.assertEqual(response.status_code, 403)

    def test_feed_denies_commercial(self):
        self.assertEqual(self.api_client().get('/api/admin/duplicate-alerts').status_code, 403)

    def test_feed_returns_full_admin_alert_with_cursor(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = [1]
        cur.fetchall.return_value = [dict(id=8, actor_name='Alice', attempted_name='ABC',
                                         details=[dict(id=2, owner_name='Bob', reasons=['SIRET'])])]
        with patch.object(crm, 'get_db', return_value=conn), \
             patch.object(crm, 'ensure_duplicate_alerts_schema'):
            response = self.api_client('admin').get('/api/admin/duplicate-alerts?after=7')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['cursor'], 8)
        self.assertEqual(response.json['alerts'][0]['actor_name'], 'Alice')
        self.assertEqual(response.json['alerts'][0]['dossiers'][0]['owner_name'], 'Bob')
        self.assertEqual(response.headers['Cache-Control'], 'no-store')

    def test_creation_is_blocked_without_javascript(self):
        conn = MagicMock()
        with patch.object(crm, 'get_db', return_value=conn), \
             patch.object(crm, 'ensure_hot_followups_schema'), \
             patch.object(crm, 'record_dossier_duplicates', return_value=dict(blocked=True)):
            response = self.api_client().post('/clients/create', data={
                'csrf_token': 'test-token', 'name': 'ABC', 'siret': '123'})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith('/clients'))
        conn.cursor.assert_not_called()

    def test_prevalidation_no_duplicate_allows_submission(self):
        with patch.object(crm, 'get_db', return_value=MagicMock()), \
             patch.object(crm, 'record_dossier_duplicates', return_value=None):
            response = self.api_client().post('/api/dossiers/check-duplicates', data={
                'csrf_token': 'test-token', 'duplicate_kind': 'create', 'name': 'New'})
        self.assertFalse(response.json['blocked'])
        self.assertEqual(response.json['dossiers'], [])

    def test_admin_prevalidation_keeps_dossier_details_and_override(self):
        match = dict(id=2, name='ABC', siret='123', status='gagne', owner_name='Bob',
                     owner_id=2, reasons=['SIRET'])
        with patch.object(crm, 'get_db', return_value=MagicMock()), \
             patch.object(crm, 'record_dossier_duplicates', return_value=dict(
                 blocked=False, dossiers=[match])):
            response = self.api_client('admin').post('/api/dossiers/check-duplicates', data={
                'csrf_token': 'test-token', 'duplicate_kind': 'create', 'name': 'ABC'})
        self.assertFalse(response.json['blocked'])
        self.assertEqual(response.json['dossiers'][0]['owner_name'], 'Bob')

    def test_prevalidation_and_submission_do_not_duplicate_notification(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        dossier = dict(id=2, name='ABC', siret='123', owner_id=2, status='gagne', owner_name='Bob')
        quotation = dict(client_id=2, entreprise_nom='ABC', siret='123', pdl_pce='001', pce=None, reference_code=None)
        cur.fetchall.side_effect = [[dossier], [quotation], [dossier], [quotation]]
        cur.fetchone.side_effect = [None, [12], None, [12]]
        with crm.app.test_request_context('/clients/create'):
            crm.session['user'] = {'id': 1, 'username': 'Alice', 'role': 'commercial'}
            with patch.object(crm, 'ensure_cotation_schema'), \
                 patch.object(crm, 'ensure_cotation_delivery_points_schema'), \
                 patch.object(crm, 'ensure_duplicate_alerts_schema'):
                preview = crm.record_dossier_duplicates(conn, 'ABC', '123', references=['001'], status='en_cours', flash_warning=False)
                saved = crm.record_dossier_duplicates(conn, 'ABC', '123', references=['001'], status='en_cours')
                self.assertTrue(preview['blocked'])
                self.assertTrue(saved['blocked'])
                self.assertEqual(crm.session['_flashes'][-1][1], "dossier bloqué, voir avec l'administrateur")
        inserts = [call for call in cur.execute.call_args_list
                   if 'INSERT INTO dossier_duplicate_alerts' in call.args[0]]
        self.assertEqual(len(inserts), 1)
        self.assertEqual(conn.commit.call_count, 2)

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
                self.assertEqual(render.call_args.kwargs['alerts'], [{'details': [], 'message': 'dossier déjà en cours'}])

    def test_partial_match_warns_commercial_without_blocking_or_exposing_details(self):
        with patch.object(crm, 'get_db', return_value=MagicMock()), \
             patch.object(crm, 'record_dossier_duplicates', return_value=dict(
                 id=5, blocked=False, dossiers=[dict(owner_name='Secret', reasons=['SIRET'])])):
            response = self.api_client().post('/api/dossiers/check-duplicates', data={
                'csrf_token': 'test-token', 'duplicate_kind': 'create', 'name': 'ABC'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json['warning'])
        self.assertFalse(response.json['blocked'])
        self.assertEqual(response.json['message'], 'dossier déjà en cours')
        self.assertEqual(response.json['dossiers'], [])

    def test_partial_match_records_attempt_and_flashes_warning(self):
        for siret, expected in [('456', ['Raison sociale']), ('123', ['Raison sociale', 'SIRET'])]:
            with self.subTest(siret=siret):
                conn = MagicMock()
                cur = conn.cursor.return_value.__enter__.return_value
                cur.fetchall.side_effect = [[dict(id=2, name='ABC', siret='123', owner_id=2,
                    status='en_cours', owner_name='Bob')], []]
                cur.fetchone.side_effect = [None, [12]]
                with crm.app.test_request_context('/clients/create'):
                    crm.session['user'] = dict(id=1, username='Alice', role='commercial')
                    with patch.object(crm, 'ensure_cotation_schema'), \
                         patch.object(crm, 'ensure_cotation_delivery_points_schema'), \
                         patch.object(crm, 'ensure_duplicate_alerts_schema'):
                        result = crm.record_dossier_duplicates(conn, 'ABC', siret, status='en_cours')
                    self.assertFalse(result['blocked'])
                    self.assertEqual(result['dossiers'][0]['reasons'], expected)
                    self.assertEqual(crm.session['_flashes'][-1], ('warning', 'dossier déjà en cours'))


if __name__ == '__main__':
    unittest.main()
