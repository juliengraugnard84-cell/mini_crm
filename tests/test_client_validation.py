import os
import unittest
from datetime import date
from decimal import Decimal
from unittest.mock import MagicMock, patch

os.environ['LOCAL_MODE'] = '1'
import app as crm


class ClientValidationTests(unittest.TestCase):
    def setUp(self):
        self.conn = MagicMock()
        self.cur = self.conn.cursor.return_value.__enter__.return_value
        self.cur.fetchone.return_value = dict(id=42, name='Dossier test', status='gagne',
                                             owner_id=7, commercial='Alice')
        self.cur.fetchall.return_value = []
        self.client = crm.app.test_client()
        with self.client.session_transaction() as session:
            session['user'] = dict(id=7, username='Alice', role='commercial')
            session['csrf_token'] = 'test'
        for name, kwargs in [('get_db', dict(return_value=self.conn)),
                             ('ensure_commissions_schema', {}),
                             ('can_access_client', dict(return_value=True)),
                             ('render_template', dict(return_value='validation'))]:
            patcher = patch.object(crm, name, **kwargs)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

    def post(self, amount='1 250,50', **extra):
        return self.client.post('/clients/42/validation', data=dict(
            csrf_token='test', montant=amount, date='2026-11-19', revenue_source='ade', **extra))

    def inserts(self):
        return [c for c in self.cur.execute.call_args_list if 'INSERT INTO revenus' in c.args[0]]

    def test_records_ca_with_server_side_owner_and_dossier(self):
        response = self.post(commercial='Someone else', client_id=99)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/chiffre-affaire?year=2026', response.location)
        self.assertEqual(self.inserts()[0].args[1],
                         (date(2026, 11, 19), 'Alice', 'Dossier test', 42, Decimal('812.82'), 'ade', 'ade', Decimal('1250.50'), 'ade', Decimal('35'), None, 'Alice'))
        self.conn.commit.assert_called_once()

    def test_existing_ca_prevents_duplicate_submission(self):
        self.cur.fetchall.return_value = [dict(id=1, montant=100, date=date.today())]
        self.assertEqual(self.post().status_code, 302)
        self.assertFalse(self.inserts())

    def test_rejects_invalid_amounts(self):
        for amount in ['', '0', '-1', 'NaN', 'Infinity', '12.345', '1e9999999', 'abc']:
            with self.subTest(amount=amount):
                self.assertEqual(self.post(amount).status_code, 400)
                self.assertFalse(self.inserts())

    def test_invalid_date_preserves_input(self):
        response = self.client.post('/clients/42/validation', data=dict(
            csrf_token='test', montant='25,50', date='2026-02-30'))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.render_template.call_args.kwargs['amount_text'], '25,50')
        self.assertFalse(self.inserts())

    def test_access_and_csrf(self):
        self.can_access_client.return_value = False
        self.assertEqual(self.post().status_code, 403)
        self.can_access_client.return_value = True
        self.assertEqual(self.client.post('/clients/42/validation').status_code, 403)
        self.cur.fetchone.return_value['owner_id'] = 99
        self.assertEqual(self.post().status_code, 403)
        self.assertFalse(self.inserts())

    def test_only_won_dossiers_can_be_validated(self):
        self.cur.fetchone.return_value['status'] = 'en_cours'
        self.assertEqual(self.post().location, '/clients/42')
        self.assertFalse(self.inserts())

    def test_database_failure_allows_retry(self):
        self.conn.commit.side_effect = RuntimeError('database unavailable')
        self.assertEqual(self.post().status_code, 400)
        self.conn.rollback.assert_called()

    def test_status_change_opens_validation(self):
        self.cur.fetchone.return_value['siret'] = None
        with patch.object(crm, 'record_dossier_duplicates', return_value=None), \
             patch.object(crm, 'ensure_client_groups_schema'), \
             patch.object(crm, 'attach_client_group'):
            response = self.client.post('/clients/42/status', data=dict(csrf_token='test', status='gagne'))
        self.assertEqual(response.location, '/clients/42/validation')

    def test_template_renders_form_and_existing_revenue(self):
        with crm.app.test_request_context('/'):
            template = crm.app.jinja_env.get_template('client_validation.html')
            context = dict(client=self.cur.fetchone.return_value, revenues=[], error=None,
                           amount_text='', revenue_date='2026-11-19', csrf_token='test',
                           current_user=None, available_endpoints=[])
            self.assertIn('Valider et intégrer au CA', template.render(**context))
            context['revenues'] = [dict(date=date(2026, 11, 19), montant=1250.5)]
            html = template.render(**context)
            self.assertIn('1250.50', html)
            self.assertNotIn('name="montant"', html)


if __name__ == '__main__':
    unittest.main()
