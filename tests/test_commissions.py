import os
import unittest
from decimal import Decimal
from datetime import date
from unittest.mock import MagicMock, patch

os.environ['LOCAL_MODE'] = '1'
import app as crm
from commissions import parse_rate, commission_values, revenue_breakdown


class CommissionTests(unittest.TestCase):
    def test_supplier_retention_before_commission(self):
        for source, net, commission, aleo in [('ade', '650', '195', '455'), ('direct', '500', '150', '350')]:
            initial, retained, actual_net = revenue_breakdown('1 000,00', source)
            self.assertEqual(actual_net, Decimal(net))
            self.assertEqual(initial, retained + actual_net)
            self.assertEqual(commission_values(dict(montant=actual_net, commission_rate=30, aleo_rate=70)),
                             (Decimal(commission), Decimal(aleo)))
        for source in ['', 'other']:
            with self.assertRaises(ValueError):
                revenue_breakdown(1000, source)

    def test_rates(self):
        self.assertEqual(parse_rate('25,50'), Decimal('25.50'))
        for rate in ['-1', '101', 'NaN', 'Infinity', '', '2.345']:
            with self.subTest(rate=rate), self.assertRaises(ValueError):
                parse_rate(rate)

    def test_split_and_cent_rounding(self):
        self.assertEqual(commission_values(dict(montant=1000, commission_rate=30, aleo_rate=70)),
                         (Decimal('300.00'), Decimal('700.00')))
        self.assertEqual(commission_values(dict(montant=.05, commission_rate=50, aleo_rate=50)),
                         (Decimal('.03'), Decimal('.02')))
        self.assertIsNone(commission_values(dict(montant=100, commission_rate=None, aleo_rate=None)))
        self.assertEqual(commission_values(dict(montant=100, commission_rate=0, aleo_rate=100)),
                         (Decimal('0'), Decimal('100')))

    def client(self, role='admin'):
        client = crm.app.test_client()
        with client.session_transaction() as session:
            session['user'] = dict(id=1, username='Alice', role=role)
            session['csrf_token'] = 'test'
        return client

    def test_configuration_is_admin_only_and_csrf_protected(self):
        self.assertEqual(self.client('commercial').get('/admin/commissions').status_code, 302)
        self.assertEqual(self.client().post('/admin/commissions').status_code, 403)
        with patch.object(crm, 'get_db') as db:
            response = self.client('commercial').post('/admin/commissions', data=dict(
                csrf_token='test', commercial_id=1, commission_rate=100, direct_commission_rate=100))
            self.assertEqual(response.status_code, 302)
            db.assert_not_called()

    def test_templates_hide_parameters_from_commercials(self):
        row = dict(id=1, date=date(2026, 11, 19), client_id=None, client_name='Test', commercial='Alice',
                   revenue_source='ade', initial_amount=1000, montant=650, supplier_rate=35,
                   commission_rate=Decimal('27.25'), direct_commission_rate=Decimal('42.75'),
                   commission_amount=Decimal('177.13'), aleo_amount=Decimal('472.87'))
        with crm.app.test_request_context('/'):
            for role in ['admin', 'commercial']:
                context = dict(current_user=dict(id=1, username='Alice', role=role), csrf_token='test', available_endpoints=[],
                               client=row, revenues=[], amount_text='', revenue_date='2026-11-19', error=None)
                html = crm.app.jinja_env.get_template('client_validation.html').render(**context)
                self.assertEqual('data-ade="27.25"' in html, role == 'admin')
                self.assertEqual('data-direct="42.75"' in html, role == 'admin')
                self.assertEqual('retenue de 35 %' in html, role == 'admin')
                self.assertEqual('revenue_preview.js' in html, role == 'admin')
                context.update(revenues=[row], year=2026, commercial='', total_ca=650,
                               total_commercial=177.13, total_aleo=472.87, pending=0)
                html = crm.app.jinja_env.get_template('commissions.html').render(**context)
                self.assertEqual('27.25 %' in html, role == 'admin')
                self.assertEqual('35 %' in html, role == 'admin')
                self.assertEqual('Configurer les taux' in html, role == 'admin')
                self.assertIn('177.13', html)

    def test_saves_only_future_rate(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        with patch.object(crm, 'get_db', return_value=conn), patch.object(crm, 'ensure_commissions_schema'):
            response = self.client().post('/admin/commissions', data=dict(
                csrf_token='test', commercial_id=7, commission_rate='35,50', direct_commission_rate='20'))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(cur.execute.call_args.args[1], (Decimal('35.50'), Decimal('20'), 7))
        self.assertNotIn('revenus', cur.execute.call_args.args[0])

    def test_commercial_cannot_view_another_commercial_commissions(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        cur.fetchall.return_value = []
        with patch.object(crm, 'get_db', return_value=conn), patch.object(crm, 'ensure_commissions_schema'), \
             patch.object(crm, 'render_template', return_value='commissions'):
            response = self.client('commercial').get('/commissions?commercial=Bob&year=2026')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(cur.execute.call_args.args[1], (2026, 'Alice'))


if __name__ == '__main__':
    unittest.main()
