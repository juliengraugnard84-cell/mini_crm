import os
import unittest
from datetime import date
from decimal import Decimal
from io import BytesIO
from zipfile import ZipFile
from xml.etree import ElementTree as ET
from unittest.mock import MagicMock, patch

os.environ['LOCAL_MODE'] = '1'
import app as crm
from commission_statements import build_statement, payment_date, pdf_statement, xlsx_statement, parse_payment
from commissions import contract_details


class StatementTests(unittest.TestCase):
    def setUp(self):
        active_session = patch.object(crm, 'session_user_is_active', return_value=True)
        active_session.start()
        self.addCleanup(active_session.stop)

    def row(self, **changes):
        row = dict(id=1, commercial='Alice', signed_on=date(2026, 11, 30), montant=650,
                   initial_amount=1000, commission_rate=30, aleo_rate=70, revenue_source='ade',
                   supplier_name='Fournisseur signé', energy_type='gaz', dossier='Dossier test')
        row.update(changes)
        return row

    def test_calendar_months_and_year_boundary(self):
        for signed, expected in [(date(2026, 11, 30), date(2027, 1, 1)),
                                 (date(2026, 12, 1), date(2027, 2, 1)),
                                 (date(2028, 2, 29), date(2028, 4, 1))]:
            self.assertEqual(payment_date(signed), expected)

    def test_signature_month_differs_from_billing_month(self):
        for mode, month, count in [('monthly', '2026-11', 1), ('billing', '2026-11', 0),
                                   ('billing', '2027-01', 1), ('billing', '2027-02', 0)]:
            statement = build_statement([self.row()], mode, month, 'Alice')
            self.assertEqual(len(statement['groups']), count)
            if count:
                self.assertEqual(statement['total'], Decimal('195'))

    def test_missing_signature_and_rates_are_not_invented(self):
        rows = [self.row(signed_on=None), self.row(id=2, commission_rate=None)]
        monthly = build_statement(rows, 'monthly', '2026-11', 'Alice')
        billing = build_statement(rows, 'billing', '2027-01', 'Alice')
        self.assertEqual(monthly['missing_signature'], 1)
        self.assertIsNone(monthly['groups'][0]['rows'][0]['commission'])
        self.assertEqual(billing['groups'], [])
        self.assertEqual(billing['pending'], 1)

    def test_grouping_totals_and_no_rates_in_export_model(self):
        statement = build_statement([self.row(), self.row(id=2, commercial='Bob')], 'billing', '2027-01', 'Tous')
        self.assertEqual(statement['total'], Decimal('390'))
        self.assertEqual(len(statement['groups']), 2)
        self.assertNotIn('commission_rate', statement['groups'][0]['rows'][0])

    def test_exports_have_numeric_amounts_and_no_formula_injection(self):
        statement = build_statement([self.row(dossier='=HYPERLINK("evil")')], 'monthly', '2026-11', 'Alice')
        self.assertTrue(pdf_statement(statement).getvalue().startswith(b'%PDF'))
        with ZipFile(xlsx_statement(statement)) as archive:
            sheet = ET.fromstring(archive.read('xl/worksheets/sheet1.xml'))
            ns = {'s': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
            self.assertEqual(sheet.findall('.//s:f', ns), [])
            self.assertIn('195.00', [v.text for v in sheet.findall('.//s:v', ns)])
            for path in archive.namelist():
                if path.endswith(('.xml', '.rels')):
                    ET.fromstring(archive.read(path))

    def client(self, role='commercial'):
        client = crm.app.test_client()
        with client.session_transaction() as session:
            session['user'] = dict(id=1, username='Alice', role=role)
            session['csrf_token'] = 'test'
        return client

    def test_multiple_months_and_payment_totals(self):
        rows = [self.row(payment_status='paid', invoiced_on=date(2026, 11, 1), paid_on=date(2026, 11, 2)),
                self.row(id=2, signed_on=date(2026, 12, 1), payment_status='invoiced'),
                self.row(id=3, signed_on=date(2027, 1, 1))]
        for mode, start, end in [('monthly', '2026-11', '2026-12'), ('billing', '2027-01', '2027-02')]:
            statement = build_statement(rows, mode, start, 'Tous', end)
            self.assertEqual(statement['total'], Decimal('390'))
            self.assertEqual(statement['paid'], Decimal('195'))
            self.assertEqual(statement['outstanding'], Decimal('195'))
        for end in ['2026-10', '2026-13', '202612']:
            with self.assertRaises(ValueError):
                build_statement(rows, 'monthly', '2026-11', 'Tous', end)

    def test_payment_date_validation(self):
        self.assertEqual(parse_payment(dict(payment_status='to_invoice')), ('to_invoice', None, None))
        self.assertEqual(parse_payment(dict(payment_status='paid', invoiced_on='2020-01-01', paid_on='2020-01-02')),
                         ('paid', date(2020, 1, 1), date(2020, 1, 2)))
        for form in [dict(payment_status='invalid'), dict(payment_status='invoiced'),
                     dict(payment_status='paid', invoiced_on='2020-01-01'),
                     dict(payment_status='paid', invoiced_on='2020-01-02', paid_on='2020-01-01'),
                     dict(payment_status='to_invoice', invoiced_on='2020-01-01'),
                     dict(payment_status='invoiced', invoiced_on='9999-01-01'),
                     dict(payment_status='invoiced', invoiced_on='2020-02-30')]:
            with self.assertRaises(ValueError):
                parse_payment(form)

    def test_live_summary_refresh_and_access_scope(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        with patch.object(crm, 'get_db', return_value=conn), patch.object(crm, 'ensure_commissions_schema'):
            client = self.client()
            cur.fetchall.return_value = [self.row()]
            url = '/commissions/releves?month=2026-11&end_month=2026-12&commercial=Bob&format=json'
            response = client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(cur.execute.call_args.args[1], ('Alice',))
            self.assertEqual(response.json['net_total'], '650')
            self.assertEqual(response.json['total'], '195.00')
            self.assertEqual(response.headers['Cache-Control'], 'private, no-store')
            self.assertNotIn('aleo_rate', response.json)
            cur.fetchall.return_value = [self.row(), self.row(id=2, signed_on=date(2026, 12, 1))]
            self.assertEqual(client.get(url).json['total'], '390.00')
            self.client('admin').get(url + '&commercial=Alice')
            self.assertEqual(cur.execute.call_args.args[1], ('Bob', 'Alice'))
        self.assertEqual(self.client('other').get(url).status_code, 403)
        self.assertEqual(crm.app.test_client().get(url).status_code, 302)

    def test_ca_includes_dossiers_with_uncomputed_commissions(self):
        statement = build_statement([self.row(), self.row(id=2, commission_rate=None, initial_amount=None)],
                                    'billing', '2027-01', 'Tous')
        self.assertEqual(statement['net_total'], Decimal('1300'))
        self.assertEqual(statement['gross_total'], Decimal('1000'))
        self.assertEqual(statement['total'], Decimal('195'))
        self.assertEqual(statement['period_rows'], 2)
        self.assertEqual(statement['missing_gross_count'], 1)
        self.assertEqual(statement['pending'], 1)

    def test_statement_templates_show_admin_controls_only_to_admin(self):
        statement = build_statement([self.row()], 'monthly', '2026-11', 'Alice', '2026-12')
        with crm.app.test_request_context():
            for role in ['admin', 'commercial']:
                context = dict(statement=statement, notes=[], current_user=dict(id=1, role=role, username='Alice'),
                               commercial=['Alice'], selected_commercials=['Alice'], commercial_options=['Alice', 'Bob'],
                               csrf_token='test', available_endpoints=[])
                html = crm.app.jinja_env.get_template('commission_statements.html').render(**context)
                self.assertEqual('Modifier le suivi' in html, role == 'admin')
                self.assertEqual('Tout sélectionner' in html, role == 'admin')
                self.assertIn('format=json', html)
                self.assertIn('end_month=2026-12', html)
                warning = crm.app.jinja_env.get_template('statement_export_warning.html').render(export='pdf', **context)
                self.assertIn('acknowledge=1', warning)

    def test_payment_update_is_admin_only_and_csrf_protected(self):
        url = '/admin/commissions/revenus/1/reglement'
        data = dict(csrf_token='test', payment_status='paid', invoiced_on='2020-01-01', paid_on='2020-01-02',
                    month='2026-11', end_month='2026-12', commercial=['Alice', 'Bob'])
        conn = MagicMock()
        with patch.object(crm, 'get_db', return_value=conn), patch.object(crm, 'ensure_commissions_schema'):
            self.assertEqual(self.client('admin').post(url, data={}).status_code, 403)
            response = self.client().post(url, data=data)
            self.assertIn(response.status_code, (302, 403))
            conn.cursor.assert_not_called()
            response = self.client('admin').post(url, data=data)
            self.assertEqual(response.status_code, 302)
            self.assertIn('end_month=2026-12', response.location)
            self.assertIn('commercial=Alice&commercial=Bob', response.location)
            cur = conn.cursor.return_value.__enter__.return_value
            self.assertEqual(cur.execute.call_args.args[1], ('paid', date(2020, 1, 1), date(2020, 1, 2), 1))
            conn.commit.assert_called_once()
            conn.reset_mock()
            self.client('admin').post(url, data=dict(csrf_token='test', payment_status='paid'))
            conn.cursor.assert_not_called()

    def test_export_requires_acknowledgement_for_missing_data(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        cur.fetchall.return_value = [self.row(supplier_name=None), self.row(id=2, signed_on=None)]
        with patch.object(crm, 'get_db', return_value=conn), patch.object(crm, 'ensure_commissions_schema'), \
             patch.object(crm, 'render_template', return_value='warning') as render:
            url = '/commissions/releves?month=2026-11&end_month=2026-12&format=pdf'
            response = self.client('admin').get(url)
            self.assertEqual(response.data, b'warning')
            self.assertEqual(render.call_args.args[0], 'statement_export_warning.html')
            self.assertEqual(render.call_args.kwargs['statement']['missing_signature'], 1)
            response = self.client('admin').get(url + '&acknowledge=1')
            self.assertTrue(response.data.startswith(b'%PDF'))
            self.assertIn('2026-11-2026-12.pdf', response.headers['Content-Disposition'])

    def test_export_authorization_and_tampered_filter(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        cur.fetchall.return_value = [self.row()]
        with patch.object(crm, 'get_db', return_value=conn), patch.object(crm, 'ensure_commissions_schema'), \
             patch.object(crm, 'render_template', return_value='statement'):
            for fmt in ['', 'pdf', 'xlsx']:
                response = self.client().get('/commissions/releves?mode=billing&month=2027-01&commercial=Bob&commercial=Charlie&format=' + fmt)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(cur.execute.call_args.args[1], ('Alice',))
            cur.fetchall.side_effect = [[{'name': 'Alice'}], [self.row()]]
            self.client('admin').get('/commissions/releves?mode=billing&month=2027-01')
            self.assertEqual(cur.execute.call_args.args[1], ())
        self.assertEqual(crm.app.test_client().get('/commissions/releves?format=pdf').status_code, 302)
        self.assertEqual(self.client('other').get('/commissions/releves?format=xlsx').status_code, 403)

    def test_admin_multiple_selection_and_export(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        rows = [self.row(), self.row(id=2, commercial='Bob')]
        with patch.object(crm, 'get_db', return_value=conn), patch.object(crm, 'ensure_commissions_schema'), \
             patch.object(crm, 'render_template', return_value='statement') as render:
            cur.fetchall.side_effect = [[{'name': 'Alice'}, {'name': 'Bob'}], rows]
            response = self.client('admin').get('/commissions/releves?month=2026-11&commercial=Alice&commercial=Bob&commercial=Alice')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(cur.execute.call_args.args[1], ('Alice', 'Bob'))
            self.assertIn('IN (%s, %s)', cur.execute.call_args.args[0])
            self.assertEqual(render.call_args.kwargs['selected_commercials'], ['Alice', 'Bob'])
            self.assertEqual(render.call_args.kwargs['statement']['total'], Decimal('390'))
            cur.fetchall.side_effect = None
            cur.fetchall.return_value = rows
            for query, expected in [('commercial=Alice&commercial=Bob', ('Alice', 'Bob')), ('', ())]:
                response = self.client('admin').get('/commissions/releves?month=2026-11&format=pdf&' + query)
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.data.startswith(b'%PDF'))
                self.assertEqual(cur.execute.call_args.args[1], expected)

    def test_export_links_preserve_multiple_commercials(self):
        with crm.app.test_request_context():
            link = crm.url_for('commission_statements', commercial=['Alice', 'Bob'], format='pdf')
            self.assertIn('commercial=Alice&commercial=Bob', link)

    def test_bad_filters_and_contract_metadata(self):
        self.assertEqual(self.client().get('/commissions/releves?month=2026-13').status_code, 400)
        self.assertEqual(self.client().get('/commissions/releves?mode=other').status_code, 400)
        for form in [{}, dict(signed_on='2026-02-30', energy_type='gaz'), dict(signed_on='2026-11-19', energy_type='other')]:
            with self.assertRaises(ValueError):
                contract_details(form)


if __name__ == '__main__':
    unittest.main()
