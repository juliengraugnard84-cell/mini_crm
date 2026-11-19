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
from commission_statements import build_statement, payment_date, pdf_statement, xlsx_statement
from commissions import contract_details


class StatementTests(unittest.TestCase):
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
        return client

    def test_export_authorization_and_tampered_filter(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        cur.fetchall.return_value = [self.row()]
        with patch.object(crm, 'get_db', return_value=conn), patch.object(crm, 'ensure_commissions_schema'), \
             patch.object(crm, 'render_template', return_value='statement'):
            for fmt in ['', 'pdf', 'xlsx']:
                response = self.client().get('/commissions/releves?mode=billing&month=2027-01&commercial=Bob&format=' + fmt)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(cur.execute.call_args.args[1], ('Alice',))
            self.client('admin').get('/commissions/releves?mode=billing&month=2027-01')
            self.assertEqual(cur.execute.call_args.args[1], ())
        self.assertEqual(crm.app.test_client().get('/commissions/releves?format=pdf').status_code, 302)
        self.assertEqual(self.client('other').get('/commissions/releves?format=xlsx').status_code, 403)

    def test_bad_filters_and_contract_metadata(self):
        self.assertEqual(self.client().get('/commissions/releves?month=2026-13').status_code, 400)
        self.assertEqual(self.client().get('/commissions/releves?mode=other').status_code, 400)
        for form in [{}, dict(signed_on='2026-02-30', energy_type='gaz'), dict(signed_on='2026-11-19', energy_type='other')]:
            with self.assertRaises(ValueError):
                contract_details(form)


if __name__ == '__main__':
    unittest.main()
