import os
import unittest
from datetime import date, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

os.environ['LOCAL_MODE'] = '1'
import app as crm


class CommercialStatisticsTests(unittest.TestCase):
    def build(self, dossiers, revenues, commercial_id=None):
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value.fetchall.side_effect = [
            [dict(id=1, username='Alice'), dict(id=2, username='Bob')], dossiers, revenues]
        return crm.build_commercial_statistics(conn, commercial_id)

    def dossier(self, id=1, name='Signed', status='gagne', owner_id=1):
        return dict(id=id, name=name, status=status, owner_id=owner_id, siret='123',
                    created_at=datetime(2026, 1, 5))

    def revenue(self, id=1, client_id=1, dossier='Signed', montant=100.25, commercial='Alice'):
        return dict(id=id, client_id=client_id, dossier=dossier, montant=montant,
                    commercial=commercial, date=date(2026, 2, 6))

    def test_signed_details_sum_each_line_and_preserve_overall_totals(self):
        stat = self.build([self.dossier(), self.dossier(2, 'Lost', 'perdu')],
                          [self.revenue(), self.revenue(2, montant=50.5),
                           self.revenue(3, client_id=2, dossier='Lost', montant=20)])[0]
        self.assertAlmostEqual(stat['signed_ca'], 150.75)
        self.assertEqual(len(stat['signed_dossiers'][0]['revenues']), 2)
        self.assertEqual([d['name'] for d in stat['lost_dossiers']], ['Lost'])
        self.assertAlmostEqual(stat['career']['ca'], 170.75)
        self.assertEqual(len(stat['other_revenues']), 1)

    def test_legacy_name_links_only_when_unambiguous_across_statuses(self):
        revenue = self.revenue(client_id=None)
        stat = self.build([self.dossier()], [revenue])[0]
        self.assertEqual(stat['signed_ca'], 100.25)
        stat = self.build([self.dossier(), self.dossier(2, 'Signed', 'perdu')], [revenue])[0]
        self.assertEqual(stat['signed_ca'], 0)
        self.assertEqual(len(stat['other_revenues']), 1)

    def test_client_id_is_authoritative_even_with_a_different_label(self):
        stat = self.build([self.dossier()], [self.revenue(dossier='Another label')])[0]
        self.assertEqual(stat['signed_ca'], 100.25)

    def test_personal_statistics_do_not_include_other_commercial_dossiers(self):
        dossiers = [self.dossier(), self.dossier(2, 'Bob signed', owner_id=2)]
        revenues = [self.revenue(), self.revenue(2, client_id=2, commercial='Bob')]
        stats = self.build(dossiers, revenues, commercial_id=1)
        self.assertEqual(len(stats), 1)
        self.assertEqual([d['id'] for d in stats[0]['signed_dossiers']], [1])
        self.assertEqual(stats[0]['career']['ca'], 100.25)

    def test_signed_without_revenue_and_open_statuses(self):
        stat = self.build([self.dossier(), self.dossier(2, 'Open', 'en_cours'),
                           self.dossier(3, 'Pending', 'en_attente')], [])[0]
        self.assertEqual(len(stat['signed_dossiers']), 1)
        self.assertEqual(stat['signed_ca'], 0)
        self.assertEqual(stat['lost_dossiers'], [])

    def test_statistics_template_renders_both_lists_and_cents(self):
        stats = self.build([self.dossier(), self.dossier(2, 'Lost dossier', 'perdu')], [self.revenue()])
        with crm.app.test_request_context('/mes-statistiques'):
            html = crm.app.jinja_env.get_template('admin_commercial_statistics.html').render(
                commercial_statistics=stats[:1], personal_view=True, individual_view=True,
                current_user=SimpleNamespace(id=1, role='commercial', username='Alice'),
                csrf_token='token', available_endpoints=[])
        self.assertIn('Dossiers signés / gagnés — 1', html)
        self.assertIn('Dossiers perdus — 1', html)
        self.assertIn('100,25 EUR', html)
        self.assertIn('06/02/2026', html)
        self.assertIn('Lost dossier', html)


if __name__ == '__main__':
    unittest.main()
