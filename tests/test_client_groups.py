import os
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

os.environ['LOCAL_MODE'] = '1'
import app as crm
from client_groups import build_group_summaries, attach_client_group, suggested_common_name


class ClientGroupTests(unittest.TestCase):
    def clients(self):
        return [dict(id=1, client_group_id=10, common_name='Foncia', name='Foncia Paris',
                     siret='123', commercial='Alice', owner_id=1, address='Paris',
                     gerant_nom='Paul', status='en_cours'),
                dict(id=2, client_group_id=10, common_name='Foncia', name='Foncia Lyon',
                     siret='123', commercial='Bob', owner_id=2, address='Lyon',
                     gerant_nom='Marie', status='gagne')]

    def quotations(self):
        return [dict(id=1, client_id=1, energie_type='electricite', pdl_pce='001234', pce=None),
                dict(id=2, client_id=2, energie_type='elec_gaz', pdl_pce='005678', pce='009876'),
                dict(id=3, client_id=2, energie_type='gaz', pdl_pce=None, pce='009876')]

    def test_common_brand_names_are_preserved(self):
        self.assertEqual(suggested_common_name('FONCIA - Paris'), 'Foncia')
        self.assertEqual(suggested_common_name('Cythia Lyon'), 'Cythia')
        self.assertEqual(suggested_common_name('Fonciation SAS'), 'Fonciation SAS')

    def test_count_dossiers_once_and_separate_energies(self):
        group = build_group_summaries(self.clients(), self.quotations(), [])[0]
        self.assertEqual(group['name'], 'Foncia')
        self.assertEqual(group['total'], 2)
        self.assertEqual(len(group['electricite']), 2)
        self.assertEqual(len(group['gaz']), 1)
        self.assertEqual(group['commercials'], ['Alice', 'Bob'])
        self.assertEqual(group['sirets'], ['123'])
        self.assertEqual(len(group['gaz'][0]['points']['gaz']), 1)

    def test_multisite_metadata_overrides_legacy_copy(self):
        points = [dict(cotation_id=1, energy_type='electricite', reference_code='001234',
                       site_label='Site principal', address='12 rue de Paris')]
        group = build_group_summaries(self.clients(), self.quotations(), points)[0]
        point = group['electricite'][0]['points']['electricite'][0]
        self.assertEqual(point['address'], '12 rue de Paris')
        self.assertEqual(point['site'], 'Site principal')

    def test_unknown_energy_and_lost_dossiers_remain_in_memory(self):
        clients = self.clients()
        clients[1]['status'] = 'perdu'
        group = build_group_summaries(clients, [], [])[0]
        self.assertEqual(group['total'], 2)
        self.assertEqual(len(group['sans_energie']), 2)
        self.assertEqual(group['electricite'], [])

    def test_same_siret_reuses_group_without_overwriting_common_name(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = dict(client_group_id=10)
        group_id = attach_client_group(conn, 4, 'Different name', '123 456', 'New label')
        self.assertEqual(group_id, 10)
        self.assertEqual(cur.execute.call_args.args[1], (10, 4))
        self.assertFalse(any('INSERT INTO crm_client_groups' in call.args[0] for call in cur.execute.call_args_list))
        self.assertEqual(cur.execute.call_args_list[1].args[1], (4, '123456'))

    def test_empty_siret_does_not_group_unrelated_clients(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = {'id': 12}
        attach_client_group(conn, 4, 'Other client', '')
        insert = next(call for call in cur.execute.call_args_list if 'INSERT INTO crm_client_groups' in call.args[0])
        self.assertEqual(insert.args[1], ('Other client', 'client:4'))

    def test_plain_brand_and_extended_brand_share_key(self):
        for name in ['Foncia', 'Foncia - Paris']:
            with self.subTest(name=name):
                conn = MagicMock()
                cur = conn.cursor.return_value.__enter__.return_value
                cur.fetchone.side_effect = [None, {'id': 10}]
                attach_client_group(conn, 1, name, '123')
                insert = next(call for call in cur.execute.call_args_list if 'INSERT INTO crm_client_groups' in call.args[0])
                self.assertEqual(insert.args[1], ('Foncia', 'name:foncia'))

    def test_group_route_keeps_commercial_ownership_filter(self):
        client = crm.app.test_client()
        with client.session_transaction() as session:
            session['user'] = dict(id=1, username='Alice', role='commercial')
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        cur.fetchall.return_value = []
        with patch.object(crm, 'get_db', return_value=conn), \
             patch.object(crm, 'ensure_client_groups_schema'), \
             patch.object(crm, 'ensure_cotation_schema'), \
             patch.object(crm, 'ensure_cotation_delivery_points_schema'):
            response = client.get('/clients/groupes/10')
        self.assertEqual(response.status_code, 404)
        self.assertIn('AND c.owner_id = %s', cur.execute.call_args.args[0])
        self.assertEqual(cur.execute.call_args.args[1], (10, 1))

    def test_group_pages_render_counts_energies_and_commercials(self):
        group = build_group_summaries(self.clients(), self.quotations(), [])[0]
        with crm.app.test_request_context('/clients/groupes/10'):
            html = crm.app.jinja_env.get_template('client_group_detail.html').render(group=group,
                current_user=SimpleNamespace(id=9, username='Admin', role='admin'),
                csrf_token='token', available_endpoints=[])
            self.assertIn('2 dossier(s) en mémoire', html)
            self.assertIn('Alice, Bob', html)
            self.assertIn('Électricité — 2', html)
            self.assertIn('Gaz — 1', html)
            self.assertIn('009876', html)
            html = crm.app.jinja_env.get_template('clients.html').render(client_groups=[group],
                current_user=SimpleNamespace(id=9, username='Admin', role='admin'),
                csrf_token='token', available_endpoints=[], users=[], clients_en_cours=[],
                clients_en_attente=[], clients_gagnes=[], clients_perdus=[])
            self.assertIn('Électricité : 2', html)
            self.assertIn('Alice, Bob', html)


if __name__ == '__main__':
    unittest.main()
