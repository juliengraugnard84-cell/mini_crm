import os
import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

os.environ['LOCAL_MODE'] = '1'
import app as crm


class CommonDossiersTests(unittest.TestCase):
    def client(self, role='admin', user_id=1):
        client = crm.app.test_client()
        with client.session_transaction() as session:
            session['user'] = dict(id=user_id, username='Admin', role=role)
            session['csrf_token'] = 'token'
        return client

    def test_departure_preserves_history_and_is_atomic(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = dict(id=2, username='Alice', role='commercial')
        with ExitStack() as stack:
            stack.enter_context(patch.object(crm, 'get_db', return_value=conn))
            stack.enter_context(patch.object(crm, 'session_user_is_active', return_value=True))
            for schema in ('ensure_hot_followups_schema', 'ensure_planning_schema', 'ensure_cspe_schema'):
                stack.enter_context(patch.object(crm, schema))
            response = self.client().post('/admin/users/2/delete', data={'csrf_token': 'token'})
            self.assertEqual(response.status_code, 302)
            sql = '\n'.join(call.args[0] for call in cur.execute.call_args_list)
            self.assertIn("UPDATE users SET role = 'inactive'", sql)
            self.assertIn("SET visibility = 'admin'", sql)
            self.assertNotIn('DELETE', sql)
            self.assertNotIn('UPDATE crm_clients', sql)  # Preserve historical ownership.
            conn.commit.assert_called_once()
            conn.reset_mock()
            conn.commit.side_effect = RuntimeError('commit failed')
            with self.assertLogs(crm.logger, level='ERROR'):
                self.client().post('/admin/users/2/delete', data={'csrf_token': 'token'})
            conn.rollback.assert_called_once()

    def test_common_is_admin_only_and_includes_previous_orphans(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        row = dict(id=12, name='Dossier conservé', former_commercial='Alice', status='perdu', created_at=None)
        cur.fetchall.side_effect = [[row], []]
        with patch.object(crm, 'session_user_is_active', return_value=True), \
             patch.object(crm, 'get_db', return_value=conn), \
             patch.object(crm, 'render_template', return_value='Commun') as render:
            self.assertEqual(self.client().get('/admin/dossiers-communs').status_code, 200)
            self.assertEqual(render.call_args.kwargs['dossiers'], [row])
            for call in cur.execute.call_args_list:
                self.assertIn('c.owner_id IS NULL OR u.id IS NULL', call.args[0])
                self.assertIn("u.role = 'inactive'", call.args[0])
            conn.reset_mock()
            self.assertEqual(self.client('commercial', 2).get('/admin/dossiers-communs').status_code, 302)
            conn.cursor.assert_not_called()
            self.assertEqual(self.client('commercial', 2).post('/admin/users/3/delete', data={'csrf_token': 'token'}).status_code, 302)
            self.assertEqual(self.client().post('/admin/users/3/delete').status_code, 403)
            conn.cursor.assert_not_called()

    def test_closed_and_deleted_accounts_lose_existing_sessions(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = None  # Account no longer active, or deleted.
        with patch.object(crm, 'get_db', return_value=conn):
            client = self.client('commercial', 2)
            response = client.get('/clients/12')
            self.assertEqual(response.status_code, 302)
            self.assertTrue(response.location.endswith('/login'))
            self.assertIn("role <> 'inactive'", cur.execute.call_args.args[0])
            with client.session_transaction() as session:
                self.assertNotIn('user', session)
            cur.fetchone.return_value = {'id': 2}
            self.assertTrue(crm.session_user_is_active(2))

    def test_inactive_account_cannot_log_in(self):
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value.fetchone.return_value = dict(
            id=2, username='Alice', role='inactive', password_hash='unused')
        client = crm.app.test_client()
        with client.session_transaction() as session:
            session['csrf_token'] = 'token'
        with patch.object(crm, 'get_db', return_value=conn), \
             patch.object(crm, 'render_template', return_value='Login'), \
             patch.object(crm, 'check_password_hash', return_value=True) as check:
            client.post('/login', data=dict(username='Alice', password='password', csrf_token='token'))
            check.assert_not_called()
            with client.session_transaction() as session:
                self.assertNotIn('user', session)

    def test_private_followups_and_document_access(self):
        event = dict(created_by=2, assigned_to=2, visibility='admin')
        for role in ('commercial', 'other'):
            user = dict(id=2, role=role)
            self.assertFalse(crm.planning_event_can_view(event, user))
            self.assertFalse(crm.planning_event_can_edit(event, user))
        self.assertTrue(crm.planning_event_can_view(event, dict(id=1, role='admin')))
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value.fetchone.return_value = {'owner_id': 3}
        with crm.app.test_request_context(), patch.object(crm, 'get_db', return_value=conn):
            crm.session['user'] = dict(id=2, role='commercial')
            self.assertFalse(crm.can_access_client(12))
            self.assertFalse(crm.can_access_document_key('clients/12/facture.pdf'))

    def test_navigation_and_common_page(self):
        from types import SimpleNamespace
        with crm.app.test_request_context('/admin/dossiers-communs'):
            template = crm.app.jinja_env.get_template('navigation.html')
            for role, expected in [('admin', True), ('commercial', False)]:
                html = template.render(current_user=SimpleNamespace(role=role), available_endpoints=[])
                self.assertEqual('/admin/dossiers-communs' in html, expected)
            html = crm.app.jinja_env.get_template('admin_common_dossiers.html').render(
                dossiers=[dict(id=12, name='Dossier conservé', former_commercial='Alice', status='perdu')],
                cspe_dossiers=[], format_date=lambda value: '', current_user=None, available_endpoints=[])
            self.assertIn('Dossier conservé', html)
            self.assertIn('Alice', html)
            self.assertIn('/clients/12', html)

    def test_admin_can_reassign_a_common_dossier(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        cur.fetchone.side_effect = [dict(id=12, owner_id=2, commercial='Alice', status='perdu'),
                                   dict(id=3, username='Bob')]
        with ExitStack() as stack:
            stack.enter_context(patch.object(crm, 'get_db', return_value=conn))
            stack.enter_context(patch.object(crm, 'session_user_is_active', return_value=True))
            stack.enter_context(patch.object(crm, 'record_dossier_duplicates', return_value=None))
            for helper in ('ensure_client_groups_schema', 'attach_client_group'):
                stack.enter_context(patch.object(crm, helper))
            response = self.client().post('/clients/12/edit', data=dict(
                csrf_token='token', name='Dossier conservé', status='perdu', owner_id='3',
                notes='Notes conservées'))
            self.assertEqual(response.status_code, 302)
            update = next(call for call in cur.execute.call_args_list if 'UPDATE crm_clients' in call.args[0])
            self.assertEqual(update.args[1][4], 'Bob')
            self.assertEqual(update.args[1][7], 3)
            self.assertEqual(update.args[1][6], 'Notes conservées')
            self.assertIn("AND role = 'commercial'", cur.execute.call_args_list[-2].args[0])
            conn.commit.assert_called_once()


if __name__ == '__main__':
    unittest.main()
