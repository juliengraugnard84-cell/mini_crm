import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import local_crm
import open_local_crm


class LocalCrmTests(unittest.TestCase):
    def test_local_credentials_survive_restarts(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(local_crm, 'STATE', Path(directory)):
            first = local_crm.load_config()
            self.assertEqual(first, local_crm.load_config())
            self.assertGreaterEqual(len(first['admin_password']), 18)

    def test_local_mode_overrides_inherited_render_settings(self):
        config = dict(db_user='local', db_password='password', db_name='local', db_port=55432,
                      web_port=5055, secret_key='local-secret', admin_password='local-password')
        with patch.dict(local_crm.os.environ, dict(ENV='production', DATABASE_URL='postgresql://remote/db')):
            local_crm.configure_environment(config)
            self.assertIn('@127.0.0.1:55432/', local_crm.os.environ['DATABASE_URL'])
            self.assertEqual(local_crm.os.environ['ENV'], 'development')
            self.assertEqual(local_crm.os.environ['EMAIL_NOTIFICATIONS_ENABLED'], '0')

    def test_backup_contains_database_and_documents_but_not_passwords(self):
        def fake_dump(binary, args, config, **kwargs):
            Path(args[-1]).write_bytes(b'database dump')
        with tempfile.TemporaryDirectory() as directory, patch.object(local_crm, 'STATE', Path(directory)), \
             patch.object(local_crm, 'run_pg', side_effect=fake_dump):
            document = Path(directory) / 'documents' / 'clients' / '42' / 'facture.pdf'
            document.parent.mkdir(parents=True)
            document.write_bytes(b'invoice')
            config = dict(db_port=55432, db_user='local', db_name='local', db_password='secret')
            archive = local_crm.backup(config)
            with zipfile.ZipFile(archive) as output:
                self.assertEqual(output.read('database.dump'), b'database dump')
                self.assertEqual(output.read('documents/clients/42/facture.pdf'), b'invoice')
                self.assertNotIn('settings.json', output.namelist())

    def test_desktop_launcher_reuses_running_server(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(open_local_crm, 'STATE', Path(directory)), \
             patch.object(open_local_crm, 'is_ready', return_value=True), \
             patch.object(open_local_crm.subprocess, 'Popen') as spawn, \
             patch.object(open_local_crm.webbrowser, 'open') as browser:
            open_local_crm.main()
            spawn.assert_not_called()
            browser.assert_called_once_with('http://127.0.0.1:5055')
