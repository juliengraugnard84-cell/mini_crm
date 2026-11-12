import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import time

import app as crm
from crm_sync import choose, json_value
from document_sync import signature, sync_files


class SyncRulesTests(unittest.TestCase):
    def test_first_transfer_copies_only_missing_rows(self):
        self.assertEqual(choose({'montant': 12.5}, None, None), {'montant': 12.5})
        self.assertEqual(choose(None, {'montant': 12.5}, None), {'montant': 12.5})

    def test_one_sided_change_and_retry_are_safe(self):
        self.assertEqual(choose({'v': 2}, {'v': 1}, {'v': 1}), {'v': 2})
        self.assertEqual(choose({'v': 1}, {'v': 2}, {'v': 1}), {'v': 2})
        self.assertEqual(choose({'v': 2}, {'v': 2}, {'v': 1}), {'v': 2})

    def test_concurrent_changes_require_a_decision(self):
        with self.assertRaises(ValueError):
            choose({'v': 2}, {'v': 3}, {'v': 1})
        self.assertEqual(choose({'v': 2}, {'v': 3}, {'v': 1}, 'render'), {'v': 3})

    def test_deletions_are_never_automatically_propagated(self):
        with self.assertRaises(ValueError):
            choose(None, {'v': 1}, {'v': 1})
        self.assertEqual(choose(None, {'v': 1}, {'v': 1}, 'render'), {'v': 1})

    def test_signature_binds_content_and_metadata(self):
        base = signature('secret', '100', 'POST', {'action': 'put', 'uuid': 'one'}, b'file')
        self.assertNotEqual(base, signature('secret', '100', 'POST', {'action': 'put', 'uuid': 'two'}, b'file'))
        self.assertNotEqual(base, signature('secret', '100', 'POST', {'action': 'put', 'uuid': 'one'}, b'other'))

    def test_document_api_rejects_unsigned_and_expired_requests(self):
        client = crm.app.test_client()
        with patch.object(crm, 'LOCAL_MODE', False), patch.object(crm, 'DATABASE_URL', 'postgresql://u:secret@remote/db'):
            self.assertEqual(client.get('/api/local-sync/documents?action=status').status_code, 403)
            params = {'action': 'status'}
            response = client.get('/api/local-sync/documents', query_string=params, headers={
                'X-CRM-Sync-Time': '1', 'X-CRM-Sync-Signature': signature('secret', '1', 'GET', params, b'')})
            self.assertEqual(response.status_code, 403)

    def test_document_api_accepts_valid_signed_status_without_exposing_credentials(self):
        stamp = str(int(time.time()))
        params = {'action': 'status'}
        with patch.object(crm, 'LOCAL_MODE', False), patch.object(crm, 'DATABASE_URL', 'postgresql://u:secret@remote/db'):
            response = crm.app.test_client().get('/api/local-sync/documents', query_string=params, headers={
                'X-CRM-Sync-Time': stamp, 'X-CRM-Sync-Signature': signature('secret', stamp, 'GET', params, b'')})
        self.assertEqual(response.json, {'version': 1})

    def test_documents_are_content_deduplicated_and_ids_are_remapped(self):
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value.fetchall.side_effect = [[(42, 'client-uuid')], []]
        bridge = MagicMock()
        remote_content = b'remote-pdf'
        def call(params, body=b''):
            response = MagicMock()
            if params['action'] == 'list':
                response.json.return_value = {'files': [dict(entity='crm_clients', uuid='client-uuid',
                    key='clients/old_9/remote.pdf', name='remote.pdf')]}
            if params['action'] == 'get':
                response.content = remote_content
            return response
        bridge.call.side_effect = call
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'clients' / 'example_42' / 'new.pdf'
            path.parent.mkdir(parents=True)
            path.write_bytes(b'new-local-pdf')
            result = sync_files(conn, directory, bridge)
            self.assertEqual(result, dict(documents_envoyes=1, documents_recus=1))
            downloaded = list((Path(directory) / 'clients' / 'sync_42').glob('*'))
            self.assertEqual(downloaded[0].read_bytes(), remote_content)
            puts = [call for call in bridge.call.call_args_list if call.args[0]['action'] == 'put']
            self.assertEqual(puts[0].args[0]['uuid'], 'client-uuid')
            self.assertEqual(puts[0].args[1], b'new-local-pdf')

    def test_signed_document_upload_is_idempotent_and_checks_body(self):
        conn, storage = MagicMock(), MagicMock()
        conn.cursor.return_value.__enter__.return_value.fetchall.side_effect = [[(9, 'test-uuid')], [], [(9, 'test-uuid')], []]
        params = dict(action='put', entity='crm_clients', uuid='test-uuid', name='invoice.pdf')
        body = b'%PDF original'
        stamp = str(int(time.time()))
        headers = {'X-CRM-Sync-Time': stamp,
                   'X-CRM-Sync-Signature': signature('secret', stamp, 'POST', params, body),
                   'Content-Type': 'application/octet-stream'}
        with patch.object(crm, 'LOCAL_MODE', False), patch.object(crm, 'DATABASE_URL', 'postgresql://u:secret@remote/db'), \
             patch.object(crm, 's3', storage), patch.object(crm, 'AWS_BUCKET', 'test-bucket'), \
             patch.object(crm, 'get_db', return_value=conn), \
             patch.object(crm, 'client_s3_prefix', return_value='clients/client_9/'):
            client = crm.app.test_client()
            first = client.post('/api/local-sync/documents', query_string=params, data=body, headers=headers)
            second = client.post('/api/local-sync/documents', query_string=params, data=body, headers=headers)
            tampered = client.post('/api/local-sync/documents', query_string=params, data=b'changed', headers=headers)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.json['key'], first.json['key'])
        self.assertEqual(tampered.status_code, 403)
        self.assertEqual(storage.put_object.call_count, 2)
        self.assertEqual(storage.put_object.call_args.kwargs['Body'], body)
