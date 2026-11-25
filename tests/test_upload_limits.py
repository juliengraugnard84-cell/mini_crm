import io
import os
import unittest
from unittest.mock import patch

os.environ['LOCAL_MODE'] = '1'
import app as crm


class UploadLimitTests(unittest.TestCase):
    def setUp(self):
        active_session = patch.object(crm, 'session_user_is_active', return_value=True)
        active_session.start()
        self.addCleanup(active_session.stop)
        self.client = crm.app.test_client()
        with self.client.session_transaction() as session:
            session['user'] = dict(id=7, username='Test', role='commercial')
            session['csrf_token'] = 'test'

    def upload(self, size, headers=None):
        return self.client.post('/clients/42/documents/upload', data={
            'csrf_token': 'test',
            'files': (io.BytesIO(b'x' * size), 'document.pdf'),
        }, headers=headers or {})

    def test_larger_than_old_limit_reaches_access_check(self):
        with patch.dict(crm.app.config, MAX_CONTENT_LENGTH=50 * 1024 * 1024), \
                patch.object(crm, 'can_access_client', return_value=False) as access:
            response = self.upload(11 * 1024 * 1024)
        self.assertEqual(response.status_code, 403)
        access.assert_called_once_with(42)

    def test_oversized_form_returns_french_message_before_access(self):
        with patch.dict(crm.app.config, MAX_CONTENT_LENGTH=1024 * 1024), \
                patch.object(crm, 'can_access_client') as access:
            response = self.upload(1024 * 1024)
        self.assertEqual(response.status_code, 413)
        self.assertIn('limite de 1 Mo', response.get_data(as_text=True))
        access.assert_not_called()

    def test_oversized_ajax_returns_json(self):
        with patch.dict(crm.app.config, MAX_CONTENT_LENGTH=1024):
            response = self.upload(2048, {'Accept': 'application/json'})
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.get_json()['error'], 'upload_too_large')


if __name__ == '__main__':
    unittest.main()
