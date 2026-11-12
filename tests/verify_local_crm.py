"""Explicit local-only smoke test; creates and removes its own temporary dossier."""
import io
import json
from pathlib import Path
import re
import sys
import uuid
import zipfile
import psycopg2
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import local_crm

config = local_crm.load_config()
url = 'http://127.0.0.1:' + str(config['web_port'])
session = requests.Session()
session.trust_env = False
assert session.get(url + '/local/etat', timeout=10).json()['mode'] == 'local'
page = session.get(url + '/login', timeout=20)
token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page.text)[1]
page = session.post(url + '/login', data=dict(csrf_token=token, username='admin',
                   password=config['admin_password']), timeout=30)
assert page.status_code == 200 and '/login' not in page.url, ('login', page.status_code)
page = session.get(url + '/clients', timeout=30)
assert page.status_code == 200, ('clients', page.status_code)
token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page.text)[1]
conn = psycopg2.connect(host='127.0.0.1', port=config['db_port'], user=config['db_user'],
                        password=config['db_password'], dbname=config['db_name'])
conn.autocommit = True
client_id = None
file_path = None
test_archive = None
suffix = uuid.uuid4().hex
try:
    with conn.cursor() as cursor:
        cursor.execute("SELECT id FROM users WHERE username = 'Commercial local'")
        owner = cursor.fetchone()[0]
    page = session.post(url + '/clients/create', data=dict(csrf_token=token, name='VERIFICATION-' + suffix,
        owner_id=owner, siret='99999999900019', address='Adresse de verification'), timeout=40)
    assert page.status_code == 200, ('create', page.status_code)
    with conn.cursor() as cursor:
        cursor.execute('SELECT id FROM crm_clients WHERE name = %s', ('VERIFICATION-' + suffix,))
        client_id = cursor.fetchone()[0]
    page = session.post(url + f'/clients/{client_id}/cotation', data=dict(csrf_token=token,
        energie_type='electricite', entreprise_nom='VERIFICATION-' + suffix, siret='99999999900019',
        date_negociation='2026-11-12', heure_negociation='11:00', pdl_pce='99999999999999',
        type_compteur='C4'), timeout=40)
    assert page.status_code == 200
    with conn.cursor() as cursor:
        cursor.execute('SELECT type_compteur FROM cotations WHERE client_id = %s', (client_id,))
        assert cursor.fetchone()[0] == 'C4'
    content = b'%PDF-1.4\nLocal verification\n%%EOF'
    filename = 'verification-' + suffix + '.pdf'
    page = session.post(url + f'/clients/{client_id}/documents/upload',
        data=dict(csrf_token=token, doc_kind='factures'),
        files={'files': (filename, content, 'application/pdf')}, timeout=30)
    assert page.status_code == 200
    matches = [p for p in (local_crm.STATE / 'documents').rglob('*' + suffix + '*') if p.is_file()]
    assert len(matches) == 1, 'Local attachment was not saved'
    file_path = matches[0]
    key = file_path.relative_to(local_crm.STATE / 'documents').as_posix()
    response = session.get(url + '/document/download', params={'key': key}, timeout=20)
    assert response.content == content
    response = session.get(url + '/local/sauvegarde', timeout=60)
    assert response.status_code == 200
    archive_name = re.search(r'filename="?([^";]+)', response.headers['Content-Disposition'])[1]
    assert Path(archive_name).name == archive_name
    test_archive = local_crm.STATE / 'backups' / archive_name
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert 'database.dump' in archive.namelist()
        assert 'documents/' + key in archive.namelist()
    print('Local smoke test passed: login, dossier, quotation C4, attachment upload/download, complete ZIP backup.')
finally:
    with conn.cursor() as cursor:
        if client_id:
            cursor.execute('DELETE FROM cotations WHERE client_id = %s', (client_id,))
            cursor.execute('DELETE FROM crm_clients WHERE id = %s', (client_id,))
    conn.commit()
    conn.close()
    if file_path:
        file_path.unlink(missing_ok=True)
    if test_archive:
        test_archive.unlink(missing_ok=True)
        test_archive.with_suffix('.dump').unlink(missing_ok=True)
    local_crm.backup(config)
    print('Verification dossier removed; local CRM ready for real entries.')
