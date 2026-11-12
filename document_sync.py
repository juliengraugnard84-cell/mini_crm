"""Authenticated, content-addressed bridge for CRM attachments on Render."""
import hashlib
import hmac
import io
import json
from pathlib import Path
import time
from urllib.parse import urlparse
import requests
from psycopg2 import sql
from werkzeug.utils import secure_filename

ENTITIES = {'crm_clients': 'clients/', 'cspe_dossiers': 'cspe/'}


def signature(password, stamp, method, action_args, body):
    key = hashlib.sha256(('mini-crm-document-sync-v1:' + password).encode()).digest()
    message = '\n'.join([str(stamp), method, json.dumps(action_args, sort_keys=True), hashlib.sha256(body).hexdigest()])
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()


class FileBridge:
    def __init__(self, base_url, database_url):
        parsed = urlparse(base_url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError('Renseigner l’adresse HTTPS du CRM hébergé sur Render.')
        self.url = base_url.rstrip('/') + '/api/local-sync/documents'
        from urllib.parse import unquote
        self.password = unquote(urlparse(database_url).password or '')
        if not self.password:
            raise ValueError('Identifiants de synchronisation absents.')

    def call(self, params, body=b''):
        method = 'POST' if params['action'] == 'put' else 'GET'
        stamp = str(int(time.time()))
        headers = {'X-CRM-Sync-Time': stamp,
                   'X-CRM-Sync-Signature': signature(self.password, stamp, method, params, body),
                   'Content-Type': 'application/octet-stream'}
        response = requests.request(method, self.url, params=params, data=body, headers=headers,
                                    timeout=(8, 90), allow_redirects=False)
        if response.status_code != 200:
            raise RuntimeError('Passerelle de documents Render indisponible. Déployer la version du CRM avec synchronisation avant de réessayer.')
        return response


def register_document_sync(crm):
    crm.CSRF_EXEMPT_ENDPOINTS.add('sync_documents')

    @crm.app.route('/api/local-sync/documents', methods=['GET', 'POST'], endpoint='sync_documents')
    def sync_documents():
        from urllib.parse import unquote
        password = unquote(urlparse(crm.DATABASE_URL or '').password or '')
        stamp = crm.request.headers.get('X-CRM-Sync-Time', '')
        try:
            recent = abs(time.time() - int(stamp)) < 300
        except ValueError:
            recent = False
        body = crm.request.get_data()
        expected = signature(password, stamp, crm.request.method, crm.request.args.to_dict(), body)
        if crm.LOCAL_MODE or not password or not recent or not hmac.compare_digest(
                expected, crm.request.headers.get('X-CRM-Sync-Signature', '')):
            crm.abort(403)
        action = crm.request.args.get('action')
        if action == 'status':
            return crm.jsonify(version=1)
        if not crm.s3 or not crm.AWS_BUCKET:
            return crm.jsonify(error='Stockage des documents indisponible.'), 503
        conn = crm.get_db()
        maps = {}
        for entity in ENTITIES:
            with conn.cursor() as cur:
                cur.execute(sql.SQL('SELECT id, sync_uuid::text FROM {}').format(sql.Identifier(entity)))
                maps[entity] = dict(cur.fetchall())

        def identify(key, strict=True):
            if key.startswith('clients/'):
                entity, ident = 'crm_clients', crm.extract_client_id_from_s3_key(key)
            elif key.startswith('cspe/'):
                entity, ident = 'cspe_dossiers', crm.extract_cspe_id_from_storage_key(key)
            else:
                crm.abort(400)
            uid = maps[entity].get(ident)
            if not uid:
                if strict:
                    crm.abort(404)
                return None
            return entity, uid

        if action == 'list' and crm.request.method == 'GET':
            result = []
            for prefix in ENTITIES.values():
                for item in crm.s3_list_all_objects(crm.AWS_BUCKET, prefix=prefix):
                    key = item.get('Key', '')
                    if not key or key.endswith('/'):
                        continue
                    if (key.startswith('clients/') and not crm.extract_client_id_from_s3_key(key)):
                        continue  # Shared/global resources are not dossier attachments.
                    identity = identify(key, strict=False)
                    if not identity:
                        continue  # Do not block every dossier on an old orphaned attachment.
                    entity, uid = identity
                    result.append(dict(entity=entity, uuid=uid, key=key, name=key.rsplit('/', 1)[-1]))
            return crm.jsonify(files=result)
        if action == 'get' and crm.request.method == 'GET':
            key = crm.request.args.get('key', '')
            identify(key)
            content = crm.s3.get_object(Bucket=crm.AWS_BUCKET, Key=key)['Body'].read()
            return crm.send_file(io.BytesIO(content), mimetype='application/octet-stream')
        if action == 'put' and crm.request.method == 'POST':
            entity, uid = crm.request.args.get('entity'), crm.request.args.get('uuid')
            if entity not in ENTITIES:
                crm.abort(400)
            ident = next((ident for ident, value in maps[entity].items() if value == uid), None)
            name = secure_filename(crm.request.args.get('name') or '')
            if ident is None or not name or not crm.allowed_file(name) or not body:
                crm.abort(400)
            prefix = crm.client_s3_prefix(ident) if entity == 'crm_clients' else crm.cspe_storage_prefix(ident)
            digest = hashlib.sha256(body).hexdigest()
            key = prefix + 'sync_' + digest + '_' + name[-100:]
            # The same payload and name always produce the same key, including after a retry.
            crm.s3.put_object(Bucket=crm.AWS_BUCKET, Key=key, Body=body)
            return crm.jsonify(key=key, sha256=digest)
        crm.abort(400)


def sync_files(conn, root, bridge):
    root = Path(root)
    maps = {}
    for entity in ENTITIES:
        with conn.cursor() as cur:
            cur.execute(sql.SQL('SELECT id,sync_uuid::text FROM {}').format(sql.Identifier(entity)))
            maps[entity] = {uid: ident for ident, uid in cur.fetchall()}
    conn.commit()
    local = {}
    for entity, prefix in ENTITIES.items():
        from app import extract_client_id_from_s3_key, extract_cspe_id_from_storage_key
        identify = extract_client_id_from_s3_key if entity == 'crm_clients' else extract_cspe_id_from_storage_key
        inverse = {ident: uid for uid, ident in maps[entity].items()}
        for path in (root / prefix).rglob('*'):
            if path.is_file():
                uid = inverse.get(identify(path.relative_to(root).as_posix()))
                if uid:
                    digest = hashlib.sha256(path.read_bytes()).hexdigest()
                    local[(entity, uid, digest)] = path
    sent, received = 0, 0
    remote_hashes = set()
    for item in bridge.call({'action': 'list'}).json()['files']:
        entity, uid = item['entity'], item['uuid']
        ident = maps.get(entity, {}).get(uid)
        if ident is None:
            raise RuntimeError('Document Render sans dossier local : relancer la synchronisation des données.')
        content = bridge.call({'action': 'get', 'key': item['key']}).content
        digest = hashlib.sha256(content).hexdigest()
        key = entity, uid, digest
        remote_hashes.add(key)
        if key not in local:
            prefix = 'clients' if entity == 'crm_clients' else 'cspe'
            path = root / prefix / ('sync_' + str(ident)) / (digest + '_' + (secure_filename(item['name']) or 'document')[-100:])
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() and path.read_bytes() != content:
                raise RuntimeError('Conflit de contenu documentaire : aucun fichier écrasé.')
            path.write_bytes(content)
            local[key] = path
            received += 1
    for key, path in local.items():
        if key not in remote_hashes:
            entity, uid, digest = key
            bridge.call(dict(action='put', entity=entity, uuid=uid, name=path.name), path.read_bytes())
            sent += 1
    return dict(documents_envoyes=sent, documents_recus=received)
