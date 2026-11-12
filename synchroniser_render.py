"""Manual global synchronization. Same safeguards as the local admin panel."""
import hashlib
import json
from datetime import datetime
from urllib.parse import urlparse, unquote
import psycopg2
import local_crm
from crm_sync import sync_databases
from document_sync import FileBridge, sync_files


def main():
    config, state = local_crm.load_config(), local_crm.STATE
    dsn = (state.parent / 'render_database_url.txt').read_text(encoding='utf-8-sig').strip().strip('"').strip("'")
    parsed = urlparse(dsn)
    base = 'https://mini-crm-6fed.onrender.com'
    settings_file = state / 'sync-settings.json'
    settings = json.loads(settings_file.read_text(encoding='utf-8')) if settings_file.exists() else {}
    bridge = FileBridge(base, dsn)
    bridge.call({'action': 'status'})
    print('Sauvegarde locale...', flush=True)
    local_crm.backup(config)
    remote_file = state / 'backups' / ('render-avant-sync-globale-' + datetime.now().strftime('%Y%m%d-%H%M%S') + '.dump')
    print('Sauvegarde Render...', flush=True)
    local_crm.run_pg('pg_dump', ['-h', parsed.hostname, '-p', parsed.port or 5432,
        '-U', unquote(parsed.username), '-d', unquote(parsed.path.lstrip('/')), '-Fc', '-f', remote_file],
        dict(config, db_password=unquote(parsed.password), db_sslmode='require'), timeout=120)
    local = psycopg2.connect(host='127.0.0.1', port=config['db_port'], user=config['db_user'],
        password=config['db_password'], dbname=config['db_name'])
    remote = psycopg2.connect(dsn, sslmode='require', connect_timeout=8)
    target = hashlib.sha256((parsed.hostname + parsed.path).encode()).hexdigest()
    result = None
    def save():
        (state / 'last-sync.json').write_text(json.dumps(dict(date=datetime.now().isoformat(), result=result)), encoding='utf-8')
    try:
        print('Synchronisation des donnees et du CA...', flush=True)
        chosen = settings.get('commercial_local')
        result = sync_databases(local, remote, target, {'Commercial local': chosen} if chosen else {})
        result['documents'] = 'à reprendre'
        save()
        print('Donnees:', result, flush=True)
        result.update(sync_files(local, state / 'documents', bridge,
            progress=lambda counts: print('Documents:', counts, flush=True)))
        result['documents'] = 'terminé'
        save()
        settings['render_url'] = base
        settings_file.write_text(json.dumps(settings), encoding='utf-8')
        local_crm.backup(config)
        print('SYNCHRONISATION GLOBALE TERMINEE', result, flush=True)
    except Exception as error:
        print('SYNCHRONISATION INTERROMPUE:', type(error).__name__,
              str(error).replace(dsn, '[URL MASQUEE]').replace(unquote(parsed.password), '[MASQUE]'), flush=True)
        if result:
            save()
        raise SystemExit(2)
    finally:
        local.close()
        remote.close()


if __name__ == '__main__':
    main()
