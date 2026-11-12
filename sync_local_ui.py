"""Local admin control panel for a deliberate, backed-up Render synchronization."""
import hashlib
import json
from datetime import datetime
from urllib.parse import urlparse, unquote
import psycopg2
from crm_sync import prepare, sync_databases, SyncConflict
from document_sync import FileBridge, sync_files


def register_sync_ui(crm, config, state, backup, run_pg):
    @crm.app.route('/local/synchronisation', methods=['GET', 'POST'])
    @crm.admin_required
    def local_sync():
        message, conflicts, users, result = '', [], [], None
        settings = state / 'sync-settings.json'
        saved = json.loads(settings.read_text(encoding='utf-8')) if settings.exists() else {}
        remote_url = (crm.request.form.get('render_url') or saved.get('render_url') or '').strip()
        selected = (crm.request.form.get('commercial_local') or saved.get('commercial_local') or '').strip()
        remote = None
        if crm.request.method == 'POST':
            try:
                credential_file = state.parent / 'render_database_url.txt'
                if not credential_file.is_file():
                    raise RuntimeError('Fichier instance/render_database_url.txt absent.')
                dsn = credential_file.read_text(encoding='utf-8-sig').strip().strip('"').strip("'")
                parsed = urlparse(dsn)
                if parsed.scheme not in {'postgres', 'postgresql'} or not parsed.hostname or not parsed.password:
                    raise RuntimeError('Le fichier de connexion Render est invalide.')
                if not parsed.hostname.endswith('.render.com'):
                    raise RuntimeError('Utiliser l’adresse externe de la base Render.')
                remote = psycopg2.connect(dsn, sslmode='require', connect_timeout=8)
                with remote.cursor() as cur:
                    cur.execute("SELECT username FROM users WHERE role='commercial' ORDER BY username")
                    users = [row[0] for row in cur.fetchall()]
                remote.commit()
                if selected and selected not in users:
                    raise RuntimeError('Choisir un commercial existant sur Render.')
                if crm.request.form.get('action') == 'sync':
                    bridge = FileBridge(remote_url, dsn)
                    if bridge.call({'action': 'status'}).json().get('version') != 1:
                        raise RuntimeError('Passerelle Render incompatible.')
                    # Backups precede even metadata migrations on both databases.
                    backup(config)
                    target_file = state / 'backups' / ('render-avant-sync-' + datetime.now().strftime('%Y%m%d-%H%M%S') + '.dump')
                    run_pg('pg_dump', ['-h', parsed.hostname, '-p', parsed.port or 5432,
                        '-U', unquote(parsed.username or ''), '-d', unquote(parsed.path.lstrip('/')),
                        '-Fc', '-f', target_file], dict(config, db_password=unquote(parsed.password), db_sslmode='require'), timeout=120)
                    target = hashlib.sha256((parsed.hostname + parsed.path).encode()).hexdigest()
                    choices = {key.removeprefix('resolve_'): value for key, value in crm.request.form.items()
                               if key.startswith('resolve_') and value in {'local', 'render'}}
                    aliases = {'Commercial local': selected} if selected else {}
                    result = sync_databases(crm.get_db(), remote, target, aliases, choices)
                    try:
                        result.update(sync_files(crm.get_db(), state / 'documents', bridge))
                        result['documents'] = 'terminé'
                    except Exception:
                        # DB commits are idempotent; retrying completes documents without duplication.
                        result['documents'] = 'à reprendre'
                        message = 'Données et CA synchronisés. Certains documents restent à transférer : relancer la synchronisation. Les fichiers locaux sont conservés.'
                    crm.ensure_client_groups_schema(crm.get_db())
                    crm.get_db().commit()
                    saved = dict(render_url=remote_url, commercial_local=selected)
                    settings.write_text(json.dumps(saved), encoding='utf-8')
                    (state / 'last-sync.json').write_text(json.dumps(dict(date=datetime.now().isoformat(), result=result)), encoding='utf-8')
                    backup(config)
                    if not message:
                        message = 'Synchronisation terminée : dossiers, cotations, CA et documents.'
                else:
                    message = 'Connexion à la base Render réussie. Choisir le commercial et renseigner l’adresse HTTPS du CRM pour synchroniser aussi les documents.'
            except SyncConflict as error:
                conflicts = error.conflicts
                message = 'Aucune donnée métier transférée : choisir la version à conserver pour chaque conflit, puis relancer.'
            except psycopg2.Error:
                crm.get_db().rollback()
                message = 'Base Render inaccessible ou opération refusée. Les saisies locales restent conservées. Réessayer après réactivation du service.'
            except (ValueError, RuntimeError) as error:
                crm.get_db().rollback()
                message = str(error)
            except Exception:
                crm.get_db().rollback()
                message = 'La synchronisation n’a pas pu être terminée. Les données et sauvegardes locales sont conservées ; réessayer.'
            finally:
                if remote:
                    remote.close()
        history = state / 'last-sync.json'
        last = json.loads(history.read_text(encoding='utf-8')) if history.exists() else None
        return crm.render_template('local_sync.html', message=message, conflicts=conflicts, users=users,
            render_url=remote_url, selected_commercial=selected, result=result, last_sync=last)
