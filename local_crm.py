"""Isolated, loopback-only local CRM with its own PostgreSQL database."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
from datetime import datetime
from urllib.parse import quote
import webbrowser
import zipfile

ROOT = Path(__file__).resolve().parent
STATE = ROOT / 'instance' / 'local_crm'


def postgres_bin():
    candidates = [Path(os.environ['POSTGRES_BIN'])] if os.environ.get('POSTGRES_BIN') else []
    if shutil.which('pg_ctl'):
        candidates.append(Path(shutil.which('pg_ctl')).parent)
    candidates.extend(sorted(Path(os.environ.get('ProgramFiles', r'C:\Program Files')).glob('PostgreSQL/*/bin'), reverse=True))
    for candidate in candidates:
        if (candidate / 'initdb.exe').is_file() and (candidate / 'pg_dump.exe').is_file():
            return candidate
    raise RuntimeError('PostgreSQL introuvable. Definir POSTGRES_BIN avec son dossier bin.')


def run_pg(binary, args, config, quiet=False, **kwargs):
    streams = dict(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) if quiet else dict(capture_output=True)
    return subprocess.run([str(postgres_bin() / (binary + '.exe')), *map(str, args)],
        env=dict(os.environ, PGPASSWORD=config['db_password'], PGSSLMODE=config.get('db_sslmode', 'prefer')), check=True,
        **streams, text=True, errors='replace',
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0, **kwargs)


def load_config():
    STATE.mkdir(parents=True, exist_ok=True)
    path = STATE / 'settings.json'
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    config = dict(db_port=55432, web_port=5055, db_user='mini_crm_local', db_name='mini_crm_local',
                  db_password=secrets.token_urlsafe(32), secret_key=secrets.token_hex(32),
                  admin_password=secrets.token_urlsafe(14))
    with path.open('x', encoding='utf-8') as stream:
        json.dump(config, stream, indent=2)
    return config


def start_database(config):
    data = STATE / 'postgres'
    if data.exists() and not (data / 'global' / 'pg_control').exists() and not (data / 'postmaster.pid').exists():
        data.rename(STATE / ('postgres-initialisation-interrompue-' + datetime.now().strftime('%Y%m%d-%H%M%S')))
    if not (data / 'PG_VERSION').exists():
        password_file = STATE / 'init-password.tmp'
        try:
            password_file.write_text(config['db_password'], encoding='utf-8')
            run_pg('initdb', ['-D', data, '-U', config['db_user'], '--encoding=UTF8', '--locale=C',
                '--auth-host=scram-sha-256', '--auth-local=scram-sha-256', '--pwfile', password_file], config)
        finally:
            password_file.unlink(missing_ok=True)
    try:
        run_pg('pg_ctl', ['-D', data, 'status'], config, timeout=10)
    except subprocess.CalledProcessError:
        run_pg('pg_ctl', ['-D', data, '-l', STATE / 'postgres.log', '-w', '-t', '45',
               '-o', f"-h 127.0.0.1 -p {config['db_port']} -c shared_buffers=64MB -c max_connections=30",
               'start'], config, quiet=True, timeout=55)
    import psycopg2
    connection = psycopg2.connect(host='127.0.0.1', port=config['db_port'], user=config['db_user'],
                                password=config['db_password'], dbname='postgres', connect_timeout=10)
    connection.autocommit = True
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1 FROM pg_database WHERE datname = %s', (config['db_name'],))
            if not cursor.fetchone():
                from psycopg2 import sql
                cursor.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(config['db_name'])))
    finally:
        connection.close()


def configure_environment(config):
    os.environ.update(LOCAL_MODE='1', ENV='development', FLASK_ENV='development',
        EMAIL_NOTIFICATIONS_ENABLED='0', PORT=str(config['web_port']),
        APP_BASE_URL=f"http://127.0.0.1:{config['web_port']}", SECRET_KEY=config['secret_key'],
        ADMIN_DEFAULT_PASSWORD=config['admin_password'],
        DATABASE_URL=f"postgresql://{quote(config['db_user'])}:{quote(config['db_password'])}@127.0.0.1:{config['db_port']}/{config['db_name']}")


def backup(config):
    directory = STATE / 'backups'
    directory.mkdir(exist_ok=True)
    target = directory / ('mini-crm-local-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.dump')
    run_pg('pg_dump', ['-h', '127.0.0.1', '-p', config['db_port'], '-U', config['db_user'],
                       '-d', config['db_name'], '-Fc', '-f', target], config, timeout=120)
    archive = target.with_suffix('.zip')
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as output:
        output.write(target, 'database.dump')
        for file in (STATE / 'documents').rglob('*'):
            if file.is_file():
                output.write(file, 'documents/' + file.relative_to(STATE / 'documents').as_posix())
        output.writestr('LIRE-MOI.txt', 'Sauvegarde Mini CRM local : database.dump et documents.\n'
                        'Ne pas importer directement dans Render : rapprocher les nouvelles saisies pour eviter les doublons.\n')
    return archive


def initialize_application(config):
    configure_environment(config)
    import app as crm
    crm.LOCAL_UPLOAD_ROOT = str(STATE / 'documents')
    crm.init_db()
    with crm.app.app_context():
        connection = crm.get_db()
        crm.ensure_cotation_schema(connection)
        crm.ensure_cotation_delivery_points_schema(connection)
        crm.ensure_client_groups_schema(connection)
        crm.ensure_duplicate_alerts_schema(connection)
        with connection.cursor() as cursor:
            cursor.execute('''INSERT INTO users (username, password_hash, role)
                              VALUES (%s, %s, 'commercial') ON CONFLICT (username) DO NOTHING''',
                           ('Commercial local', crm.generate_password_hash(secrets.token_urlsafe(32))))
        connection.commit()

    from sync_local_ui import register_sync_ui
    from crm_sync import prepare
    with crm.app.app_context():
        prepare(crm.get_db())
    register_sync_ui(crm, config, STATE, backup, run_pg)

    @crm.app.context_processor
    def local_context():
        return dict(local_crm_active=True)

    @crm.app.route('/local/sauvegarde')
    @crm.admin_required
    def local_backup():
        target = backup(config)
        return crm.send_file(target, as_attachment=True, download_name=target.name)

    @crm.app.route('/local/etat')
    def local_status():
        return crm.jsonify(mode='local', database='mini_crm_local')

    return crm


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--backup', action='store_true')
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    os.chdir(ROOT)
    config = load_config()
    start_database(config)
    if args.backup:
        print('Sauvegarde creee :', backup(config))
        return
    crm = initialize_application(config)
    backup(config)
    url = f"http://127.0.0.1:{config['web_port']}"
    instructions = (f"MINI CRM LOCAL\n\nAdresse : {url}\nIdentifiant : admin\n"
                    f"Mot de passe : {config['admin_password']}\n\n"
                    'Les donnees restent sur cet ordinateur. Synchronisation Render disponible dans le bandeau local.\n'
                    'Sauvegardes : instance\\local_crm\\backups\n'
                    'Copier le dossier instance\\local_crm et les documents locaux sur un support de sauvegarde.\n')
    (STATE / 'ACCES_LOCAL.txt').write_text(instructions, encoding='utf-8')
    print('Mini CRM local :', url, flush=True)
    print('Identifiants : instance\\local_crm\\ACCES_LOCAL.txt', flush=True)
    if args.prepare:
        return
    if not args.no_browser:
        webbrowser.open(url)
    try:
        crm.app.run(host='127.0.0.1', port=config['web_port'], debug=False, use_reloader=False)
    finally:
        backup(config)


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        print('Erreur PostgreSQL :', error.stderr or error.stdout, file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print('ERREUR locale :', error, file=sys.stderr)
        sys.exit(1)
