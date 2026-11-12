"""Conservative bidirectional PostgreSQL sync; no deletes or password copying."""
from datetime import date, datetime, time
from decimal import Decimal
import json
import secrets
import uuid
from psycopg2 import sql
from psycopg2.extras import Json, RealDictCursor
from werkzeug.security import generate_password_hash
from duplicate_detection import normalize_name, normalize_reference

TABLES = ('crm_clients', 'cotations', 'cotation_delivery_points', 'revenus',
          'cspe_dossiers', 'client_updates', 'calendar_events', 'client_hot_followups')
REFS = {'client_id': 'crm_clients', 'cotation_id': 'cotations', 'calendar_event_id': 'calendar_events'}
USER_REFS = {'owner_id', 'created_by', 'commercial_id', 'assigned_to'}
IGNORED = {'id', 'sync_uuid', 'client_group_id'}


class SyncConflict(Exception):
    def __init__(self, conflicts):
        self.conflicts = conflicts
        super().__init__('Des modifications concurrentes nécessitent une décision.')


def json_value(value):
    if isinstance(value, (date, datetime, time)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, uuid.UUID):
        return str(value)
    return value


def choose(local, remote, baseline, choice=None):
    if choice == 'local' and local is not None:
        return local
    if choice == 'render' and remote is not None:
        return remote
    if local == remote:
        return local
    if baseline is None:
        if local is None:
            return remote
        if remote is None:
            return local
        raise ValueError('conflict')
    # A missing row is never interpreted as permission to delete its counterpart.
    if local is None or remote is None:
        raise ValueError('missing')
    if local == baseline:
        return remote
    if remote == baseline:
        return local
    raise ValueError('conflict')


def columns(conn, table):
    with conn.cursor() as cur:
        cur.execute('''SELECT column_name, data_type FROM information_schema.columns
                       WHERE table_schema = current_schema() AND table_name = %s''', (table,))
        return dict(cur.fetchall())


def prepare(conn):
    available = {}
    for table in TABLES:
        cols = columns(conn, table)
        if not cols:
            continue
        with conn.cursor() as cur:
            cur.execute(sql.SQL('ALTER TABLE {} ADD COLUMN IF NOT EXISTS sync_uuid UUID DEFAULT gen_random_uuid()').format(sql.Identifier(table)))
            cur.execute(sql.SQL('UPDATE {} SET sync_uuid = gen_random_uuid() WHERE sync_uuid IS NULL').format(sql.Identifier(table)))
            cur.execute(sql.SQL('CREATE UNIQUE INDEX IF NOT EXISTS {} ON {} (sync_uuid)').format(
                sql.Identifier('idx_sync_' + table), sql.Identifier(table)))
        available[table] = columns(conn, table)
    with conn.cursor() as cur:
        cur.execute('''CREATE TABLE IF NOT EXISTS crm_sync_baselines (
            target TEXT NOT NULL, entity TEXT NOT NULL, sync_uuid UUID NOT NULL,
            payload JSONB NOT NULL, synced_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(target, entity, sync_uuid))''')
    conn.commit()
    return available


def user_maps(local, remote, aliases):
    def users(conn):
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute('SELECT id, username, role FROM users ORDER BY id')
            return [dict(row) for row in cur.fetchall()]
    remote_users = users(remote)
    local_users = users(local)
    remote_names = {u['username'].casefold(): u['username'] for u in remote_users}
    local_names = {u['username'].casefold() for u in local_users}
    for user in remote_users:
        if user['username'].casefold() not in local_names:
            with local.cursor() as cur:
                # Imported accounts receive no copied password and no new admin privilege.
                cur.execute("INSERT INTO users(username,password_hash,role) VALUES(%s,%s,'commercial')",
                    (user['username'], generate_password_hash(secrets.token_urlsafe(32))))
            local_names.add(user['username'].casefold())
    local_users = users(local)
    local_canonical = {u['id']: remote_names.get(aliases.get(u['username'], u['username']).casefold(),
                                               aliases.get(u['username'], u['username'])) for u in local_users}
    remote_canonical = {u['id']: u['username'] for u in remote_users}
    local_ids = {name.casefold(): ident for ident, name in local_canonical.items()}
    remote_ids = {name.casefold(): ident for ident, name in remote_canonical.items()}
    return ((local_canonical, local_ids), (remote_canonical, remote_ids))


def read_rows(conn, tables):
    result = {}
    for table in tables:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql.SQL('SELECT * FROM {} ORDER BY id').format(sql.Identifier(table)))
            result[table] = {str(row['sync_uuid']): dict(row) for row in cur.fetchall()}
    return result


def archive_unlinked(local, sites, target):
    """Keep legacy orphan records verbatim, without deleting or fabricating parents."""
    with local.cursor() as cur:
        cur.execute('''CREATE TABLE IF NOT EXISTS crm_sync_orphans (
            target TEXT NOT NULL, entity TEXT NOT NULL, sync_uuid UUID NOT NULL,
            payload JSONB NOT NULL, reason TEXT NOT NULL,
            archived_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(target,entity,sync_uuid))''')
        for site in sites:
            changed = True
            while changed:
                changed = False
                present = {table: {row['id'] for row in records.values()} for table, records in site.items()}
                for table, records in site.items():
                    for uid, row in list(records.items()):
                        missing = [f'{parent} n°{row[col]}' for col, parent in REFS.items()
                                   if row.get(col) is not None and row[col] not in present.get(parent, set())]
                        if not missing:
                            continue
                        payload = {key: json_value(value) for key, value in row.items()}
                        cur.execute('''INSERT INTO crm_sync_orphans(target,entity,sync_uuid,payload,reason)
                            VALUES(%s,%s,%s,%s,%s) ON CONFLICT(target,entity,sync_uuid) DO UPDATE
                            SET payload=EXCLUDED.payload,reason=EXCLUDED.reason''',
                            (target, table, uid, Json(payload), 'Référence source absente : ' + ', '.join(missing)))
                        del records[uid]
                        changed = True
        cur.execute('SELECT COUNT(*) FROM crm_sync_orphans WHERE target=%s', (target,))
        return cur.fetchone()[0]


def sync_databases(local, remote, target, aliases=None, choices=None):
    """Caller backs up both databases first. UUIDs make retries idempotent."""
    aliases, choices = aliases or {}, choices or {}
    lc, rc = prepare(local), prepare(remote)
    missing = [t for t in TABLES if t in lc and t not in rc]
    if missing:
        raise RuntimeError('Version Render à mettre à jour : tables manquantes : ' + ', '.join(missing))
    tables = [t for t in TABLES if t in lc and t in rc]
    try:
        for conn in (remote, local):
            with conn.cursor() as cur:
                cur.execute("SET LOCAL lock_timeout = '5s'")
                cur.execute("SET LOCAL statement_timeout = '45s'")
                cur.execute("SELECT pg_try_advisory_xact_lock(hashtext('mini-crm-sync-v1:' || current_schema()))")
                if not cur.fetchone()[0]:
                    raise RuntimeError('Une synchronisation est déjà en cours.')
                for table in sorted(tables):
                    cur.execute(sql.SQL('LOCK TABLE {} IN SHARE ROW EXCLUSIVE MODE').format(sql.Identifier(table)))
        user_data = user_maps(local, remote, aliases)
        # Apply the administrator's attribution locally as well, including CA labels.
        with local.cursor() as cur:
            cur.execute('SELECT id, username FROM users')
            local_users = {name.casefold(): ident for ident, name in cur.fetchall()}
            for old_name, new_name in aliases.items():
                old_id, new_id = local_users.get(old_name.casefold()), local_users.get(new_name.casefold())
                if not old_id or not new_id or old_id == new_id:
                    continue
                for table in tables:
                    for column in USER_REFS & set(lc[table]):
                        cur.execute(sql.SQL('UPDATE {} SET {}=%s WHERE {}=%s').format(
                            sql.Identifier(table), sql.Identifier(column), sql.Identifier(column)), (new_id, old_id))
                    for column in {'commercial', 'commercial_name'} & set(lc[table]):
                        cur.execute(sql.SQL('UPDATE {} SET {}=%s WHERE {}=%s').format(
                            sql.Identifier(table), sql.Identifier(column), sql.Identifier(column)), (new_name, old_name))
        rows = [read_rows(local, tables), read_rows(remote, tables)]
        # Legacy Render rows may reference deleted users. Preserve that identity in
        # local archival accounts; never silently reassign it to a current salesperson.
        historical_ids = {row[col] for table in tables for row in rows[1][table].values()
                          for col in USER_REFS & set(row)
                          if row[col] is not None and row[col] not in user_data[1][0]}
        for ident in sorted(historical_ids):
            name = 'Ancien compte Render n°' + str(ident)
            user_data[1][0][ident] = name
            user_data[1][1][name.casefold()] = ident
            local_id = user_data[0][1].get(name.casefold())
            if local_id is None:
                with local.cursor() as cur:
                    cur.execute("INSERT INTO users(username,password_hash,role) VALUES(%s,%s,'commercial') RETURNING id",
                                (name, generate_password_hash(secrets.token_urlsafe(32))))
                    local_id = cur.fetchone()[0]
                user_data[0][0][local_id] = name
                user_data[0][1][name.casefold()] = local_id
        archived = archive_unlinked(local, rows, target)
        # Match an independently created dossier only when its name AND SIRET are unambiguous.
        # Differences still become explicit conflicts, not silent overwrites.
        remote_keys = {}
        for uid, row in rows[1].get('crm_clients', {}).items():
            key = (normalize_name(row.get('name')), normalize_reference(row.get('siret')))
            if all(key):
                remote_keys.setdefault(key, []).append(uid)
        for uid, row in list(rows[0].get('crm_clients', {}).items()):
            key = (normalize_name(row.get('name')), normalize_reference(row.get('siret')))
            candidates = remote_keys.get(key, [])
            if uid not in rows[1]['crm_clients'] and candidates:
                if len(candidates) != 1 or candidates[0] in rows[0]['crm_clients']:
                    raise RuntimeError('Plusieurs dossiers portent les mêmes raison sociale et SIRET. Un rapprochement manuel est nécessaire.')
                new_uid = candidates[0]
                with local.cursor() as cur:
                    cur.execute('UPDATE crm_clients SET sync_uuid=%s WHERE id=%s', (new_uid, row['id']))
                row['sync_uuid'] = new_uid
                rows[0]['crm_clients'][new_uid] = row
                del rows[0]['crm_clients'][uid]

        shared = {t: sorted((set(lc[t]) & set(rc[t])) - IGNORED) for t in tables}
        for table in tables:
            unsupported = (set(lc[table]) - set(rc[table])) - IGNORED
            if unsupported and any(row.get(c) not in (None, '', False) for row in rows[0][table].values() for c in unsupported):
                raise RuntimeError('Mettre Render à jour avant la synchronisation : champs absents dans ' + table)

        ids = [{t: {row['id']: uid for uid, row in site[t].items()} for t in tables} for site in rows]

        def canonical(site, table, row):
            data = {}
            for col in shared[table]:
                value = row[col]
                if value is not None and col in REFS:
                    ref_table = REFS[col]
                    ref = ids[site].get(ref_table, {}).get(value)
                    if ref is None:
                        raise RuntimeError('Référence de dossier manquante dans ' + table)
                    value = {'ref': ref_table, 'uuid': ref}
                elif value is not None and col in USER_REFS:
                    name = user_data[site][0].get(value)
                    if not name:
                        raise RuntimeError('Commercial manquant pour ' + table)
                    value = {'user': name}
                elif col in {'commercial', 'commercial_name'} and value:
                    value = aliases.get(value, value) if site == 0 else value
                data[col] = json_value(value)
            return data

        payloads = [{t: {uid: canonical(i, t, row) for uid, row in site[t].items()} for t in tables}
                    for i, site in enumerate(rows)]
        with local.cursor() as cur:
            cur.execute('SELECT entity, sync_uuid::text, payload FROM crm_sync_baselines WHERE target=%s', (target,))
            baselines = {(t, uid): data for t, uid, data in cur.fetchall()}
        plan, conflicts = [], []
        for table in tables:
            for uid in sorted(set(payloads[0][table]) | set(payloads[1][table])):
                left, right = payloads[0][table].get(uid), payloads[1][table].get(uid)
                key = table + ':' + uid
                try:
                    selected = choose(left, right, baselines.get((table, uid)), choices.get(key))
                    if selected:
                        for value in selected.values():
                            if isinstance(value, dict) and 'user' in value and value['user'].casefold() not in user_data[1][1]:
                                raise RuntimeError('Associer le commercial local « ' + value['user'] + ' » à un compte Render avant de transférer.')
                    plan.append((table, uid, selected))
                except ValueError:
                    conflicts.append(dict(key=key, entity=table, local=left, render=right,
                                          label=(left or right).get('name') or (left or right).get('entreprise_nom') or uid))
        if conflicts:
            raise SyncConflict(conflicts)
        counts = {'envoyes': 0, 'recus': 0}
        if archived:
            counts['archives_a_rapprocher'] = archived
        for table, uid, data in plan:
            for site, conn in enumerate((local, remote)):
                if data == payloads[site][table].get(uid):
                    continue
                values = {}
                for col, value in data.items():
                    if isinstance(value, dict) and 'ref' in value:
                        ref = rows[site][value['ref']].get(value['uuid'])
                        if not ref:
                            raise RuntimeError('Ordre de synchronisation invalide.')
                        value = ref['id']
                    elif isinstance(value, dict) and 'user' in value:
                        value = user_data[site][1][value['user'].casefold()]
                    if (lc if site == 0 else rc)[table].get(col) in {'json', 'jsonb'} and value is not None:
                        value = Json(value)
                    values[col] = value
                names = list(values)
                with conn.cursor() as cur:
                    cur.execute(sql.SQL('INSERT INTO {} ({}) VALUES ({}) ON CONFLICT(sync_uuid) DO UPDATE SET {} RETURNING id').format(
                        sql.Identifier(table), sql.SQL(',').join(map(sql.Identifier, ['sync_uuid'] + names)),
                        sql.SQL(',').join([sql.Placeholder()] * (len(names) + 1)),
                        sql.SQL(',').join(sql.SQL('{}=EXCLUDED.{}').format(sql.Identifier(c), sql.Identifier(c)) for c in names)),
                        [uid] + [values[c] for c in names])
                    saved_id = cur.fetchone()[0]
                rows[site][table][uid] = dict(id=saved_id, sync_uuid=uid)
                counts['recus' if site == 0 else 'envoyes'] += 1
            with local.cursor() as cur:
                cur.execute('''INSERT INTO crm_sync_baselines(target,entity,sync_uuid,payload)
                    VALUES(%s,%s,%s,%s) ON CONFLICT(target,entity,sync_uuid) DO UPDATE
                    SET payload=EXCLUDED.payload, synced_at=CURRENT_TIMESTAMP''', (target, table, uid, Json(data)))
        remote.commit()
        local.commit()
        return counts
    except Exception:
        remote.rollback()
        local.rollback()
        raise
