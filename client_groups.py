"""Non-destructive client grouping with independent energy dossiers and ownership."""
from duplicate_detection import normalize_name, normalize_reference, name_words


def suggested_common_name(name):
    words = name_words(name)
    if words and words[0] in {'foncia', 'cythia'}:
        return words[0].capitalize()
    return (name or '').strip()


def attach_client_group(conn, client_id, name, siret, common_name='', preserve_current=False):
    """Same SIRET always reuses its group; a shared label can group several SIRETs."""
    reference = normalize_reference(siret)
    with conn.cursor() as cur:
        if reference:
            cur.execute('SELECT pg_advisory_xact_lock(hashtext(%s))', ('client-group:' + reference,))
            cur.execute('''SELECT client_group_id FROM crm_clients
                           WHERE id <> %s AND client_group_id IS NOT NULL
                             AND upper(regexp_replace(COALESCE(siret, ''), '[[:space:]./-]', '', 'g')) = %s
                           ORDER BY id LIMIT 1''', (client_id, reference))
            existing = cur.fetchone()
            if existing:
                group_id = existing['client_group_id']
                cur.execute('UPDATE crm_clients SET client_group_id = %s WHERE id = %s', (group_id, client_id))
                return group_id
        if preserve_current:
            cur.execute('SELECT client_group_id FROM crm_clients WHERE id = %s', (client_id,))
            current = cur.fetchone()
            if current and current['client_group_id']:
                return current['client_group_id']
        label = (common_name or '').strip() or suggested_common_name(name)
        words = name_words(name)
        branded = bool(words and words[0] in {'foncia', 'cythia'})
        if common_name or branded:
            key = 'name:' + normalize_name(label)
        elif reference:
            key = 'siret:' + reference
        else:
            key = 'client:' + str(client_id)
        cur.execute('''INSERT INTO crm_client_groups (common_name, group_key)
                       VALUES (%s, %s) ON CONFLICT (group_key) DO UPDATE
                       SET group_key = EXCLUDED.group_key RETURNING id''', (label, key))
        group_id = cur.fetchone()['id']
        cur.execute('UPDATE crm_clients SET client_group_id = %s WHERE id = %s', (group_id, client_id))
        return group_id


def ensure_client_groups_schema(conn):
    with conn.cursor() as cur:
        cur.execute('''CREATE TABLE IF NOT EXISTS crm_client_groups (
                       id SERIAL PRIMARY KEY, common_name TEXT NOT NULL,
                       group_key TEXT NOT NULL UNIQUE,
                       created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('''ALTER TABLE crm_clients ADD COLUMN IF NOT EXISTS
                       client_group_id INTEGER REFERENCES crm_client_groups(id)''')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_crm_clients_group ON crm_clients(client_group_id)')
        cur.execute('SELECT id, name, siret FROM crm_clients WHERE client_group_id IS NULL ORDER BY id')
        missing = cur.fetchall()
    for client in missing:
        attach_client_group(conn, client['id'], client['name'], client['siret'])


def build_group_summaries(clients, quotations, points):
    """Count unique dossiers per energy, not repeated quotation requests."""
    groups, client_map, quote_map = {}, {}, {}
    for source in clients:
        client = dict(source)
        client['energies'] = set()
        client['points'] = {'electricite': [], 'gaz': []}
        client_map[client['id']] = client
        group_id = client['client_group_id']
        group = groups.setdefault(group_id, dict(id=group_id, name=client['common_name'], dossiers=[],
                                                commercials=set(), sirets=set()))
        group['dossiers'].append(client)
        if client.get('commercial'):
            group['commercials'].add(client['commercial'])
        if client.get('siret'):
            group['sirets'].add(normalize_reference(client['siret']))
    for quote in quotations:
        if quote['client_id'] not in client_map:
            continue
        quote_map[quote['id']] = dict(quote)
        client = client_map[quote['client_id']]
        energy = (quote.get('energie_type') or '').strip().lower()
        if energy in {'electricite', 'gaz'}:
            client['energies'].add(energy)
        elif energy in {'mixte', 'electricite_gaz', 'gaz_electricite', 'elec_gaz'}:
            client['energies'].update(['electricite', 'gaz'])
        for reference, point_energy in [(quote.get('pdl_pce'), 'gaz' if energy == 'gaz' else 'electricite'),
                                        (quote.get('pce'), 'gaz')]:
            if reference:
                client['energies'].add(point_energy)
                client['points'][point_energy].append(dict(reference=reference,
                    address=quote.get('adresse_consommation') or client.get('address'),
                    site=quote.get('site_nom') or client['name']))
    for point in points:
        quote = quote_map.get(point['cotation_id'])
        if not quote:
            continue
        client = client_map[quote['client_id']]
        energy = (point.get('energy_type') or quote.get('energie_type') or '').lower()
        if energy not in {'electricite', 'gaz'}:
            continue
        client['energies'].add(energy)
        client['points'][energy].append(dict(reference=point.get('reference_code'),
            address=point.get('address') or client.get('address'),
            site=point.get('site_label') or client['name']))
    for group in groups.values():
        for client in group['dossiers']:
            for energy in ['electricite', 'gaz']:
                unique = {}
                for point in client['points'][energy]:
                    key = normalize_reference(point['reference']) or (point['site'], point['address'])
                    # Prefer the richer multisite row over the legacy copy.
                    unique[key] = point
                client['points'][energy] = list(unique.values())
        group['commercials'] = sorted(group['commercials'], key=str.casefold)
        group['sirets'] = sorted(group['sirets'])
        group['total'] = len(group['dossiers'])
        group['electricite'] = [c for c in group['dossiers'] if 'electricite' in c['energies']]
        group['gaz'] = [c for c in group['dossiers'] if 'gaz' in c['energies']]
        group['sans_energie'] = [c for c in group['dossiers'] if not c['energies']]
    return sorted(groups.values(), key=lambda group: group['name'].casefold())


def load_group_summaries(conn, clients):
    if not clients:
        return []
    ids = [client['id'] for client in clients]
    with conn.cursor() as cur:
        cur.execute('SELECT id, common_name FROM crm_client_groups WHERE id = ANY(%s)',
                    (list({client['client_group_id'] for client in clients}),))
        group_names = {row['id']: row['common_name'] for row in cur.fetchall()}
        cur.execute('''SELECT id, client_id, energie_type, pdl_pce, pce,
                              adresse_consommation, site_nom FROM cotations
                       WHERE client_id = ANY(%s) ORDER BY id''', (ids,))
        quotations = cur.fetchall()
        cur.execute('''SELECT p.* FROM cotation_delivery_points p
                       JOIN cotations q ON q.id = p.cotation_id
                       WHERE q.client_id = ANY(%s) ORDER BY p.id''', (ids,))
        points = cur.fetchall()
    enriched = [dict(client, common_name=group_names[client['client_group_id']]) for client in clients]
    return build_group_summaries(enriched, quotations, points)
