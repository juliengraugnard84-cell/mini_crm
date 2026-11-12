"""Explicit integration test using two disposable schemas in the LOCAL database."""
import sys
from pathlib import Path
import uuid
import psycopg2
from psycopg2 import sql

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import local_crm
from crm_sync import sync_databases, SyncConflict

c = local_crm.load_config()
def connect():
    return psycopg2.connect(host='127.0.0.1', port=c['db_port'], dbname=c['db_name'],
                            user=c['db_user'], password=c['db_password'])
connections = [connect(), connect()]
schemas = ['sync_verification_' + uuid.uuid4().hex for _ in connections]
try:
    for index, (conn, schema) in enumerate(zip(connections, schemas)):
        with conn.cursor() as cur:
            cur.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
            cur.execute(sql.SQL('SET search_path TO {}').format(sql.Identifier(schema)))
            cur.execute('CREATE TABLE users(id SERIAL PRIMARY KEY,username TEXT UNIQUE,password_hash TEXT,role TEXT)')
            cur.execute('CREATE TABLE crm_clients(id SERIAL PRIMARY KEY,name TEXT,siret TEXT,owner_id INTEGER,status TEXT,notes TEXT)')
            cur.execute('CREATE TABLE cotations(id SERIAL PRIMARY KEY,client_id INTEGER REFERENCES crm_clients(id),created_by INTEGER,entreprise_nom TEXT,heure_negociation TIME)')
            cur.execute('CREATE TABLE cotation_delivery_points(id SERIAL PRIMARY KEY,cotation_id INTEGER REFERENCES cotations(id),reference_code TEXT)')
            cur.execute('CREATE TABLE revenus(id SERIAL PRIMARY KEY,client_id INTEGER REFERENCES crm_clients(id),commercial TEXT,montant NUMERIC,date DATE)')
            if index == 0:
                cur.execute("INSERT INTO users(username,role) VALUES('Commercial local','commercial')")
                cur.execute("INSERT INTO crm_clients(name,siret,owner_id,status) VALUES('Local test','111',1,'en_cours')")
                cur.execute("INSERT INTO cotations(client_id,created_by,entreprise_nom,heure_negociation) VALUES(1,1,'Local test','11:00')")
                cur.execute("INSERT INTO cotation_delivery_points(cotation_id,reference_code) VALUES(1,'001234')")
                cur.execute("INSERT INTO revenus(client_id,commercial,montant,date) VALUES(1,'Commercial local',123.45,'2026-11-12')")
            else:
                cur.execute("INSERT INTO users(id,username,role) VALUES(7,'Julien','commercial')")
                cur.execute("INSERT INTO crm_clients(id,name,siret,owner_id,status) VALUES(50,'Render test','222',999,'gagne')")
        conn.commit()
    local, remote = connections
    result = sync_databases(local, remote, 'verification', {'Commercial local': 'Julien'})
    assert result['envoyes'] == 4 and result['recus'] == 1, result
    with remote.cursor() as cur:
        cur.execute('SELECT c.name,r.montant,c.owner_id FROM revenus r JOIN crm_clients c ON c.id=r.client_id')
        row = cur.fetchone()
        assert row[0] == 'Local test' and float(row[1]) == 123.45 and row[2] == 7
        cur.execute('SELECT p.reference_code,c.name FROM cotation_delivery_points p JOIN cotations q ON q.id=p.cotation_id JOIN crm_clients c ON c.id=q.client_id')
        assert cur.fetchone() == ('001234', 'Local test')
    remote.commit()
    with local.cursor() as cur:
        cur.execute("SELECT u.username FROM crm_clients c JOIN users u ON u.id=c.owner_id WHERE c.name='Render test'")
        assert cur.fetchone()[0] == 'Ancien compte Render n°999'
    local.commit()
    retry = sync_databases(local, remote, 'verification', {'Commercial local': 'Julien'})
    assert retry == {'envoyes': 0, 'recus': 0}, retry
    with local.cursor() as cur:
        cur.execute("UPDATE crm_clients SET notes='modified locally' WHERE name='Local test'")
    local.commit()
    with remote.cursor() as cur:
        cur.execute("UPDATE crm_clients SET notes='modified on Render' WHERE name='Local test'")
    remote.commit()
    try:
        sync_databases(local, remote, 'verification', {'Commercial local': 'Julien'})
        raise AssertionError('Concurrent changes must require a choice')
    except SyncConflict as error:
        assert len(error.conflicts) == 1
        key = error.conflicts[0]['key']
    sync_databases(local, remote, 'verification', {'Commercial local': 'Julien'}, {key: 'render'})
    with local.cursor() as cur:
        cur.execute("SELECT notes FROM crm_clients WHERE name='Local test'")
        assert cur.fetchone()[0] == 'modified on Render'
    local.commit()
    with remote.cursor() as cur:
        cur.execute("INSERT INTO cotations(client_id,created_by,entreprise_nom,heure_negociation) VALUES(NULL,7,'Historical orphan','12:00') RETURNING id")
        orphan_id = cur.fetchone()[0]
        # Simulate a pre-constraint legacy orphan without weakening real CRM tables.
        cur.execute('ALTER TABLE cotations DROP CONSTRAINT cotations_client_id_fkey')
        cur.execute('UPDATE cotations SET client_id=9999 WHERE id=%s', (orphan_id,))
    remote.commit()
    archived = sync_databases(local, remote, 'verification', {'Commercial local': 'Julien'})
    assert archived['archives_a_rapprocher'] == 1
    with local.cursor() as cur:
        cur.execute("SELECT payload->>'entreprise_nom' FROM crm_sync_orphans")
        assert cur.fetchone()[0] == 'Historical orphan'
    local.commit()
    print('Integration passed: two-way dossiers, remapped IDs/users, CA cents, cotation time, PDL, idempotent retry, conflict resolution.')
finally:
    for conn, schema in zip(connections, schemas):
        conn.rollback()
        assert schema.startswith('sync_verification_')
        with conn.cursor() as cur:
            cur.execute('SET search_path TO public')
            cur.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(sql.Identifier(schema)))
        conn.commit()
        conn.close()
    print('Disposable verification schemas removed; real CRM data unchanged.')
