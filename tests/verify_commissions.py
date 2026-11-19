"""Run against disposable tables in a unique schema of the local database only."""
import os
import sys
import uuid
from pathlib import Path
from decimal import Decimal
from datetime import date
from unittest.mock import patch
import psycopg2
from psycopg2 import sql
from psycopg2.extras import DictCursor

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ['LOCAL_MODE'] = '1'
import local_crm
import app as crm
from commissions import ensure_commissions_schema, insert_revenue, commission_values

config = local_crm.load_config()
conn = psycopg2.connect(host='127.0.0.1', port=config['db_port'], dbname=config['db_name'],
                        user=config['db_user'], password=config['db_password'], cursor_factory=DictCursor)
schema = 'commission_verification_' + uuid.uuid4().hex
try:
    with conn.cursor() as cur:
        cur.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
        cur.execute(sql.SQL('SET search_path TO {}').format(sql.Identifier(schema)))
        cur.execute('CREATE TABLE users(id SERIAL PRIMARY KEY, username TEXT UNIQUE, role TEXT)')
        cur.execute('CREATE TABLE crm_clients(id SERIAL PRIMARY KEY, name TEXT, status TEXT, owner_id INTEGER, commercial TEXT)')
        cur.execute('CREATE TABLE revenus(id SERIAL PRIMARY KEY, date DATE, commercial TEXT, dossier TEXT, client_id INTEGER, montant DOUBLE PRECISION)')
        cur.execute("INSERT INTO users(username,role) VALUES ('Alice','commercial')")
        cur.execute("INSERT INTO crm_clients(name,status,owner_id,commercial) VALUES ('Test','gagne',1,'Alice')")
    conn.commit()
    ensure_commissions_schema(conn)
    ensure_commissions_schema(conn)
    with conn.cursor() as cur:
        cur.execute('UPDATE users SET commission_rate=30, direct_commission_rate=20 WHERE id=1')
        insert_revenue(cur, date(2026, 11, 19), 'Alice', 'Test', 1, Decimal('1000'), 'ade')
        cur.execute('UPDATE users SET commission_rate=40 WHERE id=1')
        cur.execute('SELECT * FROM revenus')
        revenue = cur.fetchone()
        assert commission_values(revenue) == (Decimal('195'), Decimal('455'))
        assert revenue['montant'] == 650
        insert_revenue(cur, date(2026, 11, 19), 'Alice', 'Test', 1, Decimal('1000'), 'direct')
        cur.execute('SELECT * FROM revenus ORDER BY id DESC LIMIT 1')
        assert commission_values(cur.fetchone()) == (Decimal('100'), Decimal('400'))
        cur.execute("INSERT INTO users(username,role,commission_rate,direct_commission_rate) VALUES ('Bob','commercial',10,50)")
        insert_revenue(cur, date(2026, 11, 19), 'Bob', 'Test', 1, Decimal('1000'), 'ade')
        cur.execute('SELECT * FROM revenus ORDER BY id DESC LIMIT 1')
        assert commission_values(cur.fetchone()) == (Decimal('65'), Decimal('585'))
        insert_revenue(cur, date(2026, 11, 19), 'Bob', 'Test', 1, Decimal('1000'), 'direct')
        cur.execute('SELECT * FROM revenus ORDER BY id DESC LIMIT 1')
        assert commission_values(cur.fetchone()) == (Decimal('250'), Decimal('250'))
    conn.commit()
    with crm.app.test_request_context('/commissions?year=2026'):
        crm.session['user'] = dict(id=1, role='admin', username='admin')
        def render(name, **context):
            context.update(current_user=crm.session['user'], csrf_token='test', available_endpoints=[],
                           format_date=crm.format_date_safe)
            return crm.app.jinja_env.get_template(name).render(**context)
        with patch.object(crm, 'get_db', return_value=conn), patch.object(crm, 'render_template', side_effect=render):
            html = crm.commissions()
            assert '195.00' in html and '455.00' in html
            html = crm.commission_settings()
            assert '40.00' in html and 'Alice' in html
            assert "Chiffre d'affaires" in crm.chiffre_affaire()
            crm.session['user'] = dict(id=1, role='commercial', username='Alice')
            html = crm.commissions()
            assert '195.00' in html and 'Taux commercial' not in html
            assert "Chiffre d'affaires" in crm.chiffre_affaire()
            with patch.object(crm, 'can_access_client', return_value=True):
                html, status = crm.validate_client_revenue(1)
                assert status == 200 and 'data-ade' not in html
    print('OK: migration, snapshot preservation, commission totals and templates on local PostgreSQL')
finally:
    conn.rollback()
    with conn.cursor() as cur:
        cur.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(sql.Identifier(schema)))
    conn.commit()
    conn.close()
