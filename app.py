# ============================
# app.py — VERSION COMPLÈTE CORRIGÉE (PARTIE 1/4)
# Objectif: 100% fonctionnalités conservées, aucun doublon de route,
# CSRF sécurisé, update_deletions_log créé, S3 anti-overwrite sans casser.
# ============================

import os
import re
import socket
import smtplib
import ssl
import unicodedata
import secrets
import logging
from datetime import date, timedelta
from email.message import EmailMessage
from types import SimpleNamespace
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    session,
    abort,
    g,
)

from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import BadRequest

import boto3
from botocore.exceptions import ClientError

import psycopg2
import psycopg2.extras

from config import Config


############################################################
# 0. LOGGING (safe prod)
############################################################
logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


############################################################
# 1. CONFIGURATION GLOBALE
############################################################

LOCAL_MODE = Config.LOCAL_MODE

AWS_ACCESS_KEY = Config.AWS_ACCESS_KEY
AWS_SECRET_KEY = Config.AWS_SECRET_KEY
AWS_REGION = Config.AWS_REGION
AWS_BUCKET = Config.AWS_BUCKET
SMTP_HOST = Config.SMTP_HOST
SMTP_PORT = Config.SMTP_PORT
SMTP_USERNAME = Config.SMTP_USERNAME
SMTP_PASSWORD = Config.SMTP_PASSWORD
SMTP_USE_TLS = Config.SMTP_USE_TLS
SMTP_USE_SSL = Config.SMTP_USE_SSL
SMTP_FROM_EMAIL = Config.SMTP_FROM_EMAIL
EMAIL_NOTIFICATIONS_ENABLED = Config.EMAIL_NOTIFICATIONS_ENABLED
NOTIFICATION_EMAIL = Config.NOTIFICATION_EMAIL
APP_BASE_URL = Config.APP_BASE_URL

# ✅ PostgreSQL: on utilise DATABASE_URL
DATABASE_URL = getattr(Config, "DATABASE_URL", None) or os.environ.get("DATABASE_URL")

ALLOWED_EXTENSIONS = {
    "pdf",
    "jpg", "jpeg", "png",
    "doc", "docx",
    "xls", "xlsx", "csv",
}

CHAT_ALLOWED_ROLES = {"admin", "commercial"}
PLANNING_ALLOWED_ROLES = {"admin", "commercial"}
DOCUMENT_UPLOAD_KINDS = {
    "factures": "factures",
    "mandats": "mandats",
    "contrats": "contrats",
    "summary": "summary",
    "autres": "autres",
}

NOTIFICATION_EMAIL_RECIPIENTS = [
    recipient.strip()
    for recipient in (NOTIFICATION_EMAIL or "").split(",")
    if recipient.strip()
]

PLANNING_EVENT_CATEGORIES = {
    "meeting": {"label": "Rendez-vous", "color": "#2f6cab"},
    "negociation": {"label": "Negociation", "color": "#f2b233"},
    "relance": {"label": "Relance", "color": "#123646"},
    "signature": {"label": "Signature", "color": "#16a34a"},
    "visit": {"label": "Visite", "color": "#d89a24"},
    "internal": {"label": "Interne", "color": "#475569"},
}

PLANNING_EVENT_STATUSES = {
    "confirmed": "Confirme",
    "tentative": "Tentatif",
    "cancelled": "Annule",
}

PLANNING_EVENT_VISIBILITIES = {
    "private": "Prive",
    "assigned": "Cible",
    "team": "Equipe",
}

PLANNING_SOURCE_STYLES = {
    "manual": {"label": "Agenda", "color": "#2f6cab"},
    "cotation": {"label": "Negociation", "color": "#f2b233"},
    "update": {"label": "Suivi client", "color": "#08133f"},
}

# Max upload (MB) — configurable via Config.MAX_UPLOAD_MB sinon 10MB
MAX_UPLOAD_MB = getattr(Config, "MAX_UPLOAD_MB", 10)

# Debug pilotable (évite debug=True “par erreur” en prod)
DEBUG = getattr(Config, "DEBUG", False)

# Mot de passe admin par défaut (optionnel)
# ⚠️ on conserve le comportement (bootstrap), mais on privilégie l'env si présente
ADMIN_DEFAULT_PASSWORD = (
    os.environ.get("ADMIN_DEFAULT_PASSWORD")
    or getattr(Config, "ADMIN_DEFAULT_PASSWORD", None)
    or "admin123"
)

# CSRF: endpoints JSON éventuellement exemptés (si vous ne voulez pas gérer le header côté front)
CSRF_EXEMPT_ENDPOINTS = {
    "chat_send",
    "chat_mark_read",
}


############################################################
# 2. INITIALISATION FLASK
############################################################

app = Flask(__name__)
app.config.from_object(Config)

if not app.config.get("SECRET_KEY"):
    raise RuntimeError("SECRET_KEY manquant dans la configuration.")

app.secret_key = app.config["SECRET_KEY"]

# Sécurité cookies session (prod-friendly)
app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
app.config.setdefault("PERMANENT_SESSION_LIFETIME", timedelta(days=365))
app.config.setdefault("SESSION_REFRESH_EACH_REQUEST", True)

# Active SECURE si explicitement demandé, sinon détection d'env minimale
is_production = (
    os.environ.get("FLASK_ENV") == "production"
    or os.environ.get("ENV") == "production"
    or getattr(Config, "PRODUCTION", False)
)

if is_production:
    app.config.setdefault("SESSION_COOKIE_SECURE", True)

# Limite upload (évite DOS)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

###########################################################
# 3. BASE DE DONNÉES (POSTGRESQL – PROD SAFE)
############################################################

def _connect_db():
    """
    Connexion PostgreSQL unique.
    AUCUNE initialisation automatique ici.
    """
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL manquant dans la configuration.")

    sslmode = "require" if is_production else "prefer"

    conn = psycopg2.connect(
        DATABASE_URL,
        cursor_factory=psycopg2.extras.DictCursor,
        sslmode=sslmode,
    )
    conn.autocommit = False
    return conn


def get_db():
    """
    Connexion stockée dans g (1 par requête)
    """
    if "db" not in g:
        g.db = _connect_db()
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """
    Fermeture propre de la connexion
    """
    db = g.pop("db", None)
    if db is not None:
        db.close()


def row_to_obj(row):
    """
    Convertit une row PostgreSQL en objet avec accès par attribut.
    """
    if not row:
        return None
    return SimpleNamespace(**dict(row))


def _try_add_column(conn, table, column_sql):
    """
    Ajout de colonne SAFE (idempotent).
    Ne casse jamais une base existante.
    """
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column_sql}"
            )
        conn.commit()
    except Exception:
        conn.rollback()


def _try_run_ddl(conn, sql):
    """
    Exécution DDL SAFE (table/index/contrainte idempotente).
    """
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()
    except Exception:
        conn.rollback()


def init_db():
    """
    INITIALISATION MANUELLE UNIQUEMENT
    ⚠️ NE JAMAIS APPELER AUTOMATIQUEMENT EN PROD
    """
    conn = _connect_db()
    try:
        with conn.cursor() as cur:

            # ================= USERS =================
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL
                )
            """)

            # ================= CLIENTS =================
            cur.execute("""
                CREATE TABLE IF NOT EXISTS crm_clients (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT,
                    phone TEXT,
                    address TEXT,
                    commercial TEXT,
                    status TEXT,
                    notes TEXT,
                    owner_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # ================= COTATIONS =================
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cotations (
                    id SERIAL PRIMARY KEY,
                    client_id INTEGER,
                    date_negociation DATE,
                    energie_type TEXT,
                    pdl_pce TEXT,
                    date_echeance DATE,
                    fournisseur_actuel TEXT,
                    entreprise_nom TEXT,
                    siret TEXT,
                    adresse_facturation TEXT,
                    adresse_consommation TEXT,
                    signataire_nom TEXT,
                    signataire_tel TEXT,
                    signataire_email TEXT,
                    commentaire TEXT,
                    created_by INTEGER,
                    is_read INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'nouvelle',
                    date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # ================= REVENUS =================
            cur.execute("""
                CREATE TABLE IF NOT EXISTS revenus (
                    id SERIAL PRIMARY KEY,
                    date DATE NOT NULL,
                    commercial TEXT,
                    dossier TEXT,
                    client_id INTEGER,
                    montant DOUBLE PRECISION NOT NULL
                )
            """)

            # ================= CSPE =================
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cspe_dossiers (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    notes TEXT,
                    owner_id INTEGER,
                    date_negociation DATE,
                    chiffre_affaire DOUBLE PRECISION DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # ================= CHAT =================
            cur.execute("""
                CREATE TABLE IF NOT EXISTS chat_messages (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER,
                    username TEXT,
                    recipient_id INTEGER,
                    recipient_username TEXT,
                    scope TEXT DEFAULT 'broadcast',
                    message TEXT,
                    file_key TEXT,
                    file_name TEXT,
                    is_read INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS chat_message_reads (
                    id SERIAL PRIMARY KEY,
                    message_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # ================= MISES À JOUR DOSSIER =================
            cur.execute("""
                CREATE TABLE IF NOT EXISTS client_updates (
                    id SERIAL PRIMARY KEY,
                    client_id INTEGER NOT NULL,
                    client_name TEXT NOT NULL,
                    commercial_id INTEGER NOT NULL,
                    commercial_name TEXT NOT NULL,
                    update_date DATE NOT NULL,
                    commentaire TEXT,
                    is_read INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # ================= EVENEMENTS CALENDRIER =================
            cur.execute("""
                CREATE TABLE IF NOT EXISTS calendar_events (
                    id SERIAL PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    event_date DATE NOT NULL,
                    end_date DATE,
                    event_time TIME,
                    end_time TIME,
                    all_day BOOLEAN DEFAULT FALSE,
                    location TEXT,
                    category TEXT DEFAULT 'meeting',
                    status TEXT DEFAULT 'confirmed',
                    visibility TEXT DEFAULT 'private',
                    color TEXT,
                    created_by INTEGER,
                    assigned_to INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # ================= LOG SUPPRESSION =================
            cur.execute("""
                CREATE TABLE IF NOT EXISTS update_deletions_log (
                    id SERIAL PRIMARY KEY,
                    update_id INTEGER,
                    client_id INTEGER,
                    admin_id INTEGER,
                    admin_username TEXT,
                    deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # ================= ADMIN BOOTSTRAP =================
            cur.execute("SELECT id FROM users WHERE username = 'admin'")
            if not cur.fetchone():
                cur.execute("""
                    INSERT INTO users (username, password_hash, role)
                    VALUES (%s, %s, %s)
                """, (
                    "admin",
                    generate_password_hash(ADMIN_DEFAULT_PASSWORD),
                    "admin",
                ))

            # ================= MIGRATIONS SAFE =================

            # CLIENTS
            _try_add_column(conn, "crm_clients", "siret TEXT")
            _try_add_column(conn, "crm_clients", "gerant_nom TEXT")

            # CSPE
            _try_add_column(conn, "cspe_dossiers", "notes TEXT")
            _try_add_column(conn, "cspe_dossiers", "owner_id INTEGER")
            _try_add_column(conn, "cspe_dossiers", "date_negociation DATE")
            _try_add_column(conn, "cspe_dossiers", "chiffre_affaire DOUBLE PRECISION DEFAULT 0")
            _try_add_column(conn, "cspe_dossiers", "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")

            # CHAT
            _try_add_column(conn, "chat_messages", "recipient_id INTEGER")
            _try_add_column(conn, "chat_messages", "recipient_username TEXT")
            _try_add_column(conn, "chat_messages", "scope TEXT DEFAULT 'broadcast'")
            _try_run_ddl(
                conn,
                """
                CREATE TABLE IF NOT EXISTS chat_message_reads (
                    id SERIAL PRIMARY KEY,
                    message_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """,
            )
            _try_run_ddl(
                conn,
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_chat_message_reads_unique
                ON chat_message_reads (message_id, user_id)
                """,
            )
            _try_run_ddl(
                conn,
                """
                CREATE INDEX IF NOT EXISTS idx_chat_messages_visibility
                ON chat_messages (recipient_id, user_id, id)
                """,
            )

            # BASE COTATION
            _try_add_column(conn, "cotations", "type_compteur TEXT")
            _try_add_column(conn, "cotations", "heure_negociation TIME")
            _try_add_column(conn, "cotations", "signataire_mobile TEXT")

            # NOUVEAUX CHAMPS CLIENT
            _try_add_column(conn, "cotations", "site_nom TEXT")
            _try_add_column(conn, "cotations", "fonction_signataire TEXT")
            _try_add_column(conn, "cotations", "code_naf TEXT")
            _try_add_column(conn, "cotations", "date_remise_offre DATE")

            # ELECTRICITE
            _try_add_column(conn, "cotations", "elec_debut_fourniture DATE")
            _try_add_column(conn, "cotations", "elec_fin_fourniture DATE")
            _try_add_column(conn, "cotations", "elec_nb_mois INTEGER")
            _try_add_column(conn, "cotations", "elec_segment TEXT")
            _try_add_column(conn, "cotations", "formule_acheminement TEXT")
            _try_add_column(conn, "cotations", "elec_car TEXT")
            _try_add_column(conn, "cotations", "puissance_souscrite TEXT")
            _try_add_column(conn, "cotations", "elec_fournisseur_actuel TEXT")

            # PUISSANCES
            _try_add_column(conn, "cotations", "pointe TEXT")
            _try_add_column(conn, "cotations", "hph TEXT")
            _try_add_column(conn, "cotations", "hch TEXT")
            _try_add_column(conn, "cotations", "hpr TEXT")
            _try_add_column(conn, "cotations", "hce TEXT")

            # GAZ
            _try_add_column(conn, "cotations", "gaz_debut_fourniture DATE")
            _try_add_column(conn, "cotations", "gaz_fin_fourniture DATE")
            _try_add_column(conn, "cotations", "gaz_nb_mois INTEGER")
            _try_add_column(conn, "cotations", "pce TEXT")
            _try_add_column(conn, "cotations", "gaz_segment TEXT")
            _try_add_column(conn, "cotations", "profil TEXT")
            _try_add_column(conn, "cotations", "gaz_car TEXT")
            _try_add_column(conn, "cotations", "gaz_fournisseur_actuel TEXT")

            # 🔥 FIX CRITIQUE — CALENDAR EVENTS
            _try_add_column(conn, "calendar_events", "end_time TIME")
            _try_add_column(conn, "calendar_events", "all_day BOOLEAN DEFAULT FALSE")
            _try_add_column(conn, "calendar_events", "end_date DATE")
            _try_add_column(conn, "calendar_events", "location TEXT")
            _try_add_column(conn, "calendar_events", "category TEXT DEFAULT 'meeting'")
            _try_add_column(conn, "calendar_events", "status TEXT DEFAULT 'confirmed'")
            _try_add_column(conn, "calendar_events", "visibility TEXT DEFAULT 'private'")
            _try_add_column(conn, "calendar_events", "color TEXT")
            _try_add_column(conn, "calendar_events", "assigned_to INTEGER")

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


# 🚨 IMPORTANT
# ❌ NE PAS APPELER init_db() AUTOMATIQUEMENT
# ✅ À exécuter UNE SEULE FOIS manuellement
############################################################
# 4. S3 — STOCKAGE DOCUMENTS (PROD SAFE)
############################################################

s3 = None

if LOCAL_MODE:
    logger.info("ℹ️ Mode local actif : S3 désactivé.")
elif not AWS_BUCKET:
    logger.warning("S3 désactivé : AWS_BUCKET manquant.")
else:
    try:
        s3 = boto3.client(
            "s3",
            region_name=AWS_REGION,
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY,
            config=boto3.session.Config(
                retries={"max_attempts": 3, "mode": "standard"},
                connect_timeout=5,
                read_timeout=30,
            ),
        )
        logger.info(
            "S3 connecté | bucket=%s | region=%s",
            AWS_BUCKET,
            AWS_REGION,
        )
    except Exception as e:
        logger.exception("❌ Erreur connexion S3 : %r", e)
        s3 = None


# =========================================================
# VALIDATION & NORMALISATION FICHIERS
# =========================================================

def allowed_file(filename: str) -> bool:
    """
    Vérifie extension + bloque extensions dangereuses.
    """
    if not filename or "." not in filename:
        return False

    lowered = filename.lower()

    # ❌ blocage exécutables
    if re.search(r"\.(exe|js|bat|cmd|sh|php|pl|py)\b", lowered):
        return False

    ext = lowered.rsplit(".", 1)[1]
    return ext in ALLOWED_EXTENSIONS


def clean_filename(filename: str) -> str:
    """
    Nettoyage nom de fichier (ASCII / S3 safe).
    """
    name, ext = os.path.splitext(filename)
    name = (
        unicodedata.normalize("NFKD", name)
        .encode("ascii", "ignore")
        .decode()
    )
    name = re.sub(r"[^a-zA-Z0-9]+", "_", name).strip("_").lower()
    return f"{name}{ext.lower()}"


def slugify(text: str) -> str:
    """
    Génère un slug stable (clients / dossiers).
    """
    if not text:
        return ""

    text = (
        unicodedata.normalize("NFKD", text)
        .encode("ascii", "ignore")
        .decode()
    )
    return re.sub(r"[^a-zA-Z0-9]+", "_", text).strip("_").lower()


def normalize_document_kind(value: str) -> str:
    kind = slugify(value or "")
    return kind if kind in DOCUMENT_UPLOAD_KINDS else "autres"


def build_document_upload_base_name(
    container_name: str,
    original_name: str,
    manual_name: str = "",
    doc_kind: str = "autres",
    auto_name: bool = False,
    extra_suffix: str = "",
):
    normalized_kind = normalize_document_kind(doc_kind)
    safe_suffix = slugify(extra_suffix or "")

    if auto_name:
        container_slug = slugify(container_name or "") or "dossier"
        parts = [container_slug, normalized_kind]
        if safe_suffix:
            parts.append(safe_suffix)
        base_name = "_".join(part for part in parts if part)
    else:
        source_name = manual_name or original_name or "document"
        base_name = os.path.splitext(clean_filename(source_name))[0]
        if safe_suffix:
            base_name = f"{base_name}_{safe_suffix}"

    return base_name or "document"


def build_app_url(path: str) -> str:
    clean_path = path or "/"
    if clean_path.startswith("http://") or clean_path.startswith("https://"):
        return clean_path

    base_url = APP_BASE_URL or request.url_root.rstrip("/")
    return f"{base_url}{clean_path if clean_path.startswith('/') else f'/{clean_path}'}"


def resolve_smtp_settings():
    raw_host = (SMTP_HOST or "").strip()
    port = int(SMTP_PORT or 587)
    use_ssl = bool(SMTP_USE_SSL)
    use_tls = bool(SMTP_USE_TLS)

    if raw_host.startswith(("smtp://", "smtps://")):
        parsed = urlparse(raw_host)
        if parsed.hostname:
            raw_host = parsed.hostname
        if parsed.port:
            port = parsed.port
        if parsed.scheme == "smtps":
            use_ssl = True
            use_tls = False

    elif ":" in raw_host:
        host_candidate, port_candidate = raw_host.rsplit(":", 1)
        if port_candidate.isdigit():
            raw_host = host_candidate.strip()
            port = int(port_candidate)

    if port == 465 and not use_tls:
        use_ssl = True
    elif use_ssl:
        use_tls = False

    return {
        "host": raw_host.strip(),
        "port": port,
        "use_ssl": use_ssl,
        "use_tls": use_tls,
        "from_email": (SMTP_FROM_EMAIL or SMTP_USERNAME or "").strip(),
    }


def send_notification_email(subject: str, body: str, recipients=None):
    if not EMAIL_NOTIFICATIONS_ENABLED:
        logger.info("Notification email skipped: email notifications disabled.")
        return False, "emails desactives"

    targets = recipients or NOTIFICATION_EMAIL_RECIPIENTS
    settings = resolve_smtp_settings()
    smtp_host = settings["host"]
    smtp_port = settings["port"]
    smtp_use_ssl = settings["use_ssl"]
    smtp_use_tls = settings["use_tls"]
    from_email = settings["from_email"] or "no-reply@synergyconsulting.fr"

    if not smtp_host:
        logger.warning("Notification email skipped: SMTP_HOST not configured.")
        return False, "SMTP non configure"

    if not targets:
        logger.warning(
            "Notification email skipped: recipient not configured."
        )
        return False, "destinataire de notification absent"

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = from_email
    message["To"] = ", ".join(targets)
    message.set_content(body)

    server = None

    try:
        if smtp_use_ssl:
            server = smtplib.SMTP_SSL(
                smtp_host,
                smtp_port,
                timeout=20,
                context=ssl.create_default_context(),
            )
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=20)
            server.ehlo()
            if smtp_use_tls:
                server.starttls(context=ssl.create_default_context())
                server.ehlo()

        if SMTP_USERNAME and SMTP_PASSWORD:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)

        server.send_message(message)
        return True, None

    except smtplib.SMTPAuthenticationError as e:
        logger.exception(
            "Notification email authentication failed on %s:%s",
            smtp_host,
            smtp_port,
        )
        return False, "identifiants SMTP invalides"

    except smtplib.SMTPRecipientsRefused as e:
        logger.exception("Notification email recipient refused: %r", e)
        return False, "adresse destinataire refusee"

    except smtplib.SMTPConnectError as e:
        logger.exception(
            "Notification email connection failed on %s:%s",
            smtp_host,
            smtp_port,
        )
        return False, "connexion SMTP impossible"

    except (socket.gaierror, TimeoutError) as e:
        logger.exception(
            "Notification email network error on %s:%s",
            smtp_host,
            smtp_port,
        )
        return False, "serveur SMTP introuvable ou delai depasse"

    except Exception as e:
        logger.exception(
            "Notification email failed on %s:%s (ssl=%s tls=%s): %r",
            smtp_host,
            smtp_port,
            smtp_use_ssl,
            smtp_use_tls,
            e,
        )
        return False, "verifie SMTP_HOST, SMTP_PORT, SMTP_USE_TLS et SMTP_USE_SSL"

    finally:
        try:
            if server:
                server.quit()
        except Exception:
            pass


# =========================================================
# PREFIX S3 CLIENT — SOURCE DE VÉRITÉ UNIQUE
# =========================================================

def client_s3_prefix(client_id: int, client_name: str | None = None) -> str:
    """
    Préfixe S3 UNIQUE par client :
    clients/<slug_nom>_<client_id>/
    """
    if client_name is None:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT name FROM crm_clients WHERE id = %s",
                (client_id,),
            )
            row = cur.fetchone()
        client_name = row.get("name") if row else ""

    slug = slugify(client_name or "")

    base = f"{slug}_{client_id}" if slug else f"client_{client_id}"
    return f"clients/{base}/"


# =========================================================
# UPLOAD S3
# =========================================================

def s3_upload_fileobj(fileobj, bucket: str, key: str):
    """
    Upload PRIVÉ S3 (Block Public Access OK).
    """
    if not s3 or not bucket:
        raise RuntimeError("Client S3 non initialisé.")

    stream = getattr(fileobj, "stream", fileobj)

    try:
        stream.seek(0)
    except Exception:
        pass

    content_type = getattr(fileobj, "mimetype", None)
    if not content_type:
        content_type = "application/octet-stream"

    s3.upload_fileobj(
        stream,
        bucket,
        key,
        ExtraArgs={"ContentType": content_type},
    )


# =========================================================
# URL SIGNÉE
# =========================================================

def s3_presigned_url(
    key: str,
    expires_in: int = 3600,
    response_disposition: str | None = None,
) -> str:
    """
    Génère une URL signée (lecture privée).
    """
    if LOCAL_MODE or not s3 or not AWS_BUCKET:
        return ""

    try:
        params = {
            "Bucket": AWS_BUCKET,
            "Key": key,
        }

        if response_disposition:
            filename = os.path.basename(key) or "document"
            params["ResponseContentDisposition"] = (
                f'{response_disposition}; filename="{filename}"'
            )

        return s3.generate_presigned_url(
            "get_object",
            Params=params,
            ExpiresIn=expires_in,
        )
    except ClientError as e:
        logger.error(
            "Erreur presigned URL S3 (ClientError): %s",
            getattr(e, "response", None),
        )
        return ""
    except Exception as e:
        logger.exception("Erreur presigned URL S3 : %r", e)
        return ""


DOCUMENT_PREVIEW_KIND_MAP = {
    ".pdf": "pdf",
    ".png": "image",
    ".jpg": "image",
    ".jpeg": "image",
    ".gif": "image",
    ".webp": "image",
    ".bmp": "image",
    ".svg": "image",
    ".txt": "text",
    ".csv": "text",
}


def document_preview_kind(filename: str | None) -> str:
    ext = os.path.splitext((filename or "").lower())[1]
    return DOCUMENT_PREVIEW_KIND_MAP.get(ext, "unsupported")


def build_document_preview_meta(key: str) -> dict:
    filename = (key or "").split("/")[-1]
    preview_kind = document_preview_kind(filename)
    return {
        "filename": filename,
        "preview_kind": preview_kind,
        "previewable": preview_kind != "unsupported",
    }


# =========================================================
# LISTING S3
# =========================================================

def s3_list_all_objects(bucket: str, prefix: str | None = None):
    """
    Liste complète S3 avec pagination.
    """
    if not s3 or not bucket:
        return []

    items = []
    token = None

    while True:
        params = {"Bucket": bucket}

        if prefix:
            params["Prefix"] = prefix

        if token:
            params["ContinuationToken"] = token

        resp = s3.list_objects_v2(**params)

        contents = resp.get("Contents") or []
        items.extend(contents)

        if resp.get("IsTruncated") and resp.get("NextContinuationToken"):
            token = resp.get("NextContinuationToken")
        else:
            break

    return items


def _s3_object_exists(bucket: str, key: str) -> bool:
    """
    Test existence objet S3.
    """
    if not s3 or not bucket:
        return False

    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True

    except ClientError as e:
        code = (e.response or {}).get("Error", {}).get("Code", "")
        return code not in ("404", "NoSuchKey", "NotFound")

    except Exception:
        return False


def _s3_make_non_overwriting_key(bucket: str, key: str) -> str:
    """
    Empêche l'écrasement d'un fichier existant.
    """
    if not _s3_object_exists(bucket, key):
        return key

    base, ext = os.path.splitext(key)

    for _ in range(20):
        candidate = f"{base}_{secrets.token_hex(3)}{ext}"
        if not _s3_object_exists(bucket, candidate):
            return candidate

    return f"{base}_{secrets.token_hex(8)}{ext}"


# =========================================================
# LISTE DOCUMENTS CLIENT
# =========================================================

def list_client_documents(client_id: int):
    """
    Liste tous les documents d’un client.

    ✔ Compatible :
    - nouveau format : clients/<slug>_<id>/
    - ancien format : clients/<id>/
    - anciens slugs après renommage

    ✔ Optimisé :
    - scan ciblé
    """

    if not s3:
        return []

    docs = []

    try:
        base_prefix = "clients/"

        items = s3_list_all_objects(AWS_BUCKET, prefix=base_prefix)

        for item in items:
            key = item.get("Key")

            if not key or key.endswith("/"):
                continue

            extracted_client_id = extract_client_id_from_s3_key(key)

            if extracted_client_id != client_id:
                continue

            preview_meta = build_document_preview_meta(key)
            docs.append({
                "nom": key.split("/")[-1],
                "key": key,
                "taille": item.get("Size", 0),
                "preview_kind": preview_meta["preview_kind"],
                "previewable": preview_meta["previewable"],
                "url": (
                    s3_presigned_url(key)
                    if not LOCAL_MODE
                    else None
                ),
            })

    except Exception as e:
        logger.exception("Erreur list_client_documents : %r", e)

    return docs

############################################################
# 5. UTILITAIRES & CONTRÔLES D’ACCÈS
############################################################

def can_access_client(client_id: int) -> bool:
    """
    Détermine si l'utilisateur connecté peut accéder à un dossier client.

    Règles :
    - Admin : accès total
    - Commercial : uniquement ses dossiers (owner_id)
    """

    # ✅ robustesse : accepte "12" en string, évite crash
    try:
        client_id_int = int(client_id)
    except Exception:
        return False

    if client_id_int <= 0:
        return False

    user = session.get("user") or {}
    user_id = user.get("id")
    role = user.get("role")

    if not user_id or not role:
        return False

    # ✅ Admin = accès total
    if role == "admin":
        return True

    # ✅ Commercial : owner_id doit matcher
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT owner_id FROM crm_clients WHERE id = %s",
                (client_id_int,),
            )
            row = cur.fetchone()
    except Exception:
        return False

    if not row:
        return False

    return row.get("owner_id") == user_id


def get_current_user():
    """
    Retourne l'utilisateur courant sous forme d'objet
    utilisable dans Python ET Jinja.
    """
    u = session.get("user")
    return SimpleNamespace(**u) if u else None


def format_date_safe(value):
    """
    Sécurise l'affichage des dates dans les templates.
    """
    if not value:
        return "—"

    if hasattr(value, "strftime"):
        try:
            return value.strftime("%Y-%m-%d")
        except Exception:
            return "—"

    try:
        return str(value)[:10]
    except Exception:
        return "—"


# =========================================================
# Helpers documents — utilisés par bloc 11
# =========================================================

def extract_client_id_from_s3_key(key: str):
    """
    Extrait client_id depuis une key S3.

    Formats supportés :
    - clients/<slug>_<id>/fichier.pdf
    - clients/<id>/fichier.pdf   (legacy / compat)

    Retourne int ou None.
    """
    if not key:
        return None

    # Format : clients/slug_nom_123/...
    m = re.match(r"^clients\/[^\/]+_(\d+)\/", key)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            return None

    # Format legacy : clients/123/...
    m = re.match(r"^clients\/(\d+)\/", key)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            return None

    return None


def can_access_document_key(key: str) -> bool:
    """
    Règles d’accès aux documents S3.

    - Admin : accès total
    - Commercial :
        - accès aux ressources partagées : clients/shared/*
        - accès uniquement à SES clients
        - pas d’accès aux documents globaux admin-only : clients/global/*
    """

    if not key:
        return False

    user = session.get("user") or {}
    role = user.get("role")

    if not role:
        return False

    # ✅ Admin = accès total
    if role == "admin":
        return True

    # ✅ Ressources partagées (admin + commerciaux)
    if key.startswith("clients/shared/"):
        return True

    # ❌ Documents globaux réservés admin
    if key.startswith("clients/global/"):
        return False

    # 🔐 Documents liés à un client
    client_id = extract_client_id_from_s3_key(key)
    if not client_id:
        return False

    return can_access_client(client_id)


CSPE_SCHEMA_READY = False
CHAT_SCHEMA_READY = False
PLANNING_SCHEMA_READY = False
CSPE_PREFIX = "cspe/"
CHAT_UPLOAD_PREFIX = "chat/"
LOCAL_UPLOAD_ROOT = os.path.join(app.root_path, "local_uploads")


def ensure_cspe_schema():
    """
    Crée la table CSPE à la demande pour éviter une migration manuelle
    lors de l'activation du module.
    """
    global CSPE_SCHEMA_READY

    if CSPE_SCHEMA_READY:
        return

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cspe_dossiers (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    notes TEXT,
                    owner_id INTEGER,
                    date_negociation DATE,
                    chiffre_affaire DOUBLE PRECISION DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

        _try_add_column(conn, "cspe_dossiers", "notes TEXT")
        _try_add_column(conn, "cspe_dossiers", "owner_id INTEGER")
        _try_add_column(conn, "cspe_dossiers", "date_negociation DATE")
        _try_add_column(conn, "cspe_dossiers", "chiffre_affaire DOUBLE PRECISION DEFAULT 0")
        _try_add_column(conn, "cspe_dossiers", "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")

        conn.commit()
        CSPE_SCHEMA_READY = True

    except Exception:
        conn.rollback()
        raise


def can_access_cspe_dossier(dossier_id: int) -> bool:
    """
    Admin : accès total.
    Commercial : accès uniquement à ses dossiers CSPE.
    """
    try:
        dossier_id_int = int(dossier_id)
    except Exception:
        return False

    if dossier_id_int <= 0:
        return False

    try:
        ensure_cspe_schema()
    except Exception:
        return False

    user = session.get("user") or {}
    user_id = user.get("id")
    role = user.get("role")

    if not user_id or not role:
        return False

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT owner_id FROM cspe_dossiers WHERE id = %s",
                (dossier_id_int,),
            )
            row = cur.fetchone()
    except Exception:
        return False

    if not row:
        return False

    if role == "admin":
        return True

    return row.get("owner_id") == user_id


def cspe_storage_prefix(dossier_id: int, dossier_name: str | None = None) -> str:
    """
    Préfixe de stockage unique par dossier CSPE.
    """
    if dossier_name is None:
        ensure_cspe_schema()
        conn = get_db()

        with conn.cursor() as cur:
            cur.execute(
                "SELECT name FROM cspe_dossiers WHERE id = %s",
                (dossier_id,),
            )
            row = cur.fetchone()

        dossier_name = row.get("name") if row else ""

    slug = slugify(dossier_name or "")
    base = f"{slug}_{dossier_id}" if slug else f"dossier_{dossier_id}"
    return f"{CSPE_PREFIX}{base}/"


def extract_cspe_id_from_storage_key(key: str):
    """
    Extrait l'id du dossier CSPE depuis une clé de stockage.
    """
    if not key:
        return None

    match = re.match(r"^cspe\/[^\/]+_(\d+)\/", key)
    if not match:
        return None

    try:
        return int(match.group(1))
    except Exception:
        return None


def can_access_cspe_document_key(key: str) -> bool:
    """
    Vérifie qu'une pièce jointe CSPE appartient bien à un dossier accessible.
    """
    dossier_id = extract_cspe_id_from_storage_key(key)
    if not dossier_id:
        return False

    return can_access_cspe_dossier(dossier_id)


def _local_storage_parts(key: str):
    normalized = (key or "").replace("\\", "/").strip("/")
    parts = [part for part in normalized.split("/") if part and part != "."]

    if not parts or any(part == ".." for part in parts):
        raise ValueError("Clé de stockage invalide.")

    return parts


def local_storage_path(key: str) -> str:
    root = os.path.abspath(LOCAL_UPLOAD_ROOT)
    parts = _local_storage_parts(key)
    path = os.path.abspath(os.path.join(root, *parts))

    if path != root and not path.startswith(root + os.sep):
        raise ValueError("Chemin de stockage invalide.")

    return path


def _local_make_non_overwriting_key(key: str) -> str:
    if not os.path.exists(local_storage_path(key)):
        return key

    base, ext = os.path.splitext(key)

    for _ in range(20):
        candidate = f"{base}_{secrets.token_hex(3)}{ext}"
        if not os.path.exists(local_storage_path(candidate)):
            return candidate

    return f"{base}_{secrets.token_hex(8)}{ext}"


def list_local_storage_objects(prefix: str):
    try:
        directory = local_storage_path(prefix)
    except ValueError:
        return []

    if not os.path.isdir(directory):
        return []

    root = os.path.abspath(LOCAL_UPLOAD_ROOT)
    items = []

    for current_root, _, filenames in os.walk(directory):
        for filename in sorted(filenames):
            full_path = os.path.join(current_root, filename)
            key = os.path.relpath(full_path, root).replace("\\", "/")
            items.append({
                "Key": key,
                "Size": os.path.getsize(full_path),
            })

    return items


def delete_local_storage_object(key: str):
    path = local_storage_path(key)

    if not os.path.exists(path):
        return

    os.remove(path)

    root = os.path.abspath(LOCAL_UPLOAD_ROOT)
    current_dir = os.path.dirname(path)

    while current_dir.startswith(root) and current_dir != root:
        if os.listdir(current_dir):
            break
        os.rmdir(current_dir)
        current_dir = os.path.dirname(current_dir)


def list_cspe_documents(dossier_id: int):
    ensure_cspe_schema()
    docs = []

    try:
        if LOCAL_MODE:
            items = list_local_storage_objects(CSPE_PREFIX)
        elif s3:
            items = s3_list_all_objects(AWS_BUCKET, prefix=CSPE_PREFIX)
        else:
            items = []

        for item in items:
            key = item.get("Key")

            if not key or key.endswith("/"):
                continue

            if extract_cspe_id_from_storage_key(key) != dossier_id:
                continue

            preview_meta = build_document_preview_meta(key)
            docs.append({
                "nom": key.split("/")[-1],
                "key": key,
                "taille": item.get("Size", 0),
                "preview_kind": preview_meta["preview_kind"],
                "previewable": preview_meta["previewable"],
            })

    except Exception as e:
        logger.exception("Erreur list_cspe_documents : %r", e)

    return docs


def delete_cspe_documents_for_dossier(dossier_id: int):
    documents = list_cspe_documents(dossier_id)

    if LOCAL_MODE:
        for document in documents:
            try:
                delete_local_storage_object(document["key"])
            except Exception:
                logger.exception(
                    "Erreur suppression document local CSPE : %s",
                    document.get("key"),
                )
        return

    if not s3:
        return

    keys = [{"Key": document["key"]} for document in documents if document.get("key")]

    for idx in range(0, len(keys), 1000):
        chunk = keys[idx:idx + 1000]
        if chunk:
            s3.delete_objects(Bucket=AWS_BUCKET, Delete={"Objects": chunk})


def ensure_chat_schema():
    """
    Met à niveau le module chat à la demande.
    Ajoute le ciblage par destinataire et le suivi de lecture par utilisateur.
    """
    global CHAT_SCHEMA_READY

    if CHAT_SCHEMA_READY:
        return

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS chat_messages (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER,
                    username TEXT,
                    recipient_id INTEGER,
                    recipient_username TEXT,
                    scope TEXT DEFAULT 'broadcast',
                    message TEXT,
                    file_key TEXT,
                    file_name TEXT,
                    is_read INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS chat_message_reads (
                    id SERIAL PRIMARY KEY,
                    message_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

        _try_add_column(conn, "chat_messages", "recipient_id INTEGER")
        _try_add_column(conn, "chat_messages", "recipient_username TEXT")
        _try_add_column(conn, "chat_messages", "scope TEXT DEFAULT 'broadcast'")
        _try_run_ddl(
            conn,
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_chat_message_reads_unique
            ON chat_message_reads (message_id, user_id)
            """,
        )
        _try_run_ddl(
            conn,
            """
            CREATE INDEX IF NOT EXISTS idx_chat_messages_visibility
            ON chat_messages (recipient_id, user_id, id)
            """,
        )

        conn.commit()
        CHAT_SCHEMA_READY = True

    except Exception:
        conn.rollback()
        raise


def ensure_planning_schema():
    """
    Met à niveau la table agenda sans dépendre d'une migration manuelle.
    """
    global PLANNING_SCHEMA_READY

    if PLANNING_SCHEMA_READY:
        return

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS calendar_events (
                    id SERIAL PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    event_date DATE NOT NULL,
                    end_date DATE,
                    event_time TIME,
                    end_time TIME,
                    all_day BOOLEAN DEFAULT FALSE,
                    location TEXT,
                    category TEXT DEFAULT 'meeting',
                    status TEXT DEFAULT 'confirmed',
                    visibility TEXT DEFAULT 'private',
                    color TEXT,
                    created_by INTEGER,
                    assigned_to INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

        _try_add_column(conn, "calendar_events", "end_time TIME")
        _try_add_column(conn, "calendar_events", "all_day BOOLEAN DEFAULT FALSE")
        _try_add_column(conn, "calendar_events", "end_date DATE")
        _try_add_column(conn, "calendar_events", "location TEXT")
        _try_add_column(conn, "calendar_events", "category TEXT DEFAULT 'meeting'")
        _try_add_column(conn, "calendar_events", "status TEXT DEFAULT 'confirmed'")
        _try_add_column(conn, "calendar_events", "visibility TEXT DEFAULT 'private'")
        _try_add_column(conn, "calendar_events", "color TEXT")
        _try_add_column(conn, "calendar_events", "assigned_to INTEGER")

        with conn.cursor() as cur:
            cur.execute("""
                UPDATE calendar_events
                SET
                    end_date = COALESCE(end_date, event_date),
                    category = COALESCE(NULLIF(category, ''), 'meeting'),
                    status = COALESCE(NULLIF(status, ''), 'confirmed'),
                    visibility = COALESCE(NULLIF(visibility, ''), 'private')
            """)

        _try_run_ddl(
            conn,
            """
            CREATE INDEX IF NOT EXISTS idx_calendar_events_range
            ON calendar_events (event_date, end_date)
            """,
        )
        _try_run_ddl(
            conn,
            """
            CREATE INDEX IF NOT EXISTS idx_calendar_events_visibility
            ON calendar_events (created_by, assigned_to, visibility)
            """,
        )

        conn.commit()
        PLANNING_SCHEMA_READY = True

    except Exception:
        conn.rollback()
        raise


def list_planning_users():
    conn = get_db()
    users = []

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, username, role
                FROM users
                WHERE role IN ('admin', 'commercial')
                ORDER BY
                    CASE WHEN role = 'admin' THEN 0 ELSE 1 END,
                    LOWER(username) ASC
            """)
            rows = cur.fetchall()

        for row in rows:
            users.append({
                "id": row["id"],
                "username": row["username"],
                "role": row["role"],
                "role_label": chat_role_label(row["role"]),
            })

    except Exception as e:
        logger.exception("Erreur chargement utilisateurs agenda : %r", e)

    return users


def planning_parse_bool(value) -> bool:
    if isinstance(value, bool):
        return value

    return str(value or "").strip().lower() in {"1", "true", "on", "yes"}


def planning_choice(value, allowed_values, default_value):
    normalized = str(value or "").strip().lower()
    return normalized if normalized in allowed_values else default_value


def planning_category_label(category: str | None) -> str:
    meta = PLANNING_EVENT_CATEGORIES.get(category or "")
    return meta["label"] if meta else "Rendez-vous"


def planning_status_label(status: str | None) -> str:
    return PLANNING_EVENT_STATUSES.get(status or "", "Confirme")


def planning_visibility_label(visibility: str | None) -> str:
    return PLANNING_EVENT_VISIBILITIES.get(visibility or "", "Prive")


def planning_event_color(
    source_kind: str = "manual",
    category: str | None = None,
    explicit_color: str | None = None,
    status: str | None = None,
) -> str:
    if status == "cancelled":
        return "#94a3b8"

    if explicit_color:
        return explicit_color

    if source_kind != "manual":
        return PLANNING_SOURCE_STYLES.get(source_kind, {}).get("color", "#2f6cab")

    return PLANNING_EVENT_CATEGORIES.get(category or "meeting", {}).get("color", "#2f6cab")


def planning_event_text_color(color: str | None) -> str:
    if not color:
        return "#ffffff"

    raw = color.strip().lstrip("#")

    if len(raw) == 3:
        raw = "".join(ch * 2 for ch in raw)

    if len(raw) != 6:
        return "#ffffff"

    try:
        red = int(raw[0:2], 16)
        green = int(raw[2:4], 16)
        blue = int(raw[4:6], 16)
    except ValueError:
        return "#ffffff"

    luminance = (0.299 * red) + (0.587 * green) + (0.114 * blue)
    return "#10212b" if luminance >= 170 else "#f8fafc"


def planning_event_can_edit(event_row, user) -> bool:
    if not event_row:
        return False

    role = (user or {}).get("role")
    user_id = (user or {}).get("id")

    if role == "admin":
        return True

    return bool(user_id and event_row.get("created_by") == user_id)


def planning_event_can_view(event_row, user) -> bool:
    if not event_row:
        return False

    role = (user or {}).get("role")
    user_id = (user or {}).get("id")

    if role == "admin":
        return True

    if not user_id:
        return False

    visibility = event_row.get("visibility") or "private"

    return (
        event_row.get("created_by") == user_id
        or event_row.get("assigned_to") == user_id
        or visibility == "team"
    )


def fetch_calendar_event_row(event_id: int):
    ensure_planning_schema()
    conn = get_db()

    with conn.cursor() as cur:
        cur.execute("""
            SELECT
                ce.*,
                creator.username AS created_by_username,
                creator.role AS created_by_role,
                assignee.username AS assigned_to_username,
                assignee.role AS assigned_to_role
            FROM calendar_events ce
            LEFT JOIN users creator ON creator.id = ce.created_by
            LEFT JOIN users assignee ON assignee.id = ce.assigned_to
            WHERE ce.id = %s
            LIMIT 1
        """, (event_id,))
        return cur.fetchone()


def serialize_planning_event_datetimes(event_date, end_date, event_time, end_time, all_day):
    if not event_date:
        return None, None, bool(all_day)

    end_date_value = end_date or event_date

    if all_day:
        start_value = str(event_date)
        end_value = None

        if end_date_value and end_date_value > event_date:
            end_value = str(end_date_value + timedelta(days=1))

        return start_value, end_value, True

    if event_time:
        start_value = f"{event_date}T{event_time}"
    else:
        start_value = str(event_date)

    end_value = None

    if end_time or end_date_value != event_date:
        if end_time:
            end_value = f"{end_date_value}T{end_time}"
        else:
            end_value = str(end_date_value)

    return start_value, end_value, False


def serialize_manual_planning_event(row, user):
    can_edit = planning_event_can_edit(row, user)
    category = planning_choice(row.get("category"), PLANNING_EVENT_CATEGORIES, "meeting")
    status = planning_choice(row.get("status"), PLANNING_EVENT_STATUSES, "confirmed")
    visibility = planning_choice(row.get("visibility"), PLANNING_EVENT_VISIBILITIES, "private")
    color = planning_event_color(
        source_kind="manual",
        category=category,
        explicit_color=row.get("color"),
        status=status,
    )
    text_color = planning_event_text_color(color)
    start_value, end_value, all_day = serialize_planning_event_datetimes(
        row.get("event_date"),
        row.get("end_date"),
        row.get("event_time"),
        row.get("end_time"),
        row.get("all_day"),
    )

    owner_user_id = row.get("assigned_to") or row.get("created_by")
    owner_name = row.get("assigned_to_username") or row.get("created_by_username") or ""

    return {
        "id": f"manual_{row['id']}",
        "title": row.get("title") or "Rendez-vous",
        "start": start_value,
        "end": end_value,
        "allDay": all_day,
        "backgroundColor": color,
        "borderColor": color,
        "textColor": text_color,
        "editable": can_edit,
        "startEditable": can_edit,
        "durationEditable": can_edit,
        "classNames": [
            "planning-event",
            "planning-source-manual",
            f"planning-status-{status}",
            f"planning-visibility-{visibility}",
        ],
        "extendedProps": {
            "entityId": row["id"],
            "sourceKind": "manual",
            "sourceLabel": PLANNING_SOURCE_STYLES["manual"]["label"],
            "description": row.get("description") or "",
            "location": row.get("location") or "",
            "category": category,
            "categoryLabel": planning_category_label(category),
            "status": status,
            "statusLabel": planning_status_label(status),
            "visibility": visibility,
            "visibilityLabel": planning_visibility_label(visibility),
            "createdById": row.get("created_by"),
            "createdByName": row.get("created_by_username") or "",
            "createdByRole": row.get("created_by_role"),
            "assignedToId": row.get("assigned_to"),
            "assignedToName": row.get("assigned_to_username") or "",
            "assignedToRole": row.get("assigned_to_role"),
            "ownerUserId": owner_user_id,
            "ownerLabel": owner_name,
            "routeUrl": None,
            "canEdit": can_edit,
            "canDelete": can_edit,
            "color": color,
            "textColor": text_color,
        },
    }


def planning_build_payload(payload, current_user):
    title = (payload.get("title") or "").strip()
    description = (payload.get("description") or "").strip()
    location = (payload.get("location") or "").strip()
    start_date_raw = (payload.get("start_date") or payload.get("event_date") or "").strip()
    end_date_raw = (payload.get("end_date") or "").strip()
    start_time_raw = (payload.get("start_time") or "").strip()
    end_time_raw = (payload.get("end_time") or "").strip()
    all_day = planning_parse_bool(payload.get("all_day"))
    category = planning_choice(payload.get("category"), PLANNING_EVENT_CATEGORIES, "meeting")
    status = planning_choice(payload.get("status"), PLANNING_EVENT_STATUSES, "confirmed")
    visibility = planning_choice(payload.get("visibility"), PLANNING_EVENT_VISIBILITIES, "private")
    assigned_to = parse_int_safe(payload.get("assigned_to"))
    color = (payload.get("color") or "").strip()

    if not title:
        return None, "Le titre est obligatoire."

    start_date = parse_date_safe(start_date_raw)
    if not start_date:
        return None, "La date de debut est invalide."

    end_date = parse_date_safe(end_date_raw) if end_date_raw else start_date
    if end_date_raw and not end_date:
        return None, "La date de fin est invalide."

    if end_date < start_date:
        return None, "La date de fin doit etre posterieure a la date de debut."

    start_time = None
    end_time = None

    if not all_day:
        start_time = parse_time_safe(start_time_raw or "09:00")

        if start_time_raw and not start_time:
            return None, "L'heure de debut est invalide."

        if end_time_raw:
            end_time = parse_time_safe(end_time_raw)
            if not end_time:
                return None, "L'heure de fin est invalide."

        if end_date == start_date and start_time and end_time and end_time <= start_time:
            return None, "L'heure de fin doit etre apres l'heure de debut."

    current_user_id = current_user.get("id")

    if visibility == "private":
        assigned_to = current_user_id
    elif visibility == "assigned" and not assigned_to:
        return None, "Choisis le destinataire de ce rendez-vous."

    if color and not re.match(r"^#[0-9A-Fa-f]{6}$", color):
        color = ""

    if assigned_to:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id
                FROM users
                WHERE id = %s
                  AND role IN ('admin', 'commercial')
                LIMIT 1
            """, (assigned_to,))
            assignee = cur.fetchone()

        if not assignee:
            return None, "Le destinataire selectionne est invalide."

    return {
        "title": title,
        "description": description or None,
        "location": location or None,
        "event_date": start_date,
        "end_date": end_date,
        "event_time": start_time,
        "end_time": end_time,
        "all_day": all_day,
        "category": category,
        "status": status,
        "visibility": visibility,
        "assigned_to": assigned_to,
        "color": color or None,
    }, None


def list_chat_recipients(current_user_id: int):
    ensure_chat_schema()

    conn = get_db()
    recipients = []

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, username, role
                FROM users
                WHERE id <> %s
                  AND role IN ('admin', 'commercial')
                ORDER BY
                    CASE WHEN role = 'admin' THEN 0 ELSE 1 END,
                    LOWER(username) ASC
            """, (current_user_id,))
            rows = cur.fetchall()

        for row in rows:
            recipients.append({
                "id": row["id"],
                "username": row["username"],
                "role": row["role"],
                "role_label": chat_role_label(row["role"]),
            })

    except Exception as e:
        logger.exception("Erreur chargement destinataires chat : %r", e)

    return recipients


def can_access_chat_file_key(key: str) -> bool:
    if not key:
        return False

    user = session.get("user") or {}
    user_id = user.get("id")
    role = user.get("role")

    if not user_id or role not in CHAT_ALLOWED_ROLES:
        return False

    ensure_chat_schema()
    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 1
                FROM chat_messages m
                LEFT JOIN users sender ON sender.id = m.user_id
                LEFT JOIN users recipient ON recipient.id = m.recipient_id
                WHERE m.file_key = %s
                  AND sender.role IN ('admin', 'commercial')
                  AND (m.recipient_id IS NULL OR recipient.role IN ('admin', 'commercial'))
                  AND (
                      m.user_id = %s
                      OR m.recipient_id = %s
                      OR COALESCE(m.scope, 'broadcast') = 'broadcast'
                  )
                LIMIT 1
            """, (key, user_id, user_id))
            row = cur.fetchone()
    except Exception:
        return False

    return bool(row)


def chat_role_label(role: str | None) -> str:
    if role == "admin":
        return "Admin"
    if role == "commercial":
        return "Commercial"
    return "Utilisateur"



############################################################
# 5 BIS. DÉCORATEURS D’AUTHENTIFICATION & AUTORISATION
############################################################

def login_required(func):
    """
    Vérifie que l’utilisateur est connecté.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def admin_required(func):
    """
    Vérifie que l’utilisateur est admin.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))

        if session["user"].get("role") != "admin":
            flash("Accès réservé à l’administrateur.", "danger")
            return redirect(url_for("dashboard"))

        return func(*args, **kwargs)
    return wrapper


def chat_required(func):
    """
    Vérifie que l'utilisateur connecté peut accéder au chat interne.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))

        if session["user"].get("role") not in CHAT_ALLOWED_ROLES:
            abort(403)

        return func(*args, **kwargs)
    return wrapper


def planning_required(func):
    """
    Vérifie que l'utilisateur connecté peut accéder à l'agenda équipe.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))

        if session["user"].get("role") not in PLANNING_ALLOWED_ROLES:
            abort(403)

        return func(*args, **kwargs)
    return wrapper


############################################################
# CSRF — VERSION SAFE (sans casser l’existant)
############################################################

@app.before_request
def csrf_protect():
    """
    CSRF SAFE :
    - Génère toujours un token
    - Bloque toute requête mutante sans token
    - Supporte token en form OU header
    """

    if session.get("user") and not session.permanent:
        session.permanent = True

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return

    if request.endpoint in CSRF_EXEMPT_ENDPOINTS:
        return

    sent_token = (
        request.form.get("csrf_token")
        or request.headers.get("X-CSRF-Token")
        or request.headers.get("X-Csrf-Token")
    )

    if not sent_token or sent_token != session.get("csrf_token"):
        abort(403)



############################################################
# 6. VARIABLES GLOBALES POUR LES TEMPLATES
############################################################

from datetime import datetime

@app.context_processor
def inject_globals():
    """
    Variables et helpers accessibles dans TOUS les templates Jinja.
    Objectifs :
    - éviter toute logique fragile côté HTML
    - centraliser les calculs sensibles (dates, compteurs admin, etc.)
    """

    # Utilisateur courant (safe pour Jinja)
    u = session.get("user")
    current_user = SimpleNamespace(**u) if u else None

    # BADGES admin
    unread_cotations = 0
    unread_updates = 0

    if current_user and getattr(current_user, "role", None) == "admin":
        try:
            conn = get_db()
            with conn.cursor() as cur:

                # Cotations non lues
                cur.execute(
                    "SELECT COUNT(*) FROM cotations WHERE COALESCE(is_read, 0) = 0"
                )
                unread_cotations = cur.fetchone()[0]

                # Mises à jour non lues
                cur.execute(
                    "SELECT COUNT(*) FROM client_updates WHERE COALESCE(is_read, 0) = 0"
                )
                unread_updates = cur.fetchone()[0]

        except Exception:
            # Sécurité absolue : aucun crash template
            unread_cotations = 0
            unread_updates = 0

    # ✅ Liste des endpoints Flask réellement chargés (anti BuildError)
    # (dict_keys → list) pour être Jinja-friendly
    try:
        available_endpoints = list(app.view_functions.keys())
    except Exception:
        available_endpoints = []

    return dict(
        current_user=current_user,
        csrf_token=session.get("csrf_token"),
        format_date=format_date_safe,

        # ✅ AJOUT CRITIQUE (timeline FR)
        format_datetime_fr=format_datetime_fr,

        unread_cotations=unread_cotations,
        unread_updates=unread_updates,

        # ✅ FIX CRITIQUE — utilisé par chiffre_affaire.html
        current_year=datetime.now().year,

        # ✅ Utilisé par les templates pour éviter url_for sur une route absente
        available_endpoints=available_endpoints,
    )

############################################################
# 7. LOGIN / LOGOUT — VERSION ROBUSTE & ALIGNÉE DB
############################################################

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()

        if not username or not password:
            flash("Identifiants manquants.", "danger")
            return render_template("login.html")

        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    username,
                    password_hash,
                    role
                FROM users
                WHERE username = %s
                """,
                (username,),
            )
            user = cur.fetchone()

        # Sécurité : aucun crash possible ici
        if not user:
            flash("Identifiants incorrects.", "danger")
            return render_template("login.html")

        if not check_password_hash(user["password_hash"], password):
            flash("Identifiants incorrects.", "danger")
            return render_template("login.html")

        # Session SAFE
        session.clear()
        session["user"] = {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
        }
        session["csrf_token"] = secrets.token_hex(32)
        session.permanent = True

        flash("Connexion réussie.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Déconnexion effectuée.", "info")
    return redirect(url_for("login"))
###########################################################
# 8. DASHBOARD + SEARCH + OUVERTURE COTATION + CHIFFRE D’AFFAIRES
###########################################################

from datetime import datetime
from collections import defaultdict


# =========================
# DASHBOARD
# =========================
@app.route("/dashboard")
@login_required
def dashboard():

    conn = get_db()
    user = session.get("user") or {}

    role = user.get("role")
    user_id = user.get("id")
    username = user.get("username")

    with conn.cursor() as cur:

        cur.execute("SELECT COUNT(*) FROM crm_clients")
        total_clients = cur.fetchone()[0]

        cur.execute("""
            SELECT id, name, email, created_at
            FROM crm_clients
            ORDER BY created_at DESC
            LIMIT 5
        """)
        last_clients = [row_to_obj(r) for r in cur.fetchall()]

        cur.execute("SELECT COALESCE(SUM(montant),0) FROM revenus")
        total_ca = cur.fetchone()[0]

        cur.execute("""
            SELECT montant, date, commercial
            FROM revenus
            ORDER BY date::date DESC, id DESC
            LIMIT 1
        """)
        row = cur.fetchone()
        last_rev = row_to_obj(row) if row else None

    total_docs = 0
    if not LOCAL_MODE and s3:
        try:
            items = s3_list_all_objects(AWS_BUCKET)
            total_docs = len([
                i for i in items
                if i.get("Key") and not i["Key"].endswith("/")
            ])
        except Exception:
            total_docs = 0

    unread_cotations = 0
    cotations_admin = []

    if role == "admin":

        with conn.cursor() as cur:

            cur.execute("""
                SELECT COUNT(*)
                FROM cotations
                WHERE COALESCE(is_read,0)=0
            """)
            unread_cotations = cur.fetchone()[0]

            cur.execute("""
                SELECT
                    cotations.id,
                    cotations.client_id,
                    cotations.date_creation,
                    cotations.status,
                    crm_clients.name AS client_name
                FROM cotations
                LEFT JOIN crm_clients
                ON crm_clients.id = cotations.client_id
                WHERE COALESCE(cotations.is_read,0)=0
                ORDER BY cotations.date_creation DESC
            """)
            cotations_admin = [row_to_obj(r) for r in cur.fetchall()]

    pipeline = {
        "en_cours": 0,
        "en_attente": 0,
        "gagnes": 0,
        "perdus": 0
    }

    if role == "admin":

        with conn.cursor() as cur:

            cur.execute("""
                SELECT

                    COUNT(*) FILTER (
                        WHERE LOWER(COALESCE(status,'')) 
                        IN ('en_cours','nouveau','')
                    ) AS en_cours,

                    COUNT(*) FILTER (
                        WHERE LOWER(COALESCE(status,''))='en_attente'
                    ) AS en_attente,

                    COUNT(*) FILTER (
                        WHERE LOWER(COALESCE(status,''))='gagne'
                    ) AS gagnes,

                    COUNT(*) FILTER (
                        WHERE LOWER(COALESCE(status,''))='perdu'
                    ) AS perdus

                FROM crm_clients
            """)

            r = cur.fetchone()

        if r:
            pipeline["en_cours"] = r["en_cours"] or 0
            pipeline["en_attente"] = r["en_attente"] or 0
            pipeline["gagnes"] = r["gagnes"] or 0
            pipeline["perdus"] = r["perdus"] or 0

    pipeline_en_cours = []
    pipeline_en_attente = []
    pipeline_gagnes = []
    pipeline_perdus = []

    if role == "commercial":

        with conn.cursor() as cur:

            cur.execute("""
                SELECT id, name, status
                FROM crm_clients
                WHERE owner_id=%s
                ORDER BY created_at DESC
            """, (user_id,))

            rows = cur.fetchall()

        for r in rows:

            st = (r["status"] or "en_cours").lower()
            obj = row_to_obj(r)

            if st == "gagne":
                pipeline_gagnes.append(obj)

            elif st == "perdu":
                pipeline_perdus.append(obj)

            elif st == "en_attente":
                pipeline_en_attente.append(obj)

            else:
                pipeline_en_cours.append(obj)

    commercial_stats = None

    if role == "commercial":

        with conn.cursor() as cur:

            cur.execute(
                "SELECT COUNT(*) FROM crm_clients WHERE owner_id=%s",
                (user_id,)
            )
            nb_clients = cur.fetchone()[0]

            cur.execute(
                "SELECT COALESCE(SUM(montant),0) FROM revenus WHERE commercial=%s",
                (username,)
            )
            ca_total_com = cur.fetchone()[0]

            cur.execute("""
                SELECT COALESCE(SUM(montant),0)
                FROM revenus
                WHERE commercial=%s
                AND date_trunc('month', date::date)
                    = date_trunc('month', CURRENT_DATE)
            """, (username,))
            ca_mois_com = cur.fetchone()[0]

        commercial_stats = {
            "nb_clients": nb_clients,
            "ca_total": ca_total_com,
            "ca_mois": ca_mois_com,
            "cotations_attente": 0,
        }

    return render_template(
        "dashboard.html",
        total_clients=total_clients,
        total_ca=total_ca,
        total_docs=total_docs,
        last_clients=last_clients,
        last_rev=last_rev,
        unread_cotations=unread_cotations,
        cotations_admin=cotations_admin,
        commercial_stats=commercial_stats,
        pipeline=pipeline,
        pipeline_en_cours=pipeline_en_cours,
        pipeline_en_attente=pipeline_en_attente,
        pipeline_gagnes=pipeline_gagnes,
        pipeline_perdus=pipeline_perdus,
    )


# =========================================================
# CHIFFRE D'AFFAIRES
# =========================================================
@app.route("/chiffre-affaire")
@login_required
def chiffre_affaire():

    conn = get_db()
    user = session.get("user") or {}
    role = user.get("role")
    username = user.get("username")

    current_year = datetime.now().year

    try:
        selected_year = int(request.args.get("year", current_year))
    except Exception:
        selected_year = current_year

    selected_commercial = (request.args.get("commercial") or "").strip()
    selected_commercial = selected_commercial if selected_commercial else None

    where = []
    params = []

    if role == "commercial":
        where.append("r.commercial=%s")
        params.append(username)

    if role == "admin":

        where.append("EXTRACT(YEAR FROM r.date::date)=%s")
        params.append(selected_year)

        if selected_commercial:
            where.append("LOWER(r.commercial)=LOWER(%s)")
            params.append(selected_commercial)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    with conn.cursor() as cur:

        cur.execute(f"""
            SELECT
                r.id,
                r.date,
                r.commercial,
                r.dossier,
                r.client_id,
                r.montant,
                c.name AS client_name
            FROM revenus r
            LEFT JOIN crm_clients c ON c.id=r.client_id
            {where_sql}
            ORDER BY r.date DESC, r.id DESC
        """, tuple(params))

        rows = cur.fetchall()

    revenus = [row_to_obj(r) for r in rows]

    stats = defaultdict(lambda: defaultdict(float))
    ca_mensuel_par_commercial = defaultdict(lambda: defaultdict(float))
    totaux_par_commercial = defaultdict(float)

    for r in rows:

        try:

            d = r["date"]
            montant = float(r["montant"] or 0)
            commercial = r["commercial"] or "Inconnu"

            if d:

                stats[d.year][d.month] += montant

                if d.year == selected_year:
                    ca_mensuel_par_commercial[commercial][d.month] += montant
                    totaux_par_commercial[commercial] += montant

        except Exception:
            pass

    ca_total = 0
    ca_annuel_perso = 0
    ca_mensuel_perso = 0

    with conn.cursor() as cur:

        cur.execute("SELECT COALESCE(SUM(montant),0) FROM revenus")
        ca_total = cur.fetchone()[0] or 0

        if role == "commercial":

            cur.execute("""
                SELECT COALESCE(SUM(montant),0)
                FROM revenus
                WHERE commercial=%s
                AND date_trunc('year',date::date)
                    = date_trunc('year',CURRENT_DATE)
            """, (username,))
            ca_annuel_perso = cur.fetchone()[0] or 0

            cur.execute("""
                SELECT COALESCE(SUM(montant),0)
                FROM revenus
                WHERE commercial=%s
                AND date_trunc('month',date::date)
                    = date_trunc('month',CURRENT_DATE)
            """, (username,))
            ca_mensuel_perso = cur.fetchone()[0] or 0

        else:

            admin_where = ["EXTRACT(YEAR FROM date::date)=%s"]
            admin_params = [selected_year]

            if selected_commercial:
                admin_where.append("LOWER(commercial)=LOWER(%s)")
                admin_params.append(selected_commercial)

            admin_where_sql = " AND ".join(admin_where)

            cur.execute(f"""
                SELECT COALESCE(SUM(montant),0)
                FROM revenus
                WHERE {admin_where_sql}
            """, tuple(admin_params))

            ca_annuel_perso = cur.fetchone()[0] or 0

            cur.execute(f"""
                SELECT COALESCE(SUM(montant),0)
                FROM revenus
                WHERE {admin_where_sql}
                AND EXTRACT(MONTH FROM date::date)
                    = EXTRACT(MONTH FROM CURRENT_DATE)
            """, tuple(admin_params))

            ca_mensuel_perso = cur.fetchone()[0] or 0

    with conn.cursor() as cur:

        cur.execute("SELECT id,name FROM crm_clients ORDER BY name")
        clients = [row_to_obj(r) for r in cur.fetchall()]

    historique_ca = revenus

    return render_template(
        "chiffre_affaire.html",
        revenus=revenus,
        stats=stats,
        ca_total=ca_total,
        ca_annuel_perso=ca_annuel_perso,
        ca_mensuel_perso=ca_mensuel_perso,
        ca_mensuel_par_commercial=ca_mensuel_par_commercial,
        totaux_par_commercial=totaux_par_commercial,
        historique_ca=historique_ca,
        clients=clients,
        current_year=current_year,
        selected_year=selected_year,
        selected_commercial=selected_commercial
    )


# =========================================================
# AJOUT REVENU
# =========================================================
@app.route("/revenus/add", methods=["POST"], endpoint="add_revenu")
@login_required
def add_revenu():

    conn = get_db()
    user = session.get("user") or {}

    role = user.get("role")
    username = user.get("username")

    date_revenu = (request.form.get("date") or "").strip()
    commercial = (request.form.get("commercial") or "").strip()
    dossier = (request.form.get("dossier") or "").strip()
    client_id = request.form.get("client_id")
    montant = (request.form.get("montant") or "").strip()

    try:
        montant = float(montant)
    except Exception:
        flash("Montant invalide.", "danger")
        return redirect(url_for("chiffre_affaire"))

    if role == "commercial":
        commercial = username

    if not date_revenu or not montant:
        flash("Champs obligatoires manquants.", "danger")
        return redirect(url_for("chiffre_affaire"))

    try:

        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO revenus (
                    date,
                    commercial,
                    dossier,
                    client_id,
                    montant
                )
                VALUES (%s,%s,%s,%s,%s)
            """, (
                date_revenu,
                commercial,
                dossier,
                client_id if client_id else None,
                montant
            ))

        conn.commit()
        flash("Revenu ajouté avec succès.", "success")

    except Exception as e:

        conn.rollback()
        logger.exception("Erreur ajout revenu : %r", e)
        flash("Erreur lors de l'ajout.", "danger")

    return redirect(url_for("chiffre_affaire"))


# =========================================================
# SUPPRESSION REVENU
# =========================================================
@app.route("/revenus/<int:revenu_id>/delete", methods=["POST"], endpoint="delete_revenu")
@admin_required
def delete_revenu(revenu_id):

    conn = get_db()

    try:

        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM revenus WHERE id = %s",
                (revenu_id,)
            )

        conn.commit()
        flash("Chiffre d’affaires supprimé.", "success")

    except Exception as e:

        conn.rollback()
        logger.exception("Erreur suppression revenu : %r", e)
        flash("Erreur lors de la suppression.", "danger")

    return redirect(url_for("chiffre_affaire"))

############################################################
# 9. ADMIN — UTILISATEURS (GESTION COMPLÈTE ET SÉCURISÉE)
############################################################


@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():

    # =====================================================
    # 🧪 TEST TEMPORAIRE — À SUPPRIMER APRÈS VÉRIFICATION
    # =====================================================
    # return "<h1>ADMIN USERS OK</h1>"

    conn = get_db()

    # =====================================================
    # AJOUT UTILISATEUR (ADMIN / COMMERCIAL)
    # =====================================================
    if request.method == "POST":

        username = (request.form.get("username") or "").strip().lower()
        password = (request.form.get("password") or "").strip()
        role = (request.form.get("role") or "").strip()

        if not username or not password or role not in ("admin", "commercial"):
            flash("Champs invalides.", "danger")
            return redirect(url_for("admin_users"))

        if len(password) < 10:
            flash("Mot de passe trop court (min 10 caractères).", "danger")
            return redirect(url_for("admin_users"))

        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM users WHERE LOWER(username)=LOWER(%s)",
                (username,),
            )
            if cur.fetchone():
                flash("Nom d'utilisateur déjà utilisé.", "danger")
                return redirect(url_for("admin_users"))

        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO users (username, password_hash, role)
                    VALUES (%s, %s, %s)
                    """,
                    (
                        username,
                        generate_password_hash(password),
                        role,
                    ),
                )

            conn.commit()

            flash("Utilisateur créé avec succès.", "success")

        except Exception as e:
            conn.rollback()
            logger.exception("Erreur création utilisateur : %r", e)
            flash("Erreur lors de la création.", "danger")

        return redirect(url_for("admin_users"))

    # =====================================================
    # LISTE DES UTILISATEURS
    # =====================================================
    with conn.cursor() as cur:

        cur.execute(
            """
            SELECT id, username, role
            FROM users
            ORDER BY id ASC
            """
        )

        users = cur.fetchall()

    return render_template(
        "admin_users.html",
        users=[row_to_obj(u) for u in users],
    )


# =========================================================
# SUPPRESSION UTILISATEUR
# =========================================================
@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):

    # 🔒 Protection admin principal
    if user_id == 1:
        flash("Impossible de supprimer l’administrateur principal.", "danger")
        return redirect(url_for("admin_users"))

    conn = get_db()

    with conn.cursor() as cur:
        cur.execute(
            "SELECT id FROM users WHERE id=%s",
            (user_id,)
        )
        if not cur.fetchone():
            flash("Utilisateur introuvable.", "danger")
            return redirect(url_for("admin_users"))

    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM users WHERE id=%s",
                (user_id,)
            )

        conn.commit()

        flash("Utilisateur supprimé.", "success")

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur suppression utilisateur : %r", e)
        flash("Erreur lors de la suppression.", "danger")

    return redirect(url_for("admin_users"))


# =========================================================
# RESET MOT DE PASSE
# =========================================================
@app.route("/admin/users/<int:user_id>/reset_password", methods=["POST"])
@admin_required
def admin_reset_password(user_id):

    new_password = (request.form.get("new_password") or "").strip()

    if not new_password or len(new_password) < 10:
        flash("Mot de passe trop court (min 10 caractères).", "danger")
        return redirect(url_for("admin_users"))

    conn = get_db()

    with conn.cursor() as cur:
        cur.execute(
            "SELECT id FROM users WHERE id=%s",
            (user_id,)
        )
        if not cur.fetchone():
            flash("Utilisateur introuvable.", "danger")
            return redirect(url_for("admin_users"))

    try:

        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET password_hash = %s
                WHERE id = %s
                """,
                (
                    generate_password_hash(new_password),
                    user_id,
                ),
            )

        conn.commit()

        flash("Mot de passe réinitialisé.", "success")

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur reset password : %r", e)
        flash("Erreur lors de la réinitialisation.", "danger")

    return redirect(url_for("admin_users"))
############################################################
# 10. ADMIN — DEMANDES DE COTATION
############################################################

@app.route("/admin/cotations")
@admin_required
def admin_cotations():
    conn = get_db()

    with conn.cursor() as cur:
        cur.execute("""
            SELECT
                cotations.*,
                crm_clients.name AS client_name,
                users.username AS commercial_name
            FROM cotations
            LEFT JOIN crm_clients ON crm_clients.id = cotations.client_id
            LEFT JOIN users ON users.id = cotations.created_by
            ORDER BY cotations.date_creation DESC
        """)
        rows = cur.fetchall()

    return render_template(
        "admin_cotations.html",
        cotations=[row_to_obj(r) for r in rows],
    )


@app.route("/admin/cotations/<int:cotation_id>")
@admin_required
def admin_cotation_detail(cotation_id):
    conn = get_db()

    with conn.cursor() as cur:
        cur.execute("""
            SELECT
                cotations.*,
                crm_clients.name AS client_name,
                users.username AS commercial_name
            FROM cotations
            LEFT JOIN crm_clients ON crm_clients.id = cotations.client_id
            LEFT JOIN users ON users.id = cotations.created_by
            WHERE cotations.id = %s
        """, (cotation_id,))
        cotation = cur.fetchone()

    if not cotation:
        flash("Cotation introuvable.", "danger")
        return redirect(url_for("admin_cotations"))

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE cotations SET is_read = 1 WHERE id = %s",
            (cotation_id,)
        )
    conn.commit()
    cotation = dict(cotation)
    cotation["is_read"] = 1

    return render_template(
        "admin_cotation_detail.html",
        cotation=row_to_obj(cotation),
    )


@app.route("/admin/cotations/<int:cotation_id>/delete", methods=["POST"])
@admin_required
def delete_cotation_admin(cotation_id):
    conn = get_db()

    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM cotations WHERE id = %s",
            (cotation_id,)
        )

    conn.commit()
    flash("Cotation supprimée.", "success")
    return redirect(url_for("admin_cotations"))


############################################################
# 10 BIS. ADMIN — SUIVI DES DOSSIERS PAR COMMERCIAL
# - Route UNIQUE (pas de doublon)
# - Totaux fiables
# - Statuts métiers réels :
#   en_cours + nouveau + NULL => EN COURS
#   en_attente                 => EN ATTENTE
#   gagne                      => GAGNÉ
#   perdu                      => PERDU
############################################################

@app.route("/admin/dossiers")
@admin_required
def admin_dossiers():
    conn = get_db()

    with conn.cursor() as cur:
        cur.execute("""
            SELECT
                u.id AS commercial_id,
                u.username AS commercial,

                COUNT(*) FILTER (
                    WHERE
                        c.id IS NOT NULL
                        AND LOWER(COALESCE(c.status,'')) IN ('en_cours','nouveau','')
                ) AS en_cours,

                COUNT(*) FILTER (
                    WHERE LOWER(COALESCE(c.status,''))='en_attente'
                ) AS en_attente,

                COUNT(*) FILTER (
                    WHERE LOWER(COALESCE(c.status,''))='gagne'
                ) AS gagnes,

                COUNT(*) FILTER (
                    WHERE LOWER(COALESCE(c.status,''))='perdu'
                ) AS perdus

            FROM users u
            LEFT JOIN crm_clients c ON c.owner_id = u.id
            WHERE u.role = 'commercial'
            GROUP BY u.id, u.username
            ORDER BY u.username
        """)
        rows = cur.fetchall()

    stats = []

    for r in rows:
        obj = row_to_obj(r)

        # Total fiable
        obj.total = (
            (obj.en_cours or 0)
            + (obj.en_attente or 0)
            + (obj.gagnes or 0)
            + (obj.perdus or 0)
        )

        stats.append(obj)

    return render_template(
        "admin_dossiers.html",
        stats=stats,
    )


############################################################
# 10 BIS (DETAIL). ADMIN — DÉTAIL DES DOSSIERS PAR COMMERCIAL
# URL : /admin/dossiers/<username>
############################################################

@app.route("/admin/dossiers/<string:commercial>")
@admin_required
def admin_dossiers_detail(commercial):

    commercial = (commercial or "").strip()

    if not commercial:
        return redirect(url_for("admin_dossiers"))

    conn = get_db()

    # 🔒 Vérifie que le commercial existe
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, username
            FROM users
            WHERE role = 'commercial'
              AND username = %s
        """, (commercial,))
        user = cur.fetchone()

    if not user:
        flash("Commercial introuvable.", "danger")
        return redirect(url_for("admin_dossiers"))

    commercial_id = user["id"]

    # 📂 Récupération des dossiers du commercial
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, name, status, created_at
            FROM crm_clients
            WHERE owner_id = %s
            ORDER BY
                CASE LOWER(COALESCE(status,''))
                    WHEN 'en_cours' THEN 1
                    WHEN 'nouveau' THEN 1
                    WHEN '' THEN 1
                    WHEN 'en_attente' THEN 2
                    WHEN 'gagne' THEN 3
                    WHEN 'perdu' THEN 4
                    ELSE 5
                END,
                created_at DESC
        """, (commercial_id,))
        rows = cur.fetchall()

    en_cours = []
    en_attente = []
    gagnes = []
    perdus = []

    for r in rows:

        st = (r["status"] or "en_cours").lower()

        if st == "gagne":
            gagnes.append(row_to_obj(r))

        elif st == "perdu":
            perdus.append(row_to_obj(r))

        elif st == "en_attente":
            en_attente.append(row_to_obj(r))

        else:
            # en_cours + nouveau + NULL
            en_cours.append(row_to_obj(r))

    return render_template(
        "admin_dossiers_detail.html",
        commercial=row_to_obj(user),
        en_cours=en_cours,
        en_attente=en_attente,
        gagnes=gagnes,
        perdus=perdus,
    )
############################################################
# 10 TER. ADMIN — PLANNING (COTATIONS & MISES À JOUR)
############################################################

def render_planning_hub():
    ensure_planning_schema()

    user = session.get("user") or {}
    planning_bootstrap = {
        "current_user": {
            "id": user.get("id"),
            "username": user.get("username"),
            "role": user.get("role"),
            "role_label": chat_role_label(user.get("role")),
        },
        "users": list_planning_users(),
        "categories": [
            {"value": key, "label": meta["label"], "color": meta["color"]}
            for key, meta in PLANNING_EVENT_CATEGORIES.items()
        ],
        "statuses": [
            {"value": key, "label": label}
            for key, label in PLANNING_EVENT_STATUSES.items()
        ],
        "visibilities": [
            {"value": key, "label": label}
            for key, label in PLANNING_EVENT_VISIBILITIES.items()
        ],
        "source_styles": PLANNING_SOURCE_STYLES,
        "can_manage_all": user.get("role") == "admin",
    }

    return render_template(
        "planning_hub.html",
        planning_bootstrap=planning_bootstrap,
    )


@app.route("/admin/planning")
@admin_required
def admin_planning():
    return render_planning_hub()


# ===============================
# AJOUT EVENEMENT CALENDRIER
# Admin + commerciaux
# ===============================
@app.route("/calendar/add", methods=["POST"], endpoint="add_calendar_event")
@login_required
def add_calendar_event():

    conn = get_db()
    user = session.get("user") or {}
    role = user.get("role")

    title = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip()
    event_date = (request.form.get("event_date") or "").strip()

    start_time = (request.form.get("start_time") or "").strip()
    end_time = (request.form.get("end_time") or "").strip()

    all_day = request.form.get("all_day") in ("on", "1", "true")

    if not title or not event_date:
        flash("Titre et date obligatoires.", "danger")

        if role == "admin":
            return redirect(url_for("admin_planning"))

        return redirect(url_for("planning"))

    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO calendar_events (
                    title,
                    description,
                    event_date,
                    event_time,
                    end_time,
                    all_day,
                    created_by
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (
                title,
                description or None,
                event_date,
                start_time if start_time else None,
                end_time if end_time else None,
                all_day,
                user.get("id")
            ))

        conn.commit()
        flash("Rendez-vous ajouté au planning.", "success")

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur ajout rendez-vous calendrier : %r", e)
        flash("Erreur lors de l'ajout du rendez-vous.", "danger")

    if role == "admin":
        return redirect(url_for("admin_planning"))

    return redirect(url_for("planning"))


# ===============================
# COMPATIBILITÉ ANCIENNE URL ADMIN
# ===============================
@app.route("/admin/calendar/add", methods=["POST"], endpoint="add_calendar_event_admin_legacy")
@admin_required
def add_calendar_event_admin_legacy():
    return add_calendar_event()

############################################################
# 10 TER BIS. PLANNING COMMERCIAL (AGENDA)
############################################################

@app.route("/planning")
@planning_required
def planning():
    return render_planning_hub()
    if False:
        pass
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    id,
                    title,
                    description,
                    event_date,
                    event_time,
                    end_time,
                    all_day
                FROM calendar_events
                WHERE event_date IS NOT NULL
                  AND event_date >= CURRENT_DATE
                ORDER BY event_date ASC
            """)
            rows = cur.fetchall()

        events = [row_to_obj(r) for r in rows]

    except Exception as e:
        logger.exception("Erreur chargement events planning commercial : %r", e)
        events = []

    return render_template(
        "calendar.html",  # ✅ FIX ICI
        cotations=[row_to_obj(c) for c in cotations],
        updates=[row_to_obj(u) for u in updates],
        events=events
    )


############################################################
# SUPPRESSION EVENEMENT CALENDRIER
############################################################
@app.route("/admin/calendar/<int:event_id>/delete", methods=["POST"])
@admin_required
def delete_calendar_event(event_id):

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM calendar_events WHERE id = %s",
                (event_id,)
            )

        conn.commit()

        flash("Événement supprimé.", "success")

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur suppression evenement calendrier : %r", e)
        flash("Erreur lors de la suppression.", "danger")

    return redirect(url_for("admin_planning"))
############################################################
# 10 TER BIS. API CALENDRIER — NEGOCIATIONS + UPDATES
############################################################

@app.route("/api/calendar")
@login_required
def api_calendar():

    conn = get_db()
    user = session.get("user") or {}

    role = user.get("role")
    user_id = user.get("id")
    username = user.get("username")

    with conn.cursor() as cur:

        # =========================
        # ADMIN → voit tout
        # =========================
        if role == "admin":

            cur.execute("""
                SELECT
                    cotations.id,
                    cotations.date_negociation,
                    cotations.heure_negociation,
                    crm_clients.name AS client_name,
                    users.username AS commercial_name
                FROM cotations
                LEFT JOIN crm_clients
                    ON crm_clients.id = cotations.client_id
                LEFT JOIN users
                    ON users.id = cotations.created_by
                WHERE cotations.date_negociation IS NOT NULL
            """)

        # =========================
        # COMMERCIAL → voit SES dossiers (FIX)
        # =========================
        else:

            cur.execute("""
                SELECT
                    cotations.id,
                    cotations.date_negociation,
                    cotations.heure_negociation,
                    crm_clients.name AS client_name,
                    users.username AS commercial_name
                FROM cotations
                JOIN crm_clients
                    ON crm_clients.id = cotations.client_id
                LEFT JOIN users
                    ON users.id = cotations.created_by
                WHERE cotations.date_negociation IS NOT NULL
                  AND crm_clients.owner_id = %s
            """, (user_id,))

        cotations = cur.fetchall()

    events = []

    # =====================================================
    # NEGOCIATIONS
    # =====================================================
    for r in cotations:

        date_negociation = r.get("date_negociation")
        heure_negociation = r.get("heure_negociation")

        if not date_negociation:
            continue

        if heure_negociation:
            start = f"{date_negociation}T{heure_negociation}"
        else:
            start = str(date_negociation)

        events.append({
            "id": f"cotation_{r['id']}",
            "title": f"{r.get('client_name') or ''} - {r.get('commercial_name') or ''}",
            "start": start,
            "color": "#3b82f6"
        })

    # =====================================================
    # MISES À JOUR CLIENT
    # =====================================================
    try:

        with conn.cursor() as cur:

            if role == "admin":
                cur.execute("""
                    SELECT id, update_date, commentaire, client_name
                    FROM client_updates
                    WHERE update_date IS NOT NULL
                """)
            else:
                cur.execute("""
                    SELECT id, update_date, commentaire, client_name
                    FROM client_updates
                    WHERE update_date IS NOT NULL
                      AND commercial_name = %s
                """, (username,))

            updates = cur.fetchall()

        for r in updates:

            update_date = r.get("update_date")

            if not update_date:
                continue

            events.append({
                "id": f"update_{r['id']}",
                "title": f"MAJ - {r.get('client_name') or ''}",
                "start": str(update_date),
                "color": "#f59e0b"
            })

    except Exception as e:
        logger.exception("Erreur updates calendrier : %r", e)

    # =====================================================
    # EVENEMENTS ADMIN
    # =====================================================
    try:

        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    id,
                    title,
                    event_date,
                    event_time,
                    end_time,
                    all_day
                FROM calendar_events
            """)
            rows = cur.fetchall()

        for r in rows:

            event_date = r.get("event_date")

            if not event_date:
                continue

            if r.get("all_day"):

                events.append({
                    "id": f"event_{r['id']}",
                    "title": r.get("title") or "",
                    "start": str(event_date),
                    "allDay": True,
                })

            else:

                event_time = r.get("event_time")
                end_time = r.get("end_time")

                if event_time:
                    start = f"{event_date}T{event_time}"
                else:
                    start = str(event_date)

                end = None
                if end_time:
                    end = f"{event_date}T{end_time}"

                events.append({
                    "id": f"event_{r['id']}",
                    "title": r.get("title") or "",
                    "start": start,
                    "end": end,
                    "allDay": False,
                })

    except Exception as e:
        logger.exception("Erreur chargement events API calendar : %r", e)

    return jsonify(events)


def planning_request_date(value):
    raw = (value or "").strip()
    if not raw:
        return None
    return parse_date_safe(raw[:10])


def planning_date_window():
    start_date = planning_request_date(request.args.get("start"))
    end_date = planning_request_date(request.args.get("end"))

    if not start_date:
        start_date = date.today() - timedelta(days=7)

    if not end_date:
        end_date = date.today() + timedelta(days=90)

    return start_date, end_date


def planning_actor_name(row, fallback="Non assigne"):
    name = (row.get("commercial_name") or "").strip()
    return name or fallback


def planning_client_name(row, fallback="Client"):
    name = (row.get("client_name") or "").strip()
    return name or fallback


def planning_external_title(prefix, row):
    client_name = planning_client_name(row)
    commercial_name = planning_actor_name(row)
    return f"{prefix} - {client_name} - {commercial_name}"


def serialize_cotation_planning_event(row):
    start_value = str(row["date_negociation"])
    all_day = True

    if row.get("heure_negociation"):
        start_value = f"{row['date_negociation']}T{row['heure_negociation']}"
        all_day = False

    color = planning_event_color(source_kind="cotation", category="negociation")
    text_color = planning_event_text_color(color)

    return {
        "id": f"cotation_{row['id']}",
        "title": planning_external_title("Negociation", row),
        "start": start_value,
        "allDay": all_day,
        "backgroundColor": color,
        "borderColor": color,
        "textColor": text_color,
        "editable": False,
        "classNames": ["planning-event", "planning-source-cotation"],
        "extendedProps": {
            "entityId": row["id"],
            "sourceKind": "cotation",
            "sourceLabel": PLANNING_SOURCE_STYLES["cotation"]["label"],
            "description": (
                f"Negociation programmee automatiquement pour {planning_client_name(row)}. "
                f"Commercial : {planning_actor_name(row)}."
            ),
            "location": "",
            "category": "negociation",
            "categoryLabel": planning_category_label("negociation"),
            "status": "confirmed",
            "statusLabel": planning_status_label("confirmed"),
            "visibility": "assigned",
            "visibilityLabel": planning_actor_name(row, "Commercial"),
            "createdById": row.get("commercial_id"),
            "createdByName": planning_actor_name(row, ""),
            "assignedToId": row.get("commercial_id"),
            "assignedToName": planning_actor_name(row, ""),
            "ownerUserId": row.get("commercial_id"),
            "ownerLabel": planning_actor_name(row, ""),
            "clientName": planning_client_name(row),
            "commercialName": planning_actor_name(row, ""),
            "titleFull": planning_external_title("Negociation", row),
            "routeUrl": (
                url_for("client_detail", client_id=row["client_id"])
                if row.get("client_id")
                else None
            ),
            "canEdit": False,
            "canDelete": False,
            "color": color,
            "textColor": text_color,
        },
    }


def serialize_update_planning_event(row):
    color = planning_event_color(source_kind="update", category="relance")
    text_color = planning_event_text_color(color)

    return {
        "id": f"update_{row['id']}",
        "title": planning_external_title("Mise a jour", row),
        "start": str(row["update_date"]),
        "allDay": True,
        "backgroundColor": color,
        "borderColor": color,
        "textColor": text_color,
        "editable": False,
        "classNames": ["planning-event", "planning-source-update"],
        "extendedProps": {
            "entityId": row["id"],
            "sourceKind": "update",
            "sourceLabel": PLANNING_SOURCE_STYLES["update"]["label"],
            "description": (
                row.get("commentaire")
                or f"Mise a jour programmee pour {planning_client_name(row)}. "
                   f"Commercial : {planning_actor_name(row)}."
            ),
            "location": "",
            "category": "relance",
            "categoryLabel": planning_category_label("relance"),
            "status": "confirmed",
            "statusLabel": planning_status_label("confirmed"),
            "visibility": "assigned",
            "visibilityLabel": planning_actor_name(row, "Commercial"),
            "createdById": row.get("commercial_id"),
            "createdByName": planning_actor_name(row, ""),
            "assignedToId": row.get("commercial_id"),
            "assignedToName": planning_actor_name(row, ""),
            "ownerUserId": row.get("commercial_id"),
            "ownerLabel": planning_actor_name(row, ""),
            "clientName": planning_client_name(row),
            "commercialName": planning_actor_name(row, ""),
            "titleFull": planning_external_title("Mise a jour", row),
            "routeUrl": (
                url_for("client_detail", client_id=row["client_id"])
                if row.get("client_id")
                else None
            ),
            "canEdit": False,
            "canDelete": False,
            "color": color,
            "textColor": text_color,
        },
    }


@app.route("/api/planning/events")
@planning_required
def api_planning_events():
    ensure_planning_schema()

    user = session.get("user") or {}
    role = user.get("role")
    user_id = user.get("id")
    start_date, end_date = planning_date_window()

    conn = get_db()
    events = []

    try:
        with conn.cursor() as cur:
            if role == "admin":
                cur.execute("""
                    SELECT
                        cotations.id,
                        cotations.client_id,
                        cotations.date_negociation,
                        cotations.heure_negociation,
                        crm_clients.name AS client_name,
                        COALESCE(crm_clients.owner_id, cotations.created_by) AS commercial_id,
                        users.username AS commercial_name
                    FROM cotations
                    LEFT JOIN crm_clients ON crm_clients.id = cotations.client_id
                    LEFT JOIN users ON users.id = COALESCE(crm_clients.owner_id, cotations.created_by)
                    WHERE cotations.date_negociation IS NOT NULL
                      AND cotations.date_negociation >= %s
                      AND cotations.date_negociation < %s
                """, (start_date, end_date))
            else:
                cur.execute("""
                    SELECT
                        cotations.id,
                        cotations.client_id,
                        cotations.date_negociation,
                        cotations.heure_negociation,
                        crm_clients.name AS client_name,
                        COALESCE(crm_clients.owner_id, cotations.created_by) AS commercial_id,
                        users.username AS commercial_name
                    FROM cotations
                    LEFT JOIN crm_clients ON crm_clients.id = cotations.client_id
                    LEFT JOIN users ON users.id = COALESCE(crm_clients.owner_id, cotations.created_by)
                    WHERE cotations.date_negociation IS NOT NULL
                      AND cotations.date_negociation >= %s
                      AND cotations.date_negociation < %s
                      AND COALESCE(crm_clients.owner_id, cotations.created_by) = %s
                """, (start_date, end_date, user_id))

            cotations = cur.fetchall()

        for row in cotations:
            events.append(serialize_cotation_planning_event(row))

        with conn.cursor() as cur:
            if role == "admin":
                cur.execute("""
                    SELECT
                        id,
                        client_id,
                        client_name,
                        commercial_id,
                        commercial_name,
                        update_date,
                        commentaire
                    FROM client_updates
                    WHERE update_date IS NOT NULL
                      AND update_date >= %s
                      AND update_date < %s
                """, (start_date, end_date))
            else:
                cur.execute("""
                    SELECT
                        id,
                        client_id,
                        client_name,
                        commercial_id,
                        commercial_name,
                        update_date,
                        commentaire
                    FROM client_updates
                    WHERE update_date IS NOT NULL
                      AND update_date >= %s
                      AND update_date < %s
                      AND commercial_id = %s
                """, (start_date, end_date, user_id))

            updates = cur.fetchall()

        for row in updates:
            events.append(serialize_update_planning_event(row))

        with conn.cursor() as cur:
            manual_sql = """
                SELECT
                    ce.*,
                    creator.username AS created_by_username,
                    creator.role AS created_by_role,
                    assignee.username AS assigned_to_username,
                    assignee.role AS assigned_to_role
                FROM calendar_events ce
                LEFT JOIN users creator ON creator.id = ce.created_by
                LEFT JOIN users assignee ON assignee.id = ce.assigned_to
                WHERE ce.event_date < %s
                  AND COALESCE(ce.end_date, ce.event_date) >= %s
            """
            params = [end_date, start_date]

            if role != "admin":
                manual_sql += """
                  AND (
                      ce.created_by = %s
                      OR ce.assigned_to = %s
                      OR COALESCE(ce.visibility, 'private') = 'team'
                  )
                """
                params.extend([user_id, user_id])

            manual_sql += " ORDER BY ce.event_date ASC, COALESCE(ce.event_time, TIME '00:00') ASC"
            cur.execute(manual_sql, tuple(params))
            manual_rows = cur.fetchall()

        for row in manual_rows:
            if planning_event_can_view(row, user):
                events.append(serialize_manual_planning_event(row, user))

        events.sort(key=lambda item: (item.get("start") or "", item.get("title") or ""))

        return jsonify({
            "success": True,
            "events": events,
        })

    except Exception as e:
        logger.exception("Erreur agenda planning : %r", e)
        return jsonify({
            "success": False,
            "events": [],
            "message": "Impossible de charger l'agenda.",
        }), 500


@app.route("/api/planning/events", methods=["POST"])
@planning_required
def create_planning_event():
    ensure_planning_schema()

    user = session.get("user") or {}
    payload = request.get_json(silent=True) or request.form
    event_payload, error = planning_build_payload(payload, user)

    if error:
        return jsonify({"success": False, "message": error}), 400

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO calendar_events (
                    title,
                    description,
                    event_date,
                    end_date,
                    event_time,
                    end_time,
                    all_day,
                    location,
                    category,
                    status,
                    visibility,
                    color,
                    created_by,
                    assigned_to
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                event_payload["title"],
                event_payload["description"],
                event_payload["event_date"],
                event_payload["end_date"],
                event_payload["event_time"],
                event_payload["end_time"],
                event_payload["all_day"],
                event_payload["location"],
                event_payload["category"],
                event_payload["status"],
                event_payload["visibility"],
                event_payload["color"],
                user.get("id"),
                event_payload["assigned_to"],
            ))
            created_id = cur.fetchone()["id"]

        conn.commit()

        row = fetch_calendar_event_row(created_id)

        return jsonify({
            "success": True,
            "event": serialize_manual_planning_event(row, user),
        })

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur creation evenement agenda : %r", e)
        return jsonify({
            "success": False,
            "message": "Impossible de creer le rendez-vous.",
        }), 500


@app.route("/api/planning/events/<int:event_id>/update", methods=["POST"])
@planning_required
def update_planning_event(event_id):
    ensure_planning_schema()

    user = session.get("user") or {}
    existing = fetch_calendar_event_row(event_id)

    if not existing:
        return jsonify({"success": False, "message": "Rendez-vous introuvable."}), 404

    if not planning_event_can_edit(existing, user):
        return jsonify({"success": False, "message": "Modification non autorisee."}), 403

    payload = request.get_json(silent=True) or request.form
    event_payload, error = planning_build_payload(payload, user)

    if error:
        return jsonify({"success": False, "message": error}), 400

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE calendar_events
                SET
                    title = %s,
                    description = %s,
                    event_date = %s,
                    end_date = %s,
                    event_time = %s,
                    end_time = %s,
                    all_day = %s,
                    location = %s,
                    category = %s,
                    status = %s,
                    visibility = %s,
                    color = %s,
                    assigned_to = %s
                WHERE id = %s
            """, (
                event_payload["title"],
                event_payload["description"],
                event_payload["event_date"],
                event_payload["end_date"],
                event_payload["event_time"],
                event_payload["end_time"],
                event_payload["all_day"],
                event_payload["location"],
                event_payload["category"],
                event_payload["status"],
                event_payload["visibility"],
                event_payload["color"],
                event_payload["assigned_to"],
                event_id,
            ))

        conn.commit()

        row = fetch_calendar_event_row(event_id)

        return jsonify({
            "success": True,
            "event": serialize_manual_planning_event(row, user),
        })

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur modification evenement agenda : %r", e)
        return jsonify({
            "success": False,
            "message": "Impossible de modifier le rendez-vous.",
        }), 500


@app.route("/api/planning/events/<int:event_id>/delete", methods=["POST"])
@planning_required
def remove_planning_event(event_id):
    ensure_planning_schema()

    user = session.get("user") or {}
    existing = fetch_calendar_event_row(event_id)

    if not existing:
        return jsonify({"success": False, "message": "Rendez-vous introuvable."}), 404

    if not planning_event_can_edit(existing, user):
        return jsonify({"success": False, "message": "Suppression non autorisee."}), 403

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM calendar_events WHERE id = %s", (event_id,))

        conn.commit()

        return jsonify({"success": True})

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur suppression evenement agenda : %r", e)
        return jsonify({
            "success": False,
            "message": "Impossible de supprimer le rendez-vous.",
        }), 500
###########################################################
# 11. DOCUMENTS (GLOBAL + PAR DOSSIER + RESSOURCES PARTAGÉES)
############################################################

import io
import zipfile
from flask import send_file

GLOBAL_PREFIX = "clients/global/"
SHARED_PREFIX = "clients/shared/"
SHARED_CATEGORIES = ("mandats", "resiliations")

MAX_MULTI_DOWNLOAD = 20


# =========================================================
# LISTE GLOBALE DOCUMENTS (ADMIN)
# =========================================================
@app.route("/documents")
@admin_required
def documents():
    fichiers = []

    if LOCAL_MODE or not s3:
        return render_template("documents.html", fichiers=fichiers)

    try:
        items = s3_list_all_objects(AWS_BUCKET, prefix="clients/")

        for item in items:
            key = item.get("Key")
            if not key or key.endswith("/"):
                continue

            preview_meta = build_document_preview_meta(key)
            fichiers.append({
                "nom": key,
                "key": key,
                "taille": item.get("Size", 0),
                "date": item.get("LastModified"),
                "preview_kind": preview_meta["preview_kind"],
                "previewable": preview_meta["previewable"],
                "url": None,
            })

    except Exception as e:
        logger.exception("❌ Erreur chargement documents S3 : %r", e)
        flash("Impossible de charger les documents.", "danger")

    return render_template("documents.html", fichiers=fichiers)


# =========================================================
# UPLOAD DOCUMENT GLOBAL (ADMIN ONLY)
# =========================================================
@app.route("/documents/upload", methods=["POST"], endpoint="upload_document")
@admin_required
def upload_document():
    fichier = request.files.get("file")

    if not fichier or not getattr(fichier, "filename", ""):
        flash("Fichier invalide.", "danger")
        return redirect(url_for("documents"))

    if not allowed_file(fichier.filename):
        flash("Fichier invalide.", "danger")
        return redirect(url_for("documents"))

    if LOCAL_MODE or not s3:
        flash("Upload indisponible en mode local.", "warning")
        return redirect(url_for("documents"))

    try:
        original_name = secure_filename(fichier.filename) or "document"
        filename = clean_filename(original_name)

        key = _s3_make_non_overwriting_key(
            AWS_BUCKET,
            f"{GLOBAL_PREFIX}{filename}"
        )

        s3_upload_fileobj(fichier, AWS_BUCKET, key)

        flash("Document global uploadé.", "success")

    except Exception as e:
        logger.exception("❌ Erreur upload document global : %r", e)
        flash("Erreur lors de l’upload.", "danger")

    return redirect(url_for("documents"))


# =========================================================
# UPLOAD DOCUMENT PAR DOSSIER CLIENT
# =========================================================
@app.route(
    "/clients/<int:client_id>/documents/upload",
    methods=["POST"],
    endpoint="upload_client_document",
)
@login_required
def upload_client_document(client_id):

    if not can_access_client(client_id):
        abort(403)

    if LOCAL_MODE or not s3:
        flash("Upload indisponible en mode local.", "warning")
        return redirect(url_for("client_detail", client_id=client_id))

    files = request.files.getlist("files")

    doc_name = (request.form.get("doc_name") or "").strip()
    doc_kind = normalize_document_kind(request.form.get("doc_kind") or "")
    auto_name = (request.form.get("auto_name") or "").strip().lower() in {"1", "true", "on", "yes"}
    pdl = re.sub(r"[^0-9]", "", (request.form.get("pdl") or ""))

    if not files:
        legacy = request.files.get("file")
        if legacy:
            files = [legacy]

    files = [f for f in files if f and getattr(f, "filename", "")]

    if not files:
        flash("Aucun fichier sélectionné.", "danger")
        return redirect(url_for("client_detail", client_id=client_id))

    success_count = 0
    failed = []
    client_name = ""

    if auto_name:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT name FROM crm_clients WHERE id = %s",
                (client_id,),
            )
            row = cur.fetchone()
        client_name = (row.get("name") or "").strip() if row else ""

    prefix = client_s3_prefix(client_id, client_name or None)

    for fichier in files:

        if not allowed_file(fichier.filename):
            failed.append(fichier.filename or "fichier_invalide")
            continue

        try:
            original_name = secure_filename(fichier.filename) or "document"
            ext = os.path.splitext(original_name)[1].lower()
            base_name = build_document_upload_base_name(
                client_name or f"client_{client_id}",
                original_name,
                manual_name=doc_name,
                doc_kind=doc_kind,
                auto_name=auto_name,
                extra_suffix=pdl,
            )
            filename = f"{base_name}{ext}"
            key = _s3_make_non_overwriting_key(
                AWS_BUCKET,
                f"{prefix}{filename}"
            )

            s3_upload_fileobj(fichier, AWS_BUCKET, key)

            success_count += 1

        except Exception as e:
            logger.exception("❌ Erreur upload document client : %r", e)
            failed.append(fichier.filename or "fichier_erreur")

    if success_count > 0 and not failed:
        flash(f"{success_count} document(s) ajouté(s).", "success")
    elif success_count > 0:
        flash(f"{success_count} OK, {len(failed)} échecs.", "warning")
    else:
        flash("Aucun upload réussi.", "danger")

    return redirect(url_for("client_detail", client_id=client_id))


############################################################
# 11 BIS. RESSOURCES PARTAGÉES
############################################################

@app.route("/ressources")
@login_required
def shared_resources():

    fichiers = []

    if LOCAL_MODE or not s3:
        return render_template("ressources.html", fichiers=fichiers)

    try:
        items = s3_list_all_objects(AWS_BUCKET, prefix=SHARED_PREFIX)

        for item in items:
            key = item.get("Key")

            if not key or key.endswith("/"):
                continue

            preview_meta = build_document_preview_meta(key)
            fichiers.append({
                "nom": key.replace(SHARED_PREFIX, "", 1),
                "key": key,
                "taille": item.get("Size", 0),
                "date": item.get("LastModified"),
                "preview_kind": preview_meta["preview_kind"],
                "previewable": preview_meta["previewable"],
            })

    except Exception as e:
        logger.exception("Erreur ressources : %r", e)

    return render_template("ressources.html", fichiers=fichiers)


# ===============================
# UPLOAD RESSOURCES PARTAGÉES
# Stockage simple sans catégorie
# ===============================
@app.route("/ressources/upload", methods=["POST"], endpoint="shared_resources_upload")
@login_required
def shared_resources_upload():

    if LOCAL_MODE or not s3:
        flash("Upload indisponible en mode local.", "warning")
        return redirect(url_for("shared_resources"))

    fichier = request.files.get("file")

    if not fichier or not getattr(fichier, "filename", ""):
        flash("Fichier invalide.", "danger")
        return redirect(url_for("shared_resources"))

    if not allowed_file(fichier.filename):
        flash("Type de fichier non autorisé.", "danger")
        return redirect(url_for("shared_resources"))

    try:
        doc_name = (request.form.get("doc_name") or "").strip()
        original_name = secure_filename(fichier.filename) or "document"
        ext = os.path.splitext(original_name)[1].lower()

        if doc_name:
            base_name = os.path.splitext(clean_filename(doc_name))[0]
        else:
            base_name = os.path.splitext(clean_filename(original_name))[0]

        if not base_name:
            base_name = "document"

        filename = f"{base_name}{ext}"

        key = _s3_make_non_overwriting_key(
            AWS_BUCKET,
            f"{SHARED_PREFIX}{filename}"
        )

        s3_upload_fileobj(fichier, AWS_BUCKET, key)

        flash("Document ajouté aux ressources partagées.", "success")

    except Exception as e:
        logger.exception("Erreur upload ressource partagée : %r", e)
        flash("Erreur lors de l’upload.", "danger")

    return redirect(url_for("shared_resources"))

def _shared_resources_upload_endpoint():

    if LOCAL_MODE or not s3:
        flash("Upload indisponible en mode local.", "warning")
        return redirect(url_for("shared_resources"))

    files = request.files.getlist("files")
    if not files:
        legacy_file = request.files.get("file")
        if legacy_file and getattr(legacy_file, "filename", ""):
            files = [legacy_file]

    files = [f for f in files if f and getattr(f, "filename", "")]

    if not files:
        flash("Fichier invalide.", "danger")
        return redirect(url_for("shared_resources"))

    try:
        doc_name = (request.form.get("doc_name") or "").strip()
        success_count = 0
        failed = []

        for index, fichier in enumerate(files):
            if not allowed_file(fichier.filename):
                failed.append(fichier.filename or "fichier_invalide")
                continue

            original_name = secure_filename(fichier.filename) or "document"
            ext = os.path.splitext(original_name)[1].lower()

            if doc_name and len(files) == 1:
                base_name = os.path.splitext(clean_filename(doc_name))[0]
            else:
                base_name = os.path.splitext(clean_filename(original_name))[0]

            if not base_name:
                base_name = "document"

            if doc_name and len(files) > 1:
                base_name = f"{base_name}_{index + 1}"

            filename = f"{base_name}{ext}"

            key = _s3_make_non_overwriting_key(
                AWS_BUCKET,
                f"{SHARED_PREFIX}{filename}"
            )

            s3_upload_fileobj(fichier, AWS_BUCKET, key)
            success_count += 1

        if success_count > 0 and not failed:
            flash(f"{success_count} ressource(s) ajoutee(s).", "success")
        elif success_count > 0:
            flash(f"{success_count} ressource(s) ajoutee(s), {len(failed)} echec(s).", "warning")
        else:
            flash("Aucune ressource n'a pu etre ajoutee.", "danger")

    except Exception as e:
        logger.exception("Erreur upload ressource partagee : %r", e)
        flash("Erreur lors de l'upload.", "danger")

    return redirect(url_for("shared_resources"))


app.view_functions["shared_resources_upload"] = login_required(_shared_resources_upload_endpoint)


# ===============================
# COMPAT URL /resources
# ===============================
@app.route("/resources")
@login_required
def resources_redirect():
    return redirect(url_for("shared_resources"))


###########################################################
# 12. CLIENTS (LISTE / CRÉATION / DÉTAIL / MODIFICATION)
# + STATUT + COTATIONS + DELETE CLIENT + TIMELINE FR
# + DOCUMENTS (UPLOAD / DOWNLOAD / DELETE)
# ✅ VERSION FINALE STABLE (CORRIGÉE)
############################################################

from datetime import datetime
import re


# =========================
# SAFE PARSE
# =========================
def parse_date_safe(val):
    try:
        return datetime.strptime(val, "%Y-%m-%d").date()
    except Exception:
        return None


def parse_time_safe(val):
    try:
        return datetime.strptime(val, "%H:%M").time()
    except Exception:
        return None


def parse_int_safe(val):
    try:
        return int(val)
    except Exception:
        return None


def parse_amount_safe(val):
    try:
        cleaned = (val or "").strip()
        if not cleaned:
            return 0.0

        cleaned = (
            cleaned
            .replace("\xa0", "")
            .replace(" ", "")
            .replace(",", ".")
        )

        amount = float(cleaned)
        if amount < 0:
            return None

        return amount
    except Exception:
        return None


# =========================
# FORMAT DATE FR
# =========================
def format_datetime_fr(value, with_time=True):
    if not value:
        return "—"
    try:
        if with_time:
            return value.strftime("%d/%m/%Y à %H:%M")
        return value.strftime("%d/%m/%Y")
    except Exception:
        return "—"


# =========================
# CLIENT — LISTE
# =========================
@app.route("/clients", endpoint="clients")
@login_required
def clients():

    conn = get_db()
    q = (request.args.get("q") or "").strip()

    user = session.get("user") or {}
    role = user.get("role")
    user_id = user.get("id")

    users = []
    if role == "admin":
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, username
                FROM users
                WHERE role = 'commercial'
                ORDER BY username ASC
            """)
            users = cur.fetchall()

    with conn.cursor() as cur:

        if role == "admin":
            if q:
                cur.execute("""
                    SELECT crm_clients.*, users.username AS commercial
                    FROM crm_clients
                    LEFT JOIN users ON users.id = crm_clients.owner_id
                    WHERE
                        crm_clients.name ILIKE %s
                        OR COALESCE(crm_clients.email, '') ILIKE %s
                        OR COALESCE(crm_clients.phone, '') ILIKE %s
                        OR COALESCE(crm_clients.siret, '') ILIKE %s
                    ORDER BY crm_clients.created_at DESC, crm_clients.id DESC
                """, (f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"))
            else:
                cur.execute("""
                    SELECT crm_clients.*, users.username AS commercial
                    FROM crm_clients
                    LEFT JOIN users ON users.id = crm_clients.owner_id
                    ORDER BY crm_clients.created_at DESC, crm_clients.id DESC
                """)
        else:
            if q:
                cur.execute("""
                    SELECT crm_clients.*, users.username AS commercial
                    FROM crm_clients
                    LEFT JOIN users ON users.id = crm_clients.owner_id
                    WHERE crm_clients.owner_id = %s
                      AND (
                          crm_clients.name ILIKE %s
                          OR COALESCE(crm_clients.email, '') ILIKE %s
                          OR COALESCE(crm_clients.phone, '') ILIKE %s
                          OR COALESCE(crm_clients.siret, '') ILIKE %s
                      )
                    ORDER BY crm_clients.created_at DESC, crm_clients.id DESC
                """, (user_id, f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"))
            else:
                cur.execute("""
                    SELECT crm_clients.*, users.username AS commercial
                    FROM crm_clients
                    LEFT JOIN users ON users.id = crm_clients.owner_id
                    WHERE crm_clients.owner_id = %s
                    ORDER BY crm_clients.created_at DESC, crm_clients.id DESC
                """, (user_id,))

        rows = cur.fetchall()

    en_cours, en_attente, gagnes, perdus = [], [], [], []

    for r in rows:
        st = (r.get("status") or "").strip().lower()

        if st in ("", "nouveau", "en_cours"):
            en_cours.append(r)
        elif st == "en_attente":
            en_attente.append(r)
        elif st == "gagne":
            gagnes.append(r)
        elif st == "perdu":
            perdus.append(r)
        else:
            en_cours.append(r)

    return render_template(
        "clients.html",
        clients_en_cours=[row_to_obj(r) for r in en_cours],
        clients_en_attente=[row_to_obj(r) for r in en_attente],
        clients_gagnes=[row_to_obj(r) for r in gagnes],
        clients_perdus=[row_to_obj(r) for r in perdus],
        q=q,
        users=[row_to_obj(u) for u in users],
        current_user=session.get("user"),
        available_endpoints=[rule.endpoint for rule in app.url_map.iter_rules()],
    )


# =========================
# CLIENT — CREATION
# =========================
@app.route("/clients/create", methods=["POST"], endpoint="create_client")
@login_required
def create_client():

    conn = get_db()
    user = session.get("user") or {}

    role = user.get("role")
    current_user_id = user.get("id")
    current_username = user.get("username")

    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    address = (request.form.get("address") or "").strip()
    commercial = (request.form.get("commercial") or "").strip()
    status = (request.form.get("status") or "en_cours").strip().lower()
    notes = (request.form.get("notes") or "").strip()
    siret = (request.form.get("siret") or "").strip()
    gerant_nom = (request.form.get("gerant_nom") or "").strip()

    if not name:
        flash("Le nom du client est obligatoire.", "danger")
        return redirect(url_for("clients"))

    if status not in ("en_cours", "en_attente", "gagne", "perdu", "nouveau"):
        status = "en_cours"

    owner_id = None

    try:
        if role == "admin":
            owner_raw = (request.form.get("owner_id") or "").strip()

            if not owner_raw:
                flash("Veuillez assigner un commercial.", "danger")
                return redirect(url_for("clients"))

            try:
                owner_id = int(owner_raw)
            except Exception:
                flash("Commercial invalide.", "danger")
                return redirect(url_for("clients"))

            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, username
                    FROM users
                    WHERE id = %s
                      AND role = 'commercial'
                """, (owner_id,))
                owner_row = cur.fetchone()

            if not owner_row:
                flash("Commercial introuvable.", "danger")
                return redirect(url_for("clients"))

            commercial = owner_row["username"]

        else:
            owner_id = current_user_id
            commercial = current_username

        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO crm_clients (
                    name,
                    email,
                    phone,
                    address,
                    commercial,
                    status,
                    notes,
                    owner_id,
                    siret,
                    gerant_nom
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                name,
                email or None,
                phone or None,
                address or None,
                commercial or None,
                status,
                notes or None,
                owner_id,
                siret or None,
                gerant_nom or None,
            ))
            new_client_id = cur.fetchone()["id"]

        conn.commit()
        flash("Client créé avec succès.", "success")
        return redirect(url_for("client_detail", client_id=new_client_id))

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur création client : %r", e)
        flash("Erreur lors de la création du client.", "danger")
        return redirect(url_for("clients"))


# =========================
# CLIENT — DETAIL
# =========================
@app.route("/clients/<int:client_id>", endpoint="client_detail")
@login_required
def client_detail(client_id):

    if not can_access_client(client_id):
        abort(403)

    conn = get_db()
    user = session.get("user") or {}

    with conn.cursor() as cur:
        cur.execute("""
            SELECT crm_clients.*, users.username AS commercial
            FROM crm_clients
            LEFT JOIN users ON users.id = crm_clients.owner_id
            WHERE crm_clients.id = %s
        """, (client_id,))
        client = cur.fetchone()

    if not client:
        flash("Client introuvable.", "danger")
        return redirect(url_for("clients"))

    documents = list_client_documents(client_id)

    with conn.cursor() as cur:
        cur.execute("""
            SELECT *
            FROM cotations
            WHERE client_id = %s
            ORDER BY date_creation DESC, id DESC
        """, (client_id,))
        cotations = cur.fetchall()

    with conn.cursor() as cur:
        cur.execute("""
            SELECT *
            FROM (
                SELECT
                    'client' AS type,
                    created_at AS date,
                    'Création du client' AS title,
                    COALESCE(notes,'') AS description
                FROM crm_clients
                WHERE id = %s

                UNION ALL

                SELECT
                    'cotation' AS type,
                    date_creation AS date,
                    'Nouvelle cotation #' || id AS title,
                    COALESCE(commentaire,'') AS description
                FROM cotations
                WHERE client_id = %s

                UNION ALL

                SELECT
                    'update' AS type,
                    created_at AS date,
                    'Demande de mise à jour' AS title,
                    COALESCE(commentaire,'') AS description
                FROM client_updates
                WHERE client_id = %s
            ) t
            ORDER BY COALESCE(date, CURRENT_TIMESTAMP) DESC
        """, (client_id, client_id, client_id))
        timeline = cur.fetchall()

    with conn.cursor() as cur:
        cur.execute("""
            SELECT *
            FROM client_updates
            WHERE client_id = %s
            ORDER BY update_date DESC, id DESC
        """, (client_id,))
        updates = cur.fetchall()

    commercial_users = []
    if user.get("role") == "admin":
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, username
                FROM users
                WHERE role = 'commercial'
                ORDER BY username ASC
            """)
            commercial_users = [row_to_obj(row) for row in cur.fetchall()]

    return render_template(
        "client_detail.html",
        client=row_to_obj(client),
        documents=documents,
        cotations=[row_to_obj(c) for c in cotations],
        timeline=[row_to_obj(t) for t in timeline],
        updates=[row_to_obj(u) for u in updates],
        current_user=user,
        commercial_users=commercial_users,
        available_endpoints=[rule.endpoint for rule in app.url_map.iter_rules()],
    )


# =========================
# CLIENT — MODIFICATION
# =========================
@app.route("/clients/<int:client_id>/edit", methods=["POST"], endpoint="edit_client")
@login_required
def edit_client(client_id):

    if not can_access_client(client_id):
        abort(403)

    conn = get_db()
    user = session.get("user") or {}
    role = user.get("role")

    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    address = (request.form.get("address") or "").strip()
    commercial = (request.form.get("commercial") or "").strip()
    status = (request.form.get("status") or "").strip().lower()
    notes = (request.form.get("notes") or "").strip()
    siret = (request.form.get("siret") or "").strip()
    gerant_nom = (request.form.get("gerant_nom") or "").strip()

    if not name:
        flash("Le nom du client est obligatoire.", "danger")
        return redirect(url_for("client_detail", client_id=client_id))

    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, owner_id, commercial, status
            FROM crm_clients
            WHERE id = %s
        """, (client_id,))
        existing_client = cur.fetchone()

    if not existing_client:
        flash("Client introuvable.", "danger")
        return redirect(url_for("clients"))

    if status not in ("en_cours", "en_attente", "gagne", "perdu", "nouveau"):
        status = (existing_client.get("status") or "en_cours").strip().lower()

    try:
        owner_id = None

        if role == "admin":
            owner_id = existing_client["owner_id"]
            if not commercial:
                commercial = existing_client["commercial"]

            owner_raw = (request.form.get("owner_id") or "").strip()

            if owner_raw:
                try:
                    owner_id = int(owner_raw)
                except Exception:
                    flash("Commercial invalide.", "danger")
                    return redirect(url_for("client_detail", client_id=client_id))

                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT id, username
                        FROM users
                        WHERE id = %s
                          AND role = 'commercial'
                    """, (owner_id,))
                    owner_row = cur.fetchone()

                if not owner_row:
                    flash("Commercial introuvable.", "danger")
                    return redirect(url_for("client_detail", client_id=client_id))

                commercial = owner_row["username"]

            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE crm_clients
                    SET
                        name = %s,
                        email = %s,
                        phone = %s,
                        address = %s,
                        commercial = %s,
                        status = %s,
                        notes = %s,
                        owner_id = %s,
                        siret = %s,
                        gerant_nom = %s
                    WHERE id = %s
                """, (
                    name,
                    email or None,
                    phone or None,
                    address or None,
                    commercial or None,
                    status,
                    notes or None,
                    owner_id,
                    siret or None,
                    gerant_nom or None,
                    client_id,
                ))

        else:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE crm_clients
                    SET
                        name = %s,
                        email = %s,
                        phone = %s,
                        address = %s,
                        status = %s,
                        notes = %s,
                        siret = %s,
                        gerant_nom = %s
                    WHERE id = %s
                """, (
                    name,
                    email or None,
                    phone or None,
                    address or None,
                    status,
                    notes or None,
                    siret or None,
                    gerant_nom or None,
                    client_id,
                ))

        conn.commit()
        flash("Client mis à jour avec succès.", "success")

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur modification client : %r", e)
        flash("Erreur lors de la modification du client.", "danger")

    return redirect(url_for("client_detail", client_id=client_id))


# =========================
# CLIENT — UPDATE STATUS
# =========================
@app.route("/clients/<int:client_id>/status", methods=["POST"], endpoint="update_client_status")
@login_required
def update_client_status(client_id):

    if not can_access_client(client_id):
        abort(403)

    conn = get_db()
    status = (request.form.get("status") or "").strip().lower()

    if status not in ("en_cours", "en_attente", "gagne", "perdu"):
        flash("Statut invalide.", "danger")
        return redirect(request.referrer or url_for("clients"))

    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE crm_clients
                SET status = %s
                WHERE id = %s
            """, (status, client_id))

        conn.commit()

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur update status : %r", e)
        flash("Erreur lors de la mise à jour.", "danger")

    return redirect(request.referrer or url_for("clients"))


# =========================
# CLIENT — SUPPRESSION
# =========================
@app.route("/clients/<int:client_id>/delete", methods=["POST"], endpoint="delete_client")
@admin_required
def delete_client(client_id):

    if not can_access_client(client_id):
        abort(403)

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM crm_clients WHERE id = %s", (client_id,))
            row = cur.fetchone()

        if not row:
            flash("Client introuvable.", "danger")
            return redirect(url_for("clients"))

        with conn.cursor() as cur:
            cur.execute("DELETE FROM cotations WHERE client_id = %s", (client_id,))
            cur.execute("DELETE FROM client_updates WHERE client_id = %s", (client_id,))
            cur.execute("DELETE FROM revenus WHERE client_id = %s", (client_id,))
            cur.execute("DELETE FROM crm_clients WHERE id = %s", (client_id,))

        conn.commit()
        flash("Client supprimé avec succès.", "success")

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur suppression client : %r", e)
        flash("Erreur lors de la suppression du client.", "danger")

    return redirect(url_for("clients"))


# =========================
# COTATION
# =========================
@app.route("/clients/<int:client_id>/cotation", methods=["POST"], endpoint="create_cotation")
@login_required
def create_cotation(client_id):

    if not can_access_client(client_id):
        abort(403)

    conn = get_db()
    user = session.get("user") or {}
    cotation_id = None

    with conn.cursor() as cur:
        cur.execute(
            "SELECT name FROM crm_clients WHERE id = %s",
            (client_id,),
        )
        client = cur.fetchone()

    client_name = (client.get("name") or "").strip() if client else f"Client {client_id}"

    date_negociation = parse_date_safe((request.form.get("date_negociation") or "").strip())
    heure_negociation = parse_time_safe((request.form.get("heure_negociation") or "").strip())
    energie_type = (request.form.get("energie_type") or "").strip()
    pdl_pce = (request.form.get("pdl_pce") or "").strip()
    date_echeance = parse_date_safe((request.form.get("date_echeance") or "").strip())
    fournisseur_actuel = (request.form.get("fournisseur_actuel") or "").strip()
    entreprise_nom = (request.form.get("entreprise_nom") or "").strip()
    siret = (request.form.get("siret") or "").strip()
    adresse_facturation = (request.form.get("adresse_facturation") or "").strip()
    adresse_consommation = (request.form.get("adresse_consommation") or "").strip()
    signataire_nom = (request.form.get("signataire_nom") or "").strip()
    signataire_tel = (request.form.get("signataire_tel") or "").strip()
    signataire_email = (request.form.get("signataire_email") or "").strip()
    commentaire = (request.form.get("commentaire") or "").strip()

    # Champs étendus
    type_compteur = (request.form.get("type_compteur") or "").strip()
    signataire_mobile = (request.form.get("signataire_mobile") or "").strip()
    site_nom = (request.form.get("site_nom") or "").strip()
    fonction_signataire = (request.form.get("fonction_signataire") or "").strip()
    code_naf = (request.form.get("code_naf") or "").strip()
    date_remise_offre = parse_date_safe((request.form.get("date_remise_offre") or "").strip())

    elec_debut_fourniture = parse_date_safe((request.form.get("elec_debut_fourniture") or "").strip())
    elec_fin_fourniture = parse_date_safe((request.form.get("elec_fin_fourniture") or "").strip())
    elec_nb_mois = parse_int_safe((request.form.get("elec_nb_mois") or "").strip())
    elec_segment = (request.form.get("elec_segment") or "").strip()
    formule_acheminement = (request.form.get("formule_acheminement") or "").strip()
    elec_car = (request.form.get("elec_car") or "").strip()
    puissance_souscrite = (request.form.get("puissance_souscrite") or "").strip()
    elec_fournisseur_actuel = (request.form.get("elec_fournisseur_actuel") or "").strip()

    pointe = (request.form.get("pointe") or "").strip()
    hph = (request.form.get("hph") or "").strip()
    hch = (request.form.get("hch") or "").strip()
    hpr = (request.form.get("hpr") or "").strip()
    hce = (request.form.get("hce") or "").strip()

    gaz_debut_fourniture = parse_date_safe((request.form.get("gaz_debut_fourniture") or "").strip())
    gaz_fin_fourniture = parse_date_safe((request.form.get("gaz_fin_fourniture") or "").strip())
    gaz_nb_mois = parse_int_safe((request.form.get("gaz_nb_mois") or "").strip())
    pce = (request.form.get("pce") or "").strip()
    gaz_segment = (request.form.get("gaz_segment") or "").strip()
    profil = (request.form.get("profil") or "").strip()
    gaz_car = (request.form.get("gaz_car") or "").strip()
    gaz_fournisseur_actuel = (request.form.get("gaz_fournisseur_actuel") or "").strip()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO cotations (
                    client_id,
                    date_negociation,
                    energie_type,
                    pdl_pce,
                    date_echeance,
                    fournisseur_actuel,
                    entreprise_nom,
                    siret,
                    adresse_facturation,
                    adresse_consommation,
                    signataire_nom,
                    signataire_tel,
                    signataire_email,
                    commentaire,
                    created_by,
                    is_read,
                    status,
                    date_creation,
                    type_compteur,
                    heure_negociation,
                    signataire_mobile,
                    site_nom,
                    fonction_signataire,
                    code_naf,
                    date_remise_offre,
                    elec_debut_fourniture,
                    elec_fin_fourniture,
                    elec_nb_mois,
                    elec_segment,
                    formule_acheminement,
                    elec_car,
                    puissance_souscrite,
                    elec_fournisseur_actuel,
                    pointe,
                    hph,
                    hch,
                    hpr,
                    hce,
                    gaz_debut_fourniture,
                    gaz_fin_fourniture,
                    gaz_nb_mois,
                    pce,
                    gaz_segment,
                    profil,
                    gaz_car,
                    gaz_fournisseur_actuel
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, 0, 'en_cours', NOW(), %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s
                )
                RETURNING id
            """, (
                client_id,
                date_negociation,
                energie_type or None,
                pdl_pce or None,
                date_echeance,
                fournisseur_actuel or None,
                entreprise_nom or None,
                siret or None,
                adresse_facturation or None,
                adresse_consommation or None,
                signataire_nom or None,
                signataire_tel or None,
                signataire_email or None,
                commentaire or None,
                user.get("id"),
                type_compteur or None,
                heure_negociation,
                signataire_mobile or None,
                site_nom or None,
                fonction_signataire or None,
                code_naf or None,
                date_remise_offre,
                elec_debut_fourniture,
                elec_fin_fourniture,
                elec_nb_mois,
                elec_segment or None,
                formule_acheminement or None,
                elec_car or None,
                puissance_souscrite or None,
                elec_fournisseur_actuel or None,
                pointe or None,
                hph or None,
                hch or None,
                hpr or None,
                hce or None,
                gaz_debut_fourniture,
                gaz_fin_fourniture,
                gaz_nb_mois,
                pce or None,
                gaz_segment or None,
                profil or None,
                gaz_car or None,
                gaz_fournisseur_actuel or None,
            ))
            cotation_id = cur.fetchone()[0]

        conn.commit()
        flash("Cotation créée.", "success")

        cotation_link = build_app_url(
            url_for("admin_cotation_detail", cotation_id=cotation_id)
        )
        heure_display = (
            heure_negociation.strftime("%H:%M")
            if hasattr(heure_negociation, "strftime")
            else (str(heure_negociation)[:5] if heure_negociation else "-")
        )
        if EMAIL_NOTIFICATIONS_ENABLED:
            email_sent, email_error = send_notification_email(
                subject=f"Nouvelle demande de cotation - {client_name}",
                body=(
                    "Une nouvelle demande de cotation vient d'etre creee.\n\n"
                    f"Dossier : {client_name}\n"
                    f"Commercial : {user.get('username') or 'Inconnu'}\n"
                    f"Energie : {energie_type or '-'}\n"
                    f"Date de negociation : {format_date_safe(date_negociation)}\n"
                    f"Heure de negociation : {heure_display}\n"
                    f"Signataire : {signataire_nom or '-'}\n"
                    f"Email signataire : {signataire_email or '-'}\n"
                    f"PDL / PCE : {pdl_pce or pce or '-'}\n"
                    f"Commentaire : {commentaire or '-'}\n\n"
                    f"Ouvrir la demande : {cotation_link}\n"
                ),
            )

            if not email_sent:
                flash(
                    f"La cotation a ete creee, mais l'email de notification n'a pas pu etre envoye ({email_error or 'erreur SMTP'}).",
                    "warning",
                )

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur cotation : %r", e)
        flash("Erreur lors de la création de la cotation.", "danger")

    return redirect(url_for("client_detail", client_id=client_id))


@app.route(
    "/clients/<int:client_id>/cotations/<int:cotation_id>/edit",
    methods=["GET", "POST"],
    endpoint="edit_cotation",
)
@login_required
def edit_cotation(client_id, cotation_id):

    if not can_access_client(client_id):
        abort(403)

    conn = get_db()
    user = session.get("user") or {}
    back_hint = (request.values.get("back") or "client").strip().lower()

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                crm_clients.*,
                users.username AS commercial
            FROM crm_clients
            LEFT JOIN users ON users.id = crm_clients.owner_id
            WHERE crm_clients.id = %s
            """,
            (client_id,),
        )
        client = cur.fetchone()

    if not client:
        flash("Client introuvable.", "danger")
        return redirect(url_for("clients"))

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                cotations.*,
                crm_clients.name AS client_name,
                users.username AS commercial_name
            FROM cotations
            LEFT JOIN crm_clients ON crm_clients.id = cotations.client_id
            LEFT JOIN users ON users.id = cotations.created_by
            WHERE cotations.id = %s
              AND cotations.client_id = %s
            """,
            (cotation_id, client_id),
        )
        cotation = cur.fetchone()

    if not cotation:
        flash("Demande de cotation introuvable.", "danger")
        return redirect(url_for("client_detail", client_id=client_id))

    if request.method == "POST":
        date_negociation = parse_date_safe((request.form.get("date_negociation") or "").strip())
        heure_negociation = parse_time_safe((request.form.get("heure_negociation") or "").strip())
        energie_type = (request.form.get("energie_type") or "").strip()
        pdl_pce = (request.form.get("pdl_pce") or "").strip()
        date_echeance = parse_date_safe((request.form.get("date_echeance") or "").strip())
        fournisseur_actuel = (request.form.get("fournisseur_actuel") or "").strip()
        entreprise_nom = (request.form.get("entreprise_nom") or "").strip()
        siret = (request.form.get("siret") or "").strip()
        adresse_facturation = (request.form.get("adresse_facturation") or "").strip()
        adresse_consommation = (request.form.get("adresse_consommation") or "").strip()
        signataire_nom = (request.form.get("signataire_nom") or "").strip()
        signataire_tel = (request.form.get("signataire_tel") or "").strip()
        signataire_email = (request.form.get("signataire_email") or "").strip()
        commentaire = (request.form.get("commentaire") or "").strip()
        status = (request.form.get("status") or "").strip().lower()

        type_compteur = (request.form.get("type_compteur") or "").strip()
        signataire_mobile = (request.form.get("signataire_mobile") or "").strip()
        site_nom = (request.form.get("site_nom") or "").strip()
        fonction_signataire = (request.form.get("fonction_signataire") or "").strip()
        code_naf = (request.form.get("code_naf") or "").strip()
        date_remise_offre = parse_date_safe((request.form.get("date_remise_offre") or "").strip())

        elec_debut_fourniture = parse_date_safe((request.form.get("elec_debut_fourniture") or "").strip())
        elec_fin_fourniture = parse_date_safe((request.form.get("elec_fin_fourniture") or "").strip())
        elec_nb_mois = parse_int_safe((request.form.get("elec_nb_mois") or "").strip())
        elec_segment = (request.form.get("elec_segment") or "").strip()
        formule_acheminement = (request.form.get("formule_acheminement") or "").strip()
        elec_car = (request.form.get("elec_car") or "").strip()
        puissance_souscrite = (request.form.get("puissance_souscrite") or "").strip()
        elec_fournisseur_actuel = (request.form.get("elec_fournisseur_actuel") or "").strip()

        pointe = (request.form.get("pointe") or "").strip()
        hph = (request.form.get("hph") or "").strip()
        hch = (request.form.get("hch") or "").strip()
        hpr = (request.form.get("hpr") or "").strip()
        hce = (request.form.get("hce") or "").strip()

        gaz_debut_fourniture = parse_date_safe((request.form.get("gaz_debut_fourniture") or "").strip())
        gaz_fin_fourniture = parse_date_safe((request.form.get("gaz_fin_fourniture") or "").strip())
        gaz_nb_mois = parse_int_safe((request.form.get("gaz_nb_mois") or "").strip())
        pce = (request.form.get("pce") or "").strip()
        gaz_segment = (request.form.get("gaz_segment") or "").strip()
        profil = (request.form.get("profil") or "").strip()
        gaz_car = (request.form.get("gaz_car") or "").strip()
        gaz_fournisseur_actuel = (request.form.get("gaz_fournisseur_actuel") or "").strip()

        valid_statuses = {"nouvelle", "en_cours", "envoyee", "acceptee", "refusee"}
        if status not in valid_statuses:
            status = (cotation.get("status") or "en_cours").strip().lower()

        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE cotations
                    SET
                        date_negociation = %s,
                        heure_negociation = %s,
                        energie_type = %s,
                        pdl_pce = %s,
                        date_echeance = %s,
                        fournisseur_actuel = %s,
                        entreprise_nom = %s,
                        siret = %s,
                        adresse_facturation = %s,
                        adresse_consommation = %s,
                        signataire_nom = %s,
                        signataire_tel = %s,
                        signataire_email = %s,
                        commentaire = %s,
                        status = %s,
                        type_compteur = %s,
                        signataire_mobile = %s,
                        site_nom = %s,
                        fonction_signataire = %s,
                        code_naf = %s,
                        date_remise_offre = %s,
                        elec_debut_fourniture = %s,
                        elec_fin_fourniture = %s,
                        elec_nb_mois = %s,
                        elec_segment = %s,
                        formule_acheminement = %s,
                        elec_car = %s,
                        puissance_souscrite = %s,
                        elec_fournisseur_actuel = %s,
                        pointe = %s,
                        hph = %s,
                        hch = %s,
                        hpr = %s,
                        hce = %s,
                        gaz_debut_fourniture = %s,
                        gaz_fin_fourniture = %s,
                        gaz_nb_mois = %s,
                        pce = %s,
                        gaz_segment = %s,
                        profil = %s,
                        gaz_car = %s,
                        gaz_fournisseur_actuel = %s,
                        is_read = %s
                    WHERE id = %s
                      AND client_id = %s
                    """,
                    (
                        date_negociation,
                        heure_negociation,
                        energie_type or None,
                        pdl_pce or None,
                        date_echeance,
                        fournisseur_actuel or None,
                        entreprise_nom or None,
                        siret or None,
                        adresse_facturation or None,
                        adresse_consommation or None,
                        signataire_nom or None,
                        signataire_tel or None,
                        signataire_email or None,
                        commentaire or None,
                        status,
                        type_compteur or None,
                        signataire_mobile or None,
                        site_nom or None,
                        fonction_signataire or None,
                        code_naf or None,
                        date_remise_offre,
                        elec_debut_fourniture,
                        elec_fin_fourniture,
                        elec_nb_mois,
                        elec_segment or None,
                        formule_acheminement or None,
                        elec_car or None,
                        puissance_souscrite or None,
                        elec_fournisseur_actuel or None,
                        pointe or None,
                        hph or None,
                        hch or None,
                        hpr or None,
                        hce or None,
                        gaz_debut_fourniture,
                        gaz_fin_fourniture,
                        gaz_nb_mois,
                        pce or None,
                        gaz_segment or None,
                        profil or None,
                        gaz_car or None,
                        gaz_fournisseur_actuel or None,
                        0 if user.get("role") != "admin" else (1 if cotation.get("is_read") else 0),
                        cotation_id,
                        client_id,
                    ),
                )

            conn.commit()
            flash("Demande de cotation mise a jour avec succes.", "success")

            if back_hint == "admin" and user.get("role") == "admin":
                return redirect(url_for("admin_cotation_detail", cotation_id=cotation_id))
            return redirect(url_for("client_detail", client_id=client_id))

        except Exception as e:
            conn.rollback()
            logger.exception("Erreur modification cotation : %r", e)
            flash("Erreur lors de la mise a jour de la cotation.", "danger")

    return render_template(
        "cotation_edit.html",
        client=row_to_obj(client),
        cotation=row_to_obj(cotation),
        current_user=user,
        back_hint=back_hint,
    )


# =========================
# DOCUMENT PREVIEW
# =========================
@app.route("/document/preview", endpoint="preview_document")
@login_required
def preview_document():

    key = (request.args.get("key") or "").strip()

    if not key:
        return redirect(request.referrer or url_for("clients"))

    if not can_access_document_key(key):
        abort(403)

    preview_meta = build_document_preview_meta(key)

    return render_template(
        "document_preview.html",
        document_name=preview_meta["filename"] or "Document",
        preview_kind=preview_meta["preview_kind"],
        previewable=preview_meta["previewable"],
        inline_url=url_for("inline_document", key=key),
        download_url=url_for("download_document", key=key),
    )


@app.route("/document/inline", endpoint="inline_document")
@login_required
def inline_document():

    key = (request.args.get("key") or "").strip()

    if not key:
        return redirect(request.referrer or url_for("clients"))

    if not can_access_document_key(key):
        abort(403)

    try:
        if LOCAL_MODE:
            path = local_storage_path(key)
            if not os.path.exists(path):
                flash("Document introuvable.", "danger")
                return redirect(request.referrer or url_for("clients"))
            return send_file(path, as_attachment=False)

        if not s3:
            flash("Ouverture indisponible pour ce document.", "warning")
            return redirect(request.referrer or url_for("clients"))

        url = s3_presigned_url(key, response_disposition="inline")
        if not url:
            flash("Impossible de generer la previsualisation du document.", "danger")
            return redirect(request.referrer or url_for("clients"))

        return redirect(url)

    except Exception as e:
        logger.exception("Erreur preview document : %r", e)
        flash("Erreur lors de l'ouverture du document.", "danger")
        return redirect(request.referrer or url_for("clients"))


# =========================
# DOCUMENT DOWNLOAD
# =========================
@app.route("/document/download", endpoint="download_document")
@login_required
def download_document():

    key = (request.args.get("key") or "").strip()

    if not key:
        return redirect(url_for("clients"))

    if not can_access_document_key(key):
        abort(403)

    try:
        if LOCAL_MODE:
            path = local_storage_path(key)
            if not os.path.exists(path):
                flash("Document introuvable.", "danger")
                return redirect(request.referrer or url_for("clients"))
            return send_file(path, as_attachment=True)

        if not s3:
            flash("Téléchargement indisponible en mode local.", "warning")
            return redirect(request.referrer or url_for("clients"))

        url = s3_presigned_url(key, response_disposition="attachment")
        if not url:
            flash("Impossible de générer le lien de téléchargement.", "danger")
            return redirect(request.referrer or url_for("clients"))

        return redirect(url)

    except Exception as e:
        logger.exception("Erreur download : %r", e)
        flash("Erreur lors du téléchargement.", "danger")
        return redirect(request.referrer or url_for("clients"))

def _download_document_endpoint():

    key = (request.args.get("key") or "").strip()

    if not key:
        return redirect(url_for("clients"))

    if not can_access_document_key(key):
        abort(403)

    try:
        if LOCAL_MODE:
            path = local_storage_path(key)
            if not os.path.exists(path):
                flash("Document introuvable.", "danger")
                return redirect(request.referrer or url_for("clients"))
            return send_file(path, as_attachment=True)

        if not s3:
            flash("Telechargement indisponible pour ce document.", "warning")
            return redirect(request.referrer or url_for("clients"))

        url = s3_presigned_url(key, response_disposition="attachment")
        if not url:
            flash("Impossible de generer le lien de telechargement.", "danger")
            return redirect(request.referrer or url_for("clients"))

        return redirect(url)

    except Exception as e:
        logger.exception("Erreur download : %r", e)
        flash("Erreur lors du telechargement.", "danger")
        return redirect(request.referrer or url_for("clients"))


app.view_functions["download_document"] = login_required(_download_document_endpoint)


# =========================
# DOCUMENT DELETE
# =========================
@app.route("/document/delete", methods=["POST"], endpoint="delete_document")
@login_required
def delete_document():

    key = (request.form.get("key") or "").strip()

    if not key:
        flash("Document invalide.", "danger")
        return redirect(request.referrer or url_for("clients"))

    try:
        if not can_access_document_key(key):
            abort(403)

        if LOCAL_MODE or not s3:
            flash("Suppression indisponible en mode local.", "warning")
            return redirect(request.referrer or url_for("clients"))

        s3.delete_object(Bucket=AWS_BUCKET, Key=key)
        flash("Document supprimé.", "success")

    except Exception as e:
        logger.exception("Erreur delete : %r", e)
        flash("Erreur lors de la suppression du document.", "danger")

    return redirect(request.referrer or url_for("clients"))


# =========================
# DOCUMENT UPLOAD LEGACY
# =========================
# ⚠️ Conserve l’ancienne route /clients/<id>/upload
# sans écraser la vraie fonction upload_client_document du bloc 11
@app.route("/clients/<int:client_id>/upload", methods=["POST"], endpoint="upload_client_document_legacy")
@login_required
def upload_client_document_legacy(client_id):

    if not can_access_client(client_id):
        abort(403)

    if LOCAL_MODE or not s3:
        flash("Upload indisponible.", "warning")
        return redirect(url_for("client_detail", client_id=client_id))

    files = request.files.getlist("files")

    # fallback legacy
    if not files:
        legacy_file = request.files.get("file")
        if legacy_file and getattr(legacy_file, "filename", ""):
            files = [legacy_file]

    files = [f for f in files if f and getattr(f, "filename", "")]

    if not files:
        flash("Aucun fichier sélectionné.", "danger")
        return redirect(url_for("client_detail", client_id=client_id))

    success_count = 0
    failed = []
    doc_name = (request.form.get("doc_name") or "").strip()
    doc_kind = normalize_document_kind(request.form.get("doc_kind") or "")
    auto_name = (request.form.get("auto_name") or "").strip().lower() in {"1", "true", "on", "yes"}
    pdl = re.sub(r"[^0-9]", "", (request.form.get("pdl") or ""))
    client_name = ""

    if auto_name:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT name FROM crm_clients WHERE id = %s",
                (client_id,),
            )
            row = cur.fetchone()
        client_name = (row.get("name") or "").strip() if row else ""

    prefix = client_s3_prefix(client_id, client_name or None)

    for f in files:
        try:
            if not allowed_file(f.filename):
                failed.append(f.filename or "fichier_invalide")
                continue

            original_name = secure_filename(f.filename) or "document"
            ext = os.path.splitext(original_name)[1].lower()
            base_name = build_document_upload_base_name(
                client_name or f"client_{client_id}",
                original_name,
                manual_name=doc_name,
                doc_kind=doc_kind,
                auto_name=auto_name,
                extra_suffix=pdl,
            )
            filename = f"{base_name}{ext}"

            key = _s3_make_non_overwriting_key(
                AWS_BUCKET,
                f"{prefix}{filename}"
            )

            s3_upload_fileobj(f, AWS_BUCKET, key)
            success_count += 1

        except Exception as e:
            logger.exception("Erreur upload legacy : %r", e)
            failed.append(getattr(f, "filename", None) or "fichier_erreur")

    if success_count > 0 and not failed:
        flash(f"{success_count} document(s) uploadé(s).", "success")
    elif success_count > 0:
        flash(f"{success_count} upload(s) réussi(s), {len(failed)} échec(s).", "warning")
    else:
        flash("Aucun upload réussi.", "danger")

    return redirect(url_for("client_detail", client_id=client_id))


############################################################
# 12 BIS. CSPE — RÉCUPÉRATION DE TAXES
############################################################

@app.route("/cspe", endpoint="cspe_index")
@login_required
def cspe_index():
    ensure_cspe_schema()

    conn = get_db()
    user = session.get("user") or {}
    role = user.get("role")
    user_id = user.get("id")
    q = (request.args.get("q") or "").strip()

    if role not in ("admin", "commercial"):
        abort(403)

    users = []
    if role == "admin":
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, username
                FROM users
                WHERE role = 'commercial'
                ORDER BY username ASC
            """)
            users = cur.fetchall()

    with conn.cursor() as cur:
        if role == "admin":
            if q:
                cur.execute("""
                    SELECT d.*, users.username AS commercial
                    FROM cspe_dossiers d
                    LEFT JOIN users ON users.id = d.owner_id
                    WHERE
                        d.name ILIKE %s
                        OR COALESCE(d.notes, '') ILIKE %s
                        OR COALESCE(users.username, '') ILIKE %s
                    ORDER BY d.created_at DESC, d.id DESC
                """, (f"%{q}%", f"%{q}%", f"%{q}%"))
            else:
                cur.execute("""
                    SELECT d.*, users.username AS commercial
                    FROM cspe_dossiers d
                    LEFT JOIN users ON users.id = d.owner_id
                    ORDER BY d.created_at DESC, d.id DESC
                """)
        else:
            if q:
                cur.execute("""
                    SELECT d.*, users.username AS commercial
                    FROM cspe_dossiers d
                    LEFT JOIN users ON users.id = d.owner_id
                    WHERE d.owner_id = %s
                      AND (
                          d.name ILIKE %s
                          OR COALESCE(d.notes, '') ILIKE %s
                      )
                    ORDER BY d.created_at DESC, d.id DESC
                """, (user_id, f"%{q}%", f"%{q}%"))
            else:
                cur.execute("""
                    SELECT d.*, users.username AS commercial
                    FROM cspe_dossiers d
                    LEFT JOIN users ON users.id = d.owner_id
                    WHERE d.owner_id = %s
                    ORDER BY d.created_at DESC, d.id DESC
                """, (user_id,))

        rows = cur.fetchall()

    commercial_stats = {}
    total_chiffre_affaire = 0.0

    for row in rows:
        amount = float(row.get("chiffre_affaire") or 0)
        total_chiffre_affaire += amount

        commercial_name = row.get("commercial") or "Non assigné"
        if commercial_name not in commercial_stats:
            commercial_stats[commercial_name] = {
                "commercial": commercial_name,
                "dossiers": 0,
                "chiffre_affaire": 0.0,
            }

        commercial_stats[commercial_name]["dossiers"] += 1
        commercial_stats[commercial_name]["chiffre_affaire"] += amount

    stats_list = sorted(
        commercial_stats.values(),
        key=lambda item: item["commercial"].lower(),
    )

    return render_template(
        "cspe.html",
        dossiers=[row_to_obj(r) for r in rows],
        users=[row_to_obj(u) for u in users],
        commercial_stats=stats_list,
        total_dossiers=len(rows),
        total_chiffre_affaire=total_chiffre_affaire,
        q=q,
        current_user=session.get("user"),
        available_endpoints=[rule.endpoint for rule in app.url_map.iter_rules()],
    )


@app.route("/cspe/create", methods=["POST"], endpoint="create_cspe_dossier")
@login_required
def create_cspe_dossier():
    ensure_cspe_schema()

    conn = get_db()
    user = session.get("user") or {}
    role = user.get("role")

    if role not in ("admin", "commercial"):
        abort(403)

    name = (request.form.get("name") or "").strip()
    notes = (request.form.get("notes") or "").strip()
    date_negociation_raw = (request.form.get("date_negociation") or "").strip()
    date_negociation = parse_date_safe(date_negociation_raw)
    chiffre_affaire = parse_amount_safe(
        (request.form.get("chiffre_affaire") or "").strip()
    )

    if not name:
        flash("Le nom du dossier est obligatoire.", "danger")
        return redirect(url_for("cspe_index"))

    if chiffre_affaire is None:
        flash("Le chiffre d'affaires est invalide.", "danger")
        return redirect(url_for("cspe_index"))

    if date_negociation_raw and not date_negociation:
        flash("La date de négociation est invalide.", "danger")
        return redirect(url_for("cspe_index"))

    owner_id = None

    try:
        if role == "admin":
            owner_raw = (request.form.get("owner_id") or "").strip()

            if not owner_raw:
                flash("Veuillez assigner un commercial.", "danger")
                return redirect(url_for("cspe_index"))

            try:
                owner_id = int(owner_raw)
            except Exception:
                flash("Commercial invalide.", "danger")
                return redirect(url_for("cspe_index"))

            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id
                    FROM users
                    WHERE id = %s
                      AND role = 'commercial'
                """, (owner_id,))
                owner_row = cur.fetchone()

            if not owner_row:
                flash("Commercial introuvable.", "danger")
                return redirect(url_for("cspe_index"))

        else:
            owner_id = user.get("id")

        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO cspe_dossiers (
                    name,
                    notes,
                    owner_id,
                    date_negociation,
                    chiffre_affaire
                )
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            """, (
                name,
                notes or None,
                owner_id,
                date_negociation,
                chiffre_affaire or 0,
            ))
            dossier_id = cur.fetchone()["id"]

        conn.commit()
        flash("Dossier CSPE créé avec succès.", "success")
        return redirect(url_for("cspe_detail", dossier_id=dossier_id))

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur création dossier CSPE : %r", e)
        flash("Erreur lors de la création du dossier CSPE.", "danger")
        return redirect(url_for("cspe_index"))


@app.route("/cspe/<int:dossier_id>", endpoint="cspe_detail")
@login_required
def cspe_detail(dossier_id):
    ensure_cspe_schema()

    if not can_access_cspe_dossier(dossier_id):
        abort(403)

    conn = get_db()
    user = session.get("user") or {}
    role = user.get("role")

    with conn.cursor() as cur:
        cur.execute("""
            SELECT d.*, users.username AS commercial
            FROM cspe_dossiers d
            LEFT JOIN users ON users.id = d.owner_id
            WHERE d.id = %s
        """, (dossier_id,))
        dossier = cur.fetchone()

    if not dossier:
        flash("Dossier CSPE introuvable.", "danger")
        return redirect(url_for("cspe_index"))

    users = []
    if role == "admin":
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, username
                FROM users
                WHERE role = 'commercial'
                ORDER BY username ASC
            """)
            users = cur.fetchall()

    documents = list_cspe_documents(dossier_id)

    return render_template(
        "cspe_detail.html",
        dossier=row_to_obj(dossier),
        users=[row_to_obj(u) for u in users],
        documents=documents,
        current_user=session.get("user"),
        available_endpoints=[rule.endpoint for rule in app.url_map.iter_rules()],
    )


@app.route("/cspe/<int:dossier_id>/edit", methods=["POST"], endpoint="edit_cspe_dossier")
@login_required
def edit_cspe_dossier(dossier_id):
    ensure_cspe_schema()

    if not can_access_cspe_dossier(dossier_id):
        abort(403)

    conn = get_db()
    user = session.get("user") or {}
    role = user.get("role")

    name = (request.form.get("name") or "").strip()
    notes = (request.form.get("notes") or "").strip()
    date_negociation_raw = (request.form.get("date_negociation") or "").strip()
    date_negociation = parse_date_safe(date_negociation_raw)
    chiffre_affaire = parse_amount_safe(
        (request.form.get("chiffre_affaire") or "").strip()
    )

    if not name:
        flash("Le nom du dossier est obligatoire.", "danger")
        return redirect(url_for("cspe_detail", dossier_id=dossier_id))

    if chiffre_affaire is None:
        flash("Le chiffre d'affaires est invalide.", "danger")
        return redirect(url_for("cspe_detail", dossier_id=dossier_id))

    if date_negociation_raw and not date_negociation:
        flash("La date de négociation est invalide.", "danger")
        return redirect(url_for("cspe_detail", dossier_id=dossier_id))

    try:
        if role == "admin":
            owner_raw = (request.form.get("owner_id") or "").strip()

            if not owner_raw:
                flash("Veuillez assigner un commercial.", "danger")
                return redirect(url_for("cspe_detail", dossier_id=dossier_id))

            try:
                owner_id = int(owner_raw)
            except Exception:
                flash("Commercial invalide.", "danger")
                return redirect(url_for("cspe_detail", dossier_id=dossier_id))

            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id
                    FROM users
                    WHERE id = %s
                      AND role = 'commercial'
                """, (owner_id,))
                owner_row = cur.fetchone()

            if not owner_row:
                flash("Commercial introuvable.", "danger")
                return redirect(url_for("cspe_detail", dossier_id=dossier_id))

            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE cspe_dossiers
                    SET
                        name = %s,
                        notes = %s,
                        owner_id = %s,
                        date_negociation = %s,
                        chiffre_affaire = %s
                    WHERE id = %s
                """, (
                    name,
                    notes or None,
                    owner_id,
                    date_negociation,
                    chiffre_affaire or 0,
                    dossier_id,
                ))
        else:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE cspe_dossiers
                    SET
                        name = %s,
                        notes = %s,
                        date_negociation = %s,
                        chiffre_affaire = %s
                    WHERE id = %s
                """, (
                    name,
                    notes or None,
                    date_negociation,
                    chiffre_affaire or 0,
                    dossier_id,
                ))

        conn.commit()
        flash("Dossier CSPE mis à jour.", "success")

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur modification dossier CSPE : %r", e)
        flash("Erreur lors de la mise à jour du dossier CSPE.", "danger")

    return redirect(url_for("cspe_detail", dossier_id=dossier_id))


@app.route("/cspe/<int:dossier_id>/delete", methods=["POST"], endpoint="delete_cspe_dossier")
@login_required
def delete_cspe_dossier(dossier_id):
    ensure_cspe_schema()

    if not can_access_cspe_dossier(dossier_id):
        abort(403)

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM cspe_dossiers WHERE id = %s",
                (dossier_id,),
            )
            dossier = cur.fetchone()

        if not dossier:
            flash("Dossier CSPE introuvable.", "danger")
            return redirect(url_for("cspe_index"))

        delete_cspe_documents_for_dossier(dossier_id)

        with conn.cursor() as cur:
            cur.execute("DELETE FROM cspe_dossiers WHERE id = %s", (dossier_id,))

        conn.commit()
        flash("Dossier CSPE supprimé.", "success")

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur suppression dossier CSPE : %r", e)
        flash("Erreur lors de la suppression du dossier CSPE.", "danger")

    return redirect(url_for("cspe_index"))


@app.route(
    "/cspe/<int:dossier_id>/documents/upload",
    methods=["POST"],
    endpoint="upload_cspe_document",
)
@login_required
def upload_cspe_document(dossier_id):
    ensure_cspe_schema()

    if not can_access_cspe_dossier(dossier_id):
        abort(403)

    if not LOCAL_MODE and not s3:
        flash("Le stockage des documents CSPE est indisponible.", "warning")
        return redirect(url_for("cspe_detail", dossier_id=dossier_id))

    files = request.files.getlist("files")
    if not files:
        legacy_file = request.files.get("file")
        if legacy_file and getattr(legacy_file, "filename", ""):
            files = [legacy_file]

    files = [f for f in files if f and getattr(f, "filename", "")]

    if not files:
        flash("Aucun fichier sélectionné.", "danger")
        return redirect(url_for("cspe_detail", dossier_id=dossier_id))

    manual_name = (request.form.get("doc_name") or "").strip()
    doc_kind = normalize_document_kind(request.form.get("doc_kind") or "")
    auto_name = (request.form.get("auto_name") or "").strip().lower() in {"1", "true", "on", "yes"}
    dossier_name = ""

    if auto_name:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT name FROM cspe_dossiers WHERE id = %s",
                (dossier_id,),
            )
            row = cur.fetchone()
        dossier_name = (row.get("name") or "").strip() if row else ""

    prefix = cspe_storage_prefix(dossier_id, dossier_name or None)
    success_count = 0
    failed = []

    for fichier in files:
        if not allowed_file(fichier.filename):
            failed.append(fichier.filename or "fichier_invalide")
            continue

        try:
            original_name = secure_filename(fichier.filename) or "document"
            ext = os.path.splitext(original_name)[1].lower()
            base_name = build_document_upload_base_name(
                dossier_name or f"dossier_{dossier_id}",
                original_name,
                manual_name=manual_name,
                doc_kind=doc_kind,
                auto_name=auto_name,
            )
            key = f"{prefix}{base_name}{ext}"

            if LOCAL_MODE:
                key = _local_make_non_overwriting_key(key)
                path = local_storage_path(key)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                fichier.save(path)
            else:
                key = _s3_make_non_overwriting_key(AWS_BUCKET, key)
                s3_upload_fileobj(fichier, AWS_BUCKET, key)

            success_count += 1

        except Exception as e:
            logger.exception("Erreur upload document CSPE : %r", e)
            failed.append(fichier.filename or "fichier_erreur")

    if success_count > 0 and not failed:
        flash(f"{success_count} document(s) CSPE ajouté(s).", "success")
    elif success_count > 0:
        flash(f"{success_count} document(s) ajoutés, {len(failed)} échec(s).", "warning")
    else:
        flash("Aucun upload CSPE réussi.", "danger")

    return redirect(url_for("cspe_detail", dossier_id=dossier_id))


@app.route("/cspe/document/preview", endpoint="preview_cspe_document")
@login_required
def preview_cspe_document():
    ensure_cspe_schema()

    key = (request.args.get("key") or "").strip()

    if not key:
        return redirect(request.referrer or url_for("cspe_index"))

    if not can_access_cspe_document_key(key):
        abort(403)

    preview_meta = build_document_preview_meta(key)

    return render_template(
        "document_preview.html",
        document_name=preview_meta["filename"] or "Document CSPE",
        preview_kind=preview_meta["preview_kind"],
        previewable=preview_meta["previewable"],
        inline_url=url_for("inline_cspe_document", key=key),
        download_url=url_for("download_cspe_document", key=key),
    )


@app.route("/cspe/document/inline", endpoint="inline_cspe_document")
@login_required
def inline_cspe_document():
    ensure_cspe_schema()

    key = (request.args.get("key") or "").strip()

    if not key:
        return redirect(request.referrer or url_for("cspe_index"))

    if not can_access_cspe_document_key(key):
        abort(403)

    try:
        if LOCAL_MODE:
            path = local_storage_path(key)
            if not os.path.exists(path):
                flash("Document introuvable.", "danger")
                return redirect(request.referrer or url_for("cspe_index"))
            return send_file(path, as_attachment=False)

        if not s3:
            flash("Ouverture indisponible pour ce document CSPE.", "warning")
            return redirect(request.referrer or url_for("cspe_index"))

        url = s3_presigned_url(key, response_disposition="inline")
        if not url:
            flash("Impossible de generer la previsualisation du document CSPE.", "danger")
            return redirect(request.referrer or url_for("cspe_index"))

        return redirect(url)

    except Exception as e:
        logger.exception("Erreur preview document CSPE : %r", e)
        flash("Erreur lors de l'ouverture du document CSPE.", "danger")
        return redirect(request.referrer or url_for("cspe_index"))


@app.route("/cspe/document/download", endpoint="download_cspe_document")
@login_required
def download_cspe_document():
    ensure_cspe_schema()

    key = (request.args.get("key") or "").strip()

    if not key:
        flash("Document invalide.", "danger")
        return redirect(request.referrer or url_for("cspe_index"))

    if not can_access_cspe_document_key(key):
        abort(403)

    try:
        if LOCAL_MODE:
            path = local_storage_path(key)
            if not os.path.exists(path):
                flash("Document introuvable.", "danger")
                return redirect(request.referrer or url_for("cspe_index"))
            return send_file(path, as_attachment=False)

        if not s3:
            flash("Le stockage des documents CSPE est indisponible.", "warning")
            return redirect(request.referrer or url_for("cspe_index"))

        url = s3_presigned_url(key)
        if not url:
            flash("Impossible de générer le lien du document.", "danger")
            return redirect(request.referrer or url_for("cspe_index"))

        return redirect(url)

    except Exception as e:
        logger.exception("Erreur download document CSPE : %r", e)
        flash("Erreur lors de l'ouverture du document CSPE.", "danger")
        return redirect(request.referrer or url_for("cspe_index"))

def _download_cspe_document_endpoint():
    ensure_cspe_schema()

    key = (request.args.get("key") or "").strip()

    if not key:
        flash("Document invalide.", "danger")
        return redirect(request.referrer or url_for("cspe_index"))

    if not can_access_cspe_document_key(key):
        abort(403)

    try:
        if LOCAL_MODE:
            path = local_storage_path(key)
            if not os.path.exists(path):
                flash("Document introuvable.", "danger")
                return redirect(request.referrer or url_for("cspe_index"))
            return send_file(path, as_attachment=True)

        if not s3:
            flash("Le stockage des documents CSPE est indisponible.", "warning")
            return redirect(request.referrer or url_for("cspe_index"))

        url = s3_presigned_url(key, response_disposition="attachment")
        if not url:
            flash("Impossible de generer le telechargement du document CSPE.", "danger")
            return redirect(request.referrer or url_for("cspe_index"))

        return redirect(url)

    except Exception as e:
        logger.exception("Erreur download document CSPE : %r", e)
        flash("Erreur lors du telechargement du document CSPE.", "danger")
        return redirect(request.referrer or url_for("cspe_index"))


app.view_functions["download_cspe_document"] = login_required(_download_cspe_document_endpoint)


@app.route("/cspe/document/delete", methods=["POST"], endpoint="delete_cspe_document")
@login_required
def delete_cspe_document():
    ensure_cspe_schema()

    key = (request.form.get("key") or "").strip()

    if not key:
        flash("Document invalide.", "danger")
        return redirect(request.referrer or url_for("cspe_index"))

    if not can_access_cspe_document_key(key):
        abort(403)

    try:
        if LOCAL_MODE:
            delete_local_storage_object(key)
        else:
            if not s3:
                flash("Le stockage des documents CSPE est indisponible.", "warning")
                return redirect(request.referrer or url_for("cspe_index"))
            s3.delete_object(Bucket=AWS_BUCKET, Key=key)

        flash("Document CSPE supprimé.", "success")

    except Exception as e:
        logger.exception("Erreur suppression document CSPE : %r", e)
        flash("Erreur lors de la suppression du document CSPE.", "danger")

    return redirect(request.referrer or url_for("cspe_index"))

############################################################
# 13. DEMANDES DE MISE À JOUR DOSSIER (ADMIN)
############################################################

# =========================
# COMMERCIAL → DEMANDE DE MISE À JOUR
# =========================
@app.route("/clients/<int:client_id>/update", methods=["POST"])
@login_required
def update_client(client_id):
    if not can_access_client(client_id):
        abort(403)

    conn = get_db()
    user = session.get("user") or {}
    update_id = None

    update_date = (request.form.get("update_date") or "").strip()
    commentaire = (request.form.get("update_commentaire") or "").strip()

    if not update_date:
        flash("La date de mise à jour est obligatoire.", "danger")
        try:
            return redirect(url_for("client_detail", client_id=client_id))
        except Exception:
            return redirect(url_for("clients"))

    with conn.cursor() as cur:
        cur.execute(
            "SELECT name FROM crm_clients WHERE id = %s",
            (client_id,)
        )
        client = cur.fetchone()

    if not client:
        flash("Dossier introuvable.", "danger")
        return redirect(url_for("clients"))

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO client_updates (
                    client_id,
                    client_name,
                    commercial_id,
                    commercial_name,
                    update_date,
                    commentaire,
                    is_read
                )
                VALUES (%s, %s, %s, %s, %s, %s, 0)
                RETURNING id
                """,
                (
                    client_id,
                    client["name"],
                    user.get("id"),
                    user.get("username"),
                    update_date,
                    commentaire,
                ),
            )
            update_id = cur.fetchone()[0]

        conn.commit()
        flash("Demande de mise à jour envoyée à l’administrateur.", "success")

        update_link = build_app_url(url_for("open_update", update_id=update_id))
        if EMAIL_NOTIFICATIONS_ENABLED:
            email_sent, email_error = send_notification_email(
                subject=f"Nouvelle demande de mise a jour - {client['name']}",
                body=(
                    "Une nouvelle demande de mise a jour vient d'etre creee.\n\n"
                    f"Dossier : {client['name']}\n"
                    f"Commercial : {user.get('username') or 'Inconnu'}\n"
                    f"Date de mise a jour : {update_date}\n"
                    f"Commentaire : {commentaire or '-'}\n\n"
                    f"Ouvrir la demande : {update_link}\n"
                ),
            )

            if not email_sent:
                flash(
                    f"La demande a ete enregistree, mais l'email de notification n'a pas pu etre envoye ({email_error or 'erreur SMTP'}).",
                    "warning",
                )

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur mise a jour client : %r", e)
        flash("Erreur lors de l'envoi de la demande de mise a jour.", "danger")

    try:
        return redirect(url_for("client_detail", client_id=client_id))
    except Exception:
        return redirect(url_for("clients"))


# =========================
# ADMIN → LISTE DES MISES À JOUR
# =========================
@app.route("/admin/updates")
@admin_required
def admin_updates():
    conn = get_db()

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT *
            FROM client_updates
            ORDER BY COALESCE(is_read, 0) ASC, created_at DESC
            """
        )
        rows = cur.fetchall()

    return render_template(
        "admin_updates.html",
        updates=[row_to_obj(r) for r in rows],
    )


# =========================
# ADMIN → OUVERTURE D’UNE MISE À JOUR
# =========================
@app.route("/admin/updates/<int:update_id>/open")
@admin_required
def open_update(update_id):
    conn = get_db()

    with conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM client_updates WHERE id = %s",
            (update_id,)
        )
        upd = cur.fetchone()

    if not upd:
        flash("Mise à jour introuvable.", "danger")
        return redirect(url_for("admin_updates"))

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE client_updates SET is_read = 1 WHERE id = %s",
            (update_id,)
        )

    conn.commit()
    flash("Mise à jour marquée comme lue.", "success")

    try:
        return redirect(url_for("client_detail", client_id=upd["client_id"]))
    except Exception:
        return redirect(url_for("clients"))


# =========================
# ADMIN → SUPPRESSION D’UNE MISE À JOUR
# =========================
@app.route("/admin/updates/<int:update_id>/delete", methods=["POST"])
@admin_required
def delete_update(update_id):
    conn = get_db()
    admin = session.get("user") or {}

    with conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM client_updates WHERE id = %s",
            (update_id,)
        )
        upd = cur.fetchone()

    if not upd:
        flash("Mise à jour introuvable.", "danger")
        return redirect(url_for("admin_updates"))

    # Log suppression (non bloquant)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO update_deletions_log (
                    update_id,
                    client_id,
                    admin_id,
                    admin_username
                )
                VALUES (%s, %s, %s, %s)
                """,
                (
                    upd["id"],
                    upd["client_id"],
                    admin.get("id"),
                    admin.get("username"),
                ),
            )
    except Exception:
        pass

    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM client_updates WHERE id = %s",
            (update_id,)
        )

    conn.commit()
    flash("Demande de mise à jour supprimée.", "success")
    return redirect(url_for("admin_updates"))

############################################################
# 14. CHAT (BACKEND) — VERSION SAFE + MULTI UPLOAD + HEURE PARIS
############################################################

from datetime import timezone
from zoneinfo import ZoneInfo


def _chat_store_file(file_storage):
    """
    Stockage d’une pièce jointe du chat.
    Retourne (file_key, file_name, error_code)
    """
    if not file_storage:
        return (None, None, None)

    if not getattr(file_storage, "filename", None):
        return (None, None, "invalid_file")

    if not allowed_file(file_storage.filename):
        return (None, None, "invalid_file")

    file_name_original = secure_filename(file_storage.filename)
    file_name_clean = clean_filename(file_name_original)

    rnd = secrets.token_hex(6)
    key_raw = f"{CHAT_UPLOAD_PREFIX}{rnd}_{file_name_clean}"

    if LOCAL_MODE:
        try:
            key = _local_make_non_overwriting_key(key_raw)
            path = local_storage_path(key)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            file_storage.save(path)
            return (key, file_name_original, None)
        except Exception as e:
            logger.exception("Erreur upload chat local: %r", e)
            return (None, None, "upload_failed")

    if not s3 or not AWS_BUCKET:
        return (None, None, "upload_unavailable")

    key = _s3_make_non_overwriting_key(AWS_BUCKET, key_raw)

    try:
        s3_upload_fileobj(file_storage, AWS_BUCKET, key)

        return (key, file_name_original, None)

    except ClientError as e:
        logger.error(
            "Erreur upload chat S3 (ClientError): %s",
            getattr(e, "response", None)
        )
        return (None, None, "upload_failed")

    except Exception as e:
        logger.exception("Erreur upload chat S3: %r", e)
        return (None, None, "upload_failed")


def _serialize_chat_datetime(value):
    """
    Sérialise created_at en heure Europe/Paris.
    Compatible timestamps naïfs / timezone-aware.
    """
    if not value:
        return ""

    try:
        paris_tz = ZoneInfo("Europe/Paris")

        if getattr(value, "tzinfo", None) is None:
            value = value.replace(tzinfo=timezone.utc)

        value = value.astimezone(paris_tz)
        return value.strftime("%Y-%m-%d %H:%M:%S")

    except Exception:
        try:
            return str(value)
        except Exception:
            return ""


# =========================================================
# CHAT BOOTSTRAP
# =========================================================
@app.route("/chat/bootstrap")
@chat_required
def chat_bootstrap():
    ensure_chat_schema()

    user = session.get("user") or {}
    user_id = user.get("id")
    role = user.get("role")

    if not user_id:
        return jsonify({
            "success": False,
            "recipients": [],
            "message": "Utilisateur non identifié."
        }), 400

    return jsonify({
        "success": True,
        "recipients": list_chat_recipients(user_id),
        "current_user": {
            "id": user_id,
            "username": user.get("username"),
            "role": role,
            "role_label": chat_role_label(role),
        },
    })


# =========================================================
# CHAT FILE DOWNLOAD
# =========================================================
@app.route("/chat/file")
@chat_required
def download_chat_file():
    ensure_chat_schema()

    key = (request.args.get("key") or "").strip()

    if not key:
        flash("Fichier chat invalide.", "danger")
        return redirect(request.referrer or url_for("dashboard"))

    if not can_access_chat_file_key(key):
        abort(403)

    try:
        if LOCAL_MODE:
            path = local_storage_path(key)
            if not os.path.exists(path):
                flash("Fichier introuvable.", "danger")
                return redirect(request.referrer or url_for("dashboard"))
            return send_file(path, as_attachment=False)

        if not s3:
            flash("Le stockage des pièces jointes du chat est indisponible.", "warning")
            return redirect(request.referrer or url_for("dashboard"))

        url = s3_presigned_url(key)
        if not url:
            flash("Impossible de générer le lien du fichier.", "danger")
            return redirect(request.referrer or url_for("dashboard"))

        return redirect(url)

    except Exception as e:
        logger.exception("Erreur download chat file : %r", e)
        flash("Erreur lors de l'ouverture du fichier du chat.", "danger")
        return redirect(request.referrer or url_for("dashboard"))


# =========================================================
# LOAD MESSAGES
# =========================================================
@app.route("/chat/messages")
@chat_required
def chat_messages():
    ensure_chat_schema()

    limit = request.args.get("limit", "50")

    try:
        limit_int = max(1, min(200, int(limit)))
    except Exception:
        limit_int = 50

    user = session.get("user") or {}
    user_id = user.get("id")

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    m.id,
                    m.user_id,
                    m.username,
                    sender.role AS user_role,
                    m.recipient_id,
                    m.recipient_username,
                    recipient.role AS recipient_role,
                    COALESCE(m.scope, 'broadcast') AS scope,
                    m.message,
                    m.file_key,
                    m.file_name,
                    m.created_at,
                    EXISTS (
                        SELECT 1
                        FROM chat_message_reads sender_reads
                        WHERE sender_reads.message_id = m.id
                          AND sender_reads.user_id = m.recipient_id
                    ) AS direct_read_by_recipient,
                    EXISTS (
                        SELECT 1
                        FROM chat_message_reads my_reads
                        WHERE my_reads.message_id = m.id
                          AND my_reads.user_id = %s
                    ) AS read_by_me
                FROM chat_messages m
                LEFT JOIN users sender ON sender.id = m.user_id
                LEFT JOIN users recipient ON recipient.id = m.recipient_id
                WHERE
                    sender.role IN ('admin', 'commercial')
                    AND (m.recipient_id IS NULL OR recipient.role IN ('admin', 'commercial'))
                    AND (
                        m.user_id = %s
                        OR m.recipient_id = %s
                        OR COALESCE(m.scope, 'broadcast') = 'broadcast'
                    )
                ORDER BY m.id DESC
                LIMIT %s
            """, (user_id, user_id, user_id, limit_int))
            rows = cur.fetchall()

        messages = []
        unread_count = 0

        for r in reversed(rows):

            file_url = None

            if r["file_key"]:
                if LOCAL_MODE:
                    file_url = url_for("download_chat_file", key=r["file_key"])
                elif s3:
                    file_url = s3_presigned_url(r["file_key"])

            scope = r["scope"] or "broadcast"
            is_mine = r["user_id"] == user_id
            is_read = bool(r["direct_read_by_recipient"]) if is_mine else bool(r["read_by_me"])

            if not is_mine and not is_read:
                unread_count += 1

            messages.append({
                "id": r["id"],
                "user_id": r["user_id"],
                "username": r["username"],
                "user_role": r["user_role"],
                "user_role_label": chat_role_label(r["user_role"]),
                "recipient_id": r["recipient_id"],
                "recipient_username": r["recipient_username"],
                "recipient_role": r["recipient_role"],
                "recipient_role_label": chat_role_label(r["recipient_role"]),
                "scope": scope,
                "message": r["message"],
                "file_key": r["file_key"],
                "file_name": r["file_name"],
                "file_url": file_url,
                "created_at": _serialize_chat_datetime(r["created_at"]),
                "is_read": is_read,
                "is_mine": is_mine,
            })

        return jsonify({
            "success": True,
            "messages": messages,
            "unread_count": unread_count,
        })

    except Exception as e:
        logger.exception("Erreur chargement messages chat : %r", e)
        return jsonify({
            "success": False,
            "messages": [],
            "message": "Impossible de charger les messages."
        }), 500


# =========================================================
# SEND MESSAGE (MULTI FILES FIX FINAL)
# =========================================================
@app.route("/chat/send", methods=["POST"])
@chat_required
def chat_send():
    ensure_chat_schema()

    message = (request.form.get("message") or "").strip()
    user = session.get("user") or {}
    user_id = user.get("id")
    user_role = user.get("role")
    recipient_raw = (request.form.get("recipient_id") or "").strip()

    if not user_id or user_role not in CHAT_ALLOWED_ROLES:
        return jsonify({
            "success": False,
            "message": "Acces au chat refuse."
        }), 403

    recipient_id = None
    recipient_username = None
    scope = "broadcast"

    if recipient_raw and recipient_raw not in ("all", "broadcast", "team"):
        try:
            recipient_id = int(recipient_raw)
        except Exception:
            return jsonify({
                "success": False,
                "message": "Destinataire invalide."
            }), 400

        if recipient_id == user_id:
            return jsonify({
                "success": False,
                "message": "Vous ne pouvez pas vous écrire à vous-même."
            }), 400

        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, username, role
                FROM users
                WHERE id = %s
            """, (recipient_id,))
            recipient_row = cur.fetchone()

        if not recipient_row:
            return jsonify({
                "success": False,
                "message": "Destinataire introuvable."
            }), 404

        if recipient_row["role"] not in CHAT_ALLOWED_ROLES:
            return jsonify({
                "success": False,
                "message": "Ce destinataire n'a pas acces au chat."
            }), 403

        recipient_username = recipient_row["username"]
        scope = "direct"

    files = []

    if "file" in request.files:
        raw = request.files.getlist("file")

        for f in raw:
            if f and getattr(f, "filename", ""):
                files.append(f)

    # fallback ultra safe
    if not files:
        for key in request.files:
            f = request.files.get(key)
            if f and getattr(f, "filename", ""):
                files.append(f)

    uploaded_files = []
    errors = []

    for file_obj in files:

        file_key, file_name, file_error = _chat_store_file(file_obj)

        if file_error:
            errors.append(file_obj.filename or "fichier")
            continue

        uploaded_files.append((file_key, file_name))

    if not message and not uploaded_files:
        return jsonify({
            "success": False,
            "message": "Message ou fichier requis."
        }), 400

    conn = get_db()

    try:

        inserted_ids = []

        with conn.cursor() as cur:

            if message:

                cur.execute("""
                    INSERT INTO chat_messages (
                        user_id,
                        username,
                        recipient_id,
                        recipient_username,
                        scope,
                        message,
                        is_read
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, 0)
                    RETURNING id
                """, (
                    user_id,
                    user.get("username"),
                    recipient_id,
                    recipient_username,
                    scope,
                    message,
                ))

                inserted_ids.append(cur.fetchone()["id"])

            for file_key, file_name in uploaded_files:

                cur.execute("""
                    INSERT INTO chat_messages (
                        user_id,
                        username,
                        recipient_id,
                        recipient_username,
                        scope,
                        file_key,
                        file_name,
                        is_read
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 0)
                    RETURNING id
                """, (
                    user_id,
                    user.get("username"),
                    recipient_id,
                    recipient_username,
                    scope,
                    file_key,
                    file_name,
                ))

                inserted_ids.append(cur.fetchone()["id"])

        conn.commit()

        return jsonify({
            "success": True,
            "ids": inserted_ids,
            "uploaded": len(uploaded_files),
            "errors": errors,
            "scope": scope,
            "recipient_id": recipient_id,
            "recipient_username": recipient_username,
        })

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur envoi message chat : %r", e)

        return jsonify({
            "success": False,
            "message": "Erreur lors de l’envoi du message."
        }), 500


# =========================================================
# MARK AS READ
# =========================================================
@app.route("/chat/mark_read", methods=["POST"])
@chat_required
def chat_mark_read():
    ensure_chat_schema()

    u = session.get("user") or {}
    user_id = u.get("id")

    if not user_id:
        return jsonify({
            "success": False,
            "message": "Utilisateur non identifié."
        }), 400

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO chat_message_reads (message_id, user_id)
                SELECT m.id, %s
                FROM chat_messages m
                LEFT JOIN users sender ON sender.id = m.user_id
                LEFT JOIN users recipient ON recipient.id = m.recipient_id
                WHERE m.user_id <> %s
                  AND sender.role IN ('admin', 'commercial')
                  AND (m.recipient_id IS NULL OR recipient.role IN ('admin', 'commercial'))
                  AND (
                      m.recipient_id = %s
                      OR COALESCE(m.scope, 'broadcast') = 'broadcast'
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM chat_message_reads r
                      WHERE r.message_id = m.id
                        AND r.user_id = %s
                  )
            """, (user_id, user_id, user_id, user_id))

        conn.commit()

        return jsonify({"success": True})

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur mark_read chat : %r", e)

        return jsonify({
            "success": False,
            "message": "Impossible de marquer les messages comme lus."
        }), 500
    
############################################################
# 15. ROOT
############################################################

@app.route("/")
def index():
    """
    Point d’entrée de l’application.
    - Si non connecté → redirection login
    - Si connecté → dashboard
    """
    if "user" not in session:
        return redirect(url_for("login"))

    return redirect(url_for("dashboard"))


############################################################
# DEBUG — LISTE DES ROUTES CHARGÉES
############################################################

@app.route("/__routes__")
def debug_routes():
    user = session.get("user") or {}

    if not (LOCAL_MODE or DEBUG or user.get("role") == "admin"):
        abort(404)

    return "<br>".join(sorted(app.view_functions.keys()))


############################################################
# 16. RUN (LOCAL / PROD SAFE)
############################################################

if __name__ == "__main__":
    """
    Lancement de l’application.
    - En local : debug piloté par Config.DEBUG
    - En production (Render) : ce bloc n’est PAS utilisé
      car Gunicorn démarre l’app via `app:app`
    """
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=DEBUG,
    )


# ============================
# FIN PARTIE 4/4
# ============================
