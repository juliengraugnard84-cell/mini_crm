# ============================
# app.py — VERSION COMPLÈTE CORRIGÉE (PARTIE 1/4)
# Objectif: 100% fonctionnalités conservées, aucun doublon de route,
# CSRF sécurisé, update_deletions_log créé, S3 anti-overwrite sans casser.
# ============================

import os
import re
import unicodedata
import secrets
import logging
from datetime import date
from types import SimpleNamespace
from functools import wraps

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

# ✅ PostgreSQL: on utilise DATABASE_URL
DATABASE_URL = getattr(Config, "DATABASE_URL", None) or os.environ.get("DATABASE_URL")

ALLOWED_EXTENSIONS = {
    "pdf",
    "jpg", "jpeg", "png",
    "doc", "docx",
    "xls", "xlsx", "csv",
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

            # ================= CHAT =================
            cur.execute("""
                CREATE TABLE IF NOT EXISTS chat_messages (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER,
                    username TEXT,
                    message TEXT,
                    file_key TEXT,
                    file_name TEXT,
                    is_read INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
                    event_time TIME,
                    created_by INTEGER,
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

if not LOCAL_MODE:
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
else:
    logger.info("ℹ️ Mode local actif : S3 désactivé.")


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


# =========================================================
# PREFIX S3 CLIENT — SOURCE DE VÉRITÉ UNIQUE
# =========================================================

def client_s3_prefix(client_id: int) -> str:
    """
    Préfixe S3 UNIQUE par client :
    clients/<slug_nom>_<client_id>/
    """
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            "SELECT name FROM crm_clients WHERE id = %s",
            (client_id,),
        )
        row = cur.fetchone()

    slug = ""
    if row and row.get("name"):
        slug = slugify(row["name"])

    base = f"{slug}_{client_id}" if slug else f"client_{client_id}"
    return f"clients/{base}/"


# =========================================================
# UPLOAD S3
# =========================================================

def s3_upload_fileobj(fileobj, bucket: str, key: str):
    """
    Upload PRIVÉ S3 (Block Public Access OK).
    """
    if not s3:
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

def s3_presigned_url(key: str, expires_in: int = 3600) -> str:
    """
    Génère une URL signée (lecture privée).
    """
    if LOCAL_MODE or not s3:
        return ""

    try:
        return s3.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": AWS_BUCKET,
                "Key": key,
            },
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


# =========================================================
# LISTING S3
# =========================================================

def s3_list_all_objects(bucket: str, prefix: str | None = None):
    """
    Liste complète S3 avec pagination.
    """
    if not s3:
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
    if not s3:
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

            docs.append({
                "nom": key.split("/")[-1],
                "key": key,
                "taille": item.get("Size", 0),
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
                JOIN crm_clients
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
            JOIN crm_clients ON crm_clients.id = cotations.client_id
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
            JOIN crm_clients ON crm_clients.id = cotations.client_id
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

@app.route("/admin/planning")
@admin_required
def admin_planning():
    conn = get_db()

    # =========================
    # NEGOCIATIONS (COTATIONS)
    # =========================
    with conn.cursor() as cur:
        cur.execute("""
            SELECT
                cotations.id,
                cotations.date_negociation,
                crm_clients.name AS client_name,
                users.username AS commercial_name
            FROM cotations
            JOIN crm_clients ON crm_clients.id = cotations.client_id
            LEFT JOIN users ON users.id = cotations.created_by
            WHERE cotations.date_negociation IS NOT NULL
              AND cotations.date_negociation >= CURRENT_DATE
            ORDER BY cotations.date_negociation ASC
        """)
        cotations = cur.fetchall()

    # =========================
    # DEMANDES DE MISE A JOUR
    # =========================
    with conn.cursor() as cur:
        cur.execute("""
            SELECT
                client_updates.id,
                client_updates.update_date,
                client_updates.commentaire,
                client_updates.client_name,
                client_updates.commercial_name
            FROM client_updates
            WHERE client_updates.update_date IS NOT NULL
              AND client_updates.update_date >= CURRENT_DATE
            ORDER BY client_updates.update_date ASC
        """)
        updates = cur.fetchall()

    # =========================
    # EVENEMENTS ADMIN
    # =========================
    events = []

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
        logger.exception("Erreur chargement events planning : %r", e)
        events = []

    return render_template(
        "admin_planning.html",
        cotations=[row_to_obj(c) for c in cotations],
        updates=[row_to_obj(u) for u in updates],
        events=events
    )


# ===============================
# AJOUT EVENEMENT CALENDRIER
# ===============================
@app.route("/admin/calendar/add", methods=["POST"])
@admin_required
def add_calendar_event():

    conn = get_db()
    user = session.get("user") or {}

    title = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip()
    event_date = (request.form.get("event_date") or "").strip()

    start_time = (request.form.get("start_time") or "").strip()
    end_time = (request.form.get("end_time") or "").strip()

    all_day = request.form.get("all_day") == "on"

    if not title or not event_date:
        flash("Titre et date obligatoires.", "danger")
        return redirect(url_for("admin_planning"))

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

        flash("Événement ajouté au planning.", "success")

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur ajout evenement calendrier : %r", e)
        flash("Erreur lors de l'ajout.", "danger")

    return redirect(url_for("admin_planning"))


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
# 10 TER BIS. API CALENDRIER — NEGOCIATIONS
# (utilisé par FullCalendar dans le planning)
############################################################

@app.route("/api/calendar")
@login_required
def api_calendar():

    conn = get_db()
    user = session.get("user") or {}

    role = user.get("role")
    user_id = user.get("id")

    with conn.cursor() as cur:

        # ADMIN → voit toutes les négociations
        if role == "admin":

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
            """)

        # COMMERCIAL → voit seulement ses négociations
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
                AND cotations.created_by = %s
            """, (user_id,))

        rows = cur.fetchall()

    events = []

    # =====================================================
    # NEGOCIATIONS
    # =====================================================
    for r in rows:

        if r["heure_negociation"]:
            start = f"{r['date_negociation']}T{r['heure_negociation']}"
        else:
            start = f"{r['date_negociation']}"

        events.append({
            "id": f"cotation_{r['id']}",
            "title": f"{r['client_name']} - {r['commercial_name']}",
            "start": start
        })

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

            # Journée entière
            if r.get("all_day"):

                events.append({
                    "id": f"event_{r['id']}",
                    "title": r["title"],
                    "start": str(r["event_date"]),
                    "allDay": True
                })

            else:

                if r["event_time"]:
                    start = f"{r['event_date']}T{r['event_time']}"
                else:
                    start = str(r["event_date"])

                if r.get("end_time"):
                    end = f"{r['event_date']}T{r['end_time']}"
                else:
                    end = None

                events.append({
                    "id": f"event_{r['id']}",
                    "title": r["title"],
                    "start": start,
                    "end": end,
                    "allDay": False
                })

    except Exception as e:
        logger.exception("Erreur chargement events API calendar : %r", e)

    return jsonify(events)

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

            fichiers.append({
                "nom": key,
                "key": key,
                "taille": item.get("Size", 0),
                "date": item.get("LastModified"),
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

        stream = getattr(fichier, "stream", fichier)
        try:
            stream.seek(0)
        except Exception:
            pass

        s3_upload_fileobj(stream, AWS_BUCKET, key)

        flash("Document global uploadé.", "success")

    except Exception as e:
        logger.exception("❌ Erreur upload document global : %r", e)
        flash("Erreur lors de l’upload.", "danger")

    return redirect(url_for("documents"))


# =========================================================
# UPLOAD DOCUMENT PAR DOSSIER CLIENT (MODIFIÉ ✔)
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

    # ✅ NOUVEAU
    doc_name = (request.form.get("doc_name") or "").strip()
    pdl = (request.form.get("pdl") or "").strip()
    pdl = re.sub(r"[^0-9]", "", pdl)

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

    for fichier in files:

        if not allowed_file(fichier.filename):
            failed.append(fichier.filename or "fichier_invalide")
            continue

        try:
            original_name = secure_filename(fichier.filename) or "document"
            original_ext = os.path.splitext(original_name)[1].lower()

            base_name = clean_filename(doc_name) if doc_name else clean_filename(original_name)

            if pdl:
                base_name = f"{base_name}_{pdl}"

            filename = f"{base_name}{original_ext}"

            prefix = client_s3_prefix(client_id)

            key = _s3_make_non_overwriting_key(
                AWS_BUCKET,
                f"{prefix}{filename}"
            )

            stream = getattr(fichier, "stream", fichier)
            try:
                stream.seek(0)
            except Exception:
                pass

            s3_upload_fileobj(stream, AWS_BUCKET, key)

            success_count += 1

        except Exception as e:
            logger.exception("❌ Erreur upload document client : %r", e)
            failed.append(fichier.filename or "fichier_erreur")

    if success_count > 0 and not failed:
        flash(f"{success_count} document(s) ajouté(s) au dossier client.", "success")
    elif success_count > 0 and failed:
        flash(
            f"{success_count} upload(s) OK, {len(failed)} échec(s): {', '.join(failed)}",
            "warning"
        )
    else:
        flash(f"Aucun upload réussi. Échecs: {', '.join(failed)}", "danger")

    return redirect(url_for("client_detail", client_id=client_id))
###########################################################
# 12. CLIENTS (LISTE / CRÉATION / DÉTAIL / MODIFICATION)
# + STATUT + COTATIONS + DELETE CLIENT + TIMELINE FR
# ✅ VERSION FINALE STABLE (100% routes OK + cotation complète)
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


# =========================
# FORMAT DATE FR (TIMELINE)
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
                SELECT id, username, role
                FROM users
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
                    WHERE crm_clients.name ILIKE %s
                    ORDER BY crm_clients.created_at DESC
                """, (f"%{q}%",))
            else:
                cur.execute("""
                    SELECT crm_clients.*, users.username AS commercial
                    FROM crm_clients
                    LEFT JOIN users ON users.id = crm_clients.owner_id
                    ORDER BY crm_clients.created_at DESC
                """)

        else:

            if q:
                cur.execute("""
                    SELECT crm_clients.*, users.username AS commercial
                    FROM crm_clients
                    LEFT JOIN users ON users.id = crm_clients.owner_id
                    WHERE crm_clients.owner_id = %s
                      AND crm_clients.name ILIKE %s
                    ORDER BY crm_clients.created_at DESC
                """, (user_id, f"%{q}%"))
            else:
                cur.execute("""
                    SELECT crm_clients.*, users.username AS commercial
                    FROM crm_clients
                    LEFT JOIN users ON users.id = crm_clients.owner_id
                    WHERE crm_clients.owner_id = %s
                    ORDER BY crm_clients.created_at DESC
                """, (user_id,))

        rows = cur.fetchall()

    en_cours, en_attente, gagnes, perdus = [], [], [], []

    for r in rows:
        st = (r["status"] or "en_cours").lower()

        if st == "gagne":
            gagnes.append(r)
        elif st == "perdu":
            perdus.append(r)
        elif st == "en_attente":
            en_attente.append(r)
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
# CLIENT — DETAIL
# =========================
@app.route("/clients/<int:client_id>", endpoint="client_detail")
@login_required
def client_detail(client_id):

    if not can_access_client(client_id):
        abort(403)

    conn = get_db()

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

    # Ressources partagées affichées dans le template
    shared_mandats = []
    shared_resiliations = []

    if not LOCAL_MODE and s3:
        try:
            items = s3_list_all_objects(AWS_BUCKET, prefix=SHARED_PREFIX)

            for item in items:
                key = item.get("Key")
                if not key or key.endswith("/"):
                    continue

                doc = {
                    "nom": key.replace(SHARED_PREFIX, "", 1),
                    "key": key,
                    "taille": item.get("Size", 0),
                    "date": item.get("LastModified"),
                }

                if key.startswith(f"{SHARED_PREFIX}mandats/"):
                    shared_mandats.append(doc)
                elif key.startswith(f"{SHARED_PREFIX}resiliations/"):
                    shared_resiliations.append(doc)

        except Exception as e:
            logger.exception("Erreur chargement ressources partagées client_detail : %r", e)

    with conn.cursor() as cur:
        cur.execute("""
            SELECT *
            FROM cotations
            WHERE client_id = %s
            ORDER BY date_creation DESC
        """, (client_id,))
        cotations = cur.fetchall()

    with conn.cursor() as cur:
        cur.execute("""
            SELECT * FROM (
                SELECT
                    'client' AS type,
                    created_at AS date,
                    'Création du client' AS title,
                    COALESCE(notes, '') AS description
                FROM crm_clients
                WHERE id = %s

                UNION ALL

                SELECT
                    'cotation' AS type,
                    date_creation AS date,
                    'Nouvelle cotation #' || id AS title,
                    COALESCE(commentaire, '') AS description
                FROM cotations
                WHERE client_id = %s
            ) t
            ORDER BY COALESCE(date, CURRENT_TIMESTAMP) DESC
        """, (client_id, client_id))
        timeline = cur.fetchall()

    with conn.cursor() as cur:
        cur.execute("""
            SELECT *
            FROM client_updates
            WHERE client_id = %s
            ORDER BY update_date DESC
        """, (client_id,))
        updates = cur.fetchall()

    return render_template(
        "client_detail.html",
        client=row_to_obj(client),
        documents=documents,
        cotations=[row_to_obj(c) for c in cotations],
        timeline=[row_to_obj(t) for t in timeline],
        updates=[row_to_obj(u) for u in updates],
        shared_mandats=shared_mandats,
        shared_resiliations=shared_resiliations,
    )


# =========================
# CLIENT — CREATION
# =========================
@app.route("/clients/new", methods=["POST"])
@login_required
def create_client():

    conn = get_db()
    user = session.get("user") or {}

    role = user.get("role")
    user_id = user.get("id")

    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    address = (request.form.get("address") or "").strip()
    notes = (request.form.get("notes") or "").strip()
    status = (request.form.get("status") or "en_cours").strip().lower()
    siret = (request.form.get("siret") or "").strip()
    gerant_nom = (request.form.get("gerant_nom") or "").strip()

    if not name:
        flash("Nom du client obligatoire.", "danger")
        return redirect(url_for("clients"))

    allowed_status = {"en_cours", "en_attente", "gagne", "perdu", "nouveau"}
    if status not in allowed_status:
        status = "en_cours"

    owner_id = user_id

    if role == "admin":
        raw_owner_id = request.form.get("owner_id")
        parsed_owner_id = parse_int_safe(raw_owner_id)
        if parsed_owner_id:
            owner_id = parsed_owner_id

    commercial = (request.form.get("commercial") or "").strip()

    try:
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
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
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

        conn.commit()
        flash("Client créé avec succès.", "success")

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur création client : %r", e)
        flash("Erreur lors de la création.", "danger")

    return redirect(url_for("clients"))


# =========================
# 🔥 COTATION — CREATION COMPLETE
# =========================
@app.route(
    "/clients/<int:client_id>/cotation",
    methods=["POST"],
    endpoint="create_cotation"
)
@login_required
def create_cotation(client_id):

    if not can_access_client(client_id):
        abort(403)

    conn = get_db()
    user = session.get("user") or {}
    f = request.form

    try:
        with conn.cursor() as cur:

            cur.execute("""
                INSERT INTO cotations (
                    client_id,
                    date_negociation,
                    heure_negociation,
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
                    type_compteur,
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
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s
                )
            """, (
                client_id,
                parse_date_safe(f.get("date_negociation")),
                parse_time_safe(f.get("heure_negociation")),
                f.get("energie_type") or None,
                f.get("pdl_pce") or None,
                parse_date_safe(f.get("date_echeance")),
                f.get("fournisseur_actuel") or None,
                f.get("entreprise_nom") or None,
                f.get("siret") or None,
                f.get("adresse_facturation") or None,
                f.get("adresse_consommation") or None,
                f.get("signataire_nom") or None,
                f.get("signataire_tel") or None,
                f.get("signataire_email") or None,
                f.get("commentaire") or None,
                user.get("id"),
                f.get("type_compteur") or None,
                f.get("signataire_mobile") or None,
                f.get("site_nom") or None,
                f.get("fonction_signataire") or None,
                f.get("code_naf") or None,
                parse_date_safe(f.get("date_remise_offre")),
                parse_date_safe(f.get("elec_debut_fourniture")),
                parse_date_safe(f.get("elec_fin_fourniture")),
                parse_int_safe(f.get("elec_nb_mois")),
                f.get("elec_segment") or None,
                f.get("formule_acheminement") or None,
                f.get("elec_car") or None,
                f.get("puissance_souscrite") or None,
                f.get("elec_fournisseur_actuel") or None,
                f.get("pointe") or None,
                f.get("hph") or None,
                f.get("hch") or None,
                f.get("hpr") or None,
                f.get("hce") or None,
                parse_date_safe(f.get("gaz_debut_fourniture")),
                parse_date_safe(f.get("gaz_fin_fourniture")),
                parse_int_safe(f.get("gaz_nb_mois")),
                f.get("pce") or None,
                f.get("gaz_segment") or None,
                f.get("profil") or None,
                f.get("gaz_car") or None,
                f.get("gaz_fournisseur_actuel") or None,
            ))

        conn.commit()
        flash("Cotation créée avec succès.", "success")

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur création cotation : %r", e)
        flash("Erreur lors de la création.", "danger")

    return redirect(url_for("client_detail", client_id=client_id))


# =========================
# 🔥 DELETE CLIENT
# =========================
@app.route(
    "/clients/<int:client_id>/delete",
    methods=["POST"],
    endpoint="delete_client"
)
@login_required
def delete_client(client_id):

    if not can_access_client(client_id):
        abort(403)

    conn = get_db()

    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, name FROM crm_clients WHERE id = %s",
            (client_id,)
        )
        client = cur.fetchone()

    if not client:
        flash("Client introuvable.", "danger")
        return redirect(url_for("clients"))

    try:
        if not LOCAL_MODE and s3:
            try:
                prefix = client_s3_prefix(client_id)
                items = s3_list_all_objects(AWS_BUCKET, prefix=prefix)

                for item in items:
                    key = item.get("Key")
                    if key and not key.endswith("/"):
                        try:
                            s3.delete_object(Bucket=AWS_BUCKET, Key=key)
                        except Exception as e:
                            logger.exception("Erreur suppression document S3 client : %r", e)

                legacy_prefix = f"clients/{client_id}/"
                legacy_items = s3_list_all_objects(AWS_BUCKET, prefix=legacy_prefix)

                for item in legacy_items:
                    key = item.get("Key")
                    if key and not key.endswith("/"):
                        try:
                            s3.delete_object(Bucket=AWS_BUCKET, Key=key)
                        except Exception as e:
                            logger.exception("Erreur suppression document S3 legacy : %r", e)

            except Exception as e:
                logger.exception("Erreur nettoyage S3 client : %r", e)

        with conn.cursor() as cur:
            cur.execute("DELETE FROM cotations WHERE client_id = %s", (client_id,))
            cur.execute("DELETE FROM client_updates WHERE client_id = %s", (client_id,))
            cur.execute("DELETE FROM revenus WHERE client_id = %s", (client_id,))
            cur.execute("DELETE FROM crm_clients WHERE id = %s", (client_id,))

        conn.commit()
        flash("Dossier client supprimé avec succès.", "success")

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur suppression client : %r", e)
        flash("Erreur lors de la suppression du dossier.", "danger")

    return redirect(url_for("clients"))


# =========================
# STATUS
# =========================
@app.route(
    "/clients/<int:client_id>/status",
    methods=["POST"],
    endpoint="update_client_status"
)
@login_required
def update_client_status(client_id):

    if not can_access_client(client_id):
        abort(403)

    conn = get_db()
    new_status = (request.form.get("status") or "").strip().lower()

    allowed_status = {"en_cours", "en_attente", "gagne", "perdu"}

    if new_status not in allowed_status:
        flash("Statut invalide.", "danger")
        return redirect(url_for("clients"))

    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE crm_clients
                SET status = %s
                WHERE id = %s
            """, (new_status, client_id))

        conn.commit()
        flash("Statut mis à jour.", "success")

    except Exception as e:
        conn.rollback()
        logger.exception("Erreur update status : %r", e)
        flash("Erreur lors de la mise à jour.", "danger")

    return redirect(url_for("clients"))
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

    conn.commit()
    flash("Demande de mise à jour envoyée à l’administrateur.", "success")

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
    Stockage d’une pièce jointe du chat en S3 PRIVÉ.
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

    if LOCAL_MODE or not s3:
        return (None, None, "upload_unavailable")

    rnd = secrets.token_hex(6)
    key_raw = f"chat/{rnd}_{file_name_clean}"
    key = _s3_make_non_overwriting_key(AWS_BUCKET, key_raw)

    try:
        stream = getattr(file_storage, "stream", file_storage)
        try:
            stream.seek(0)
        except Exception:
            pass

        s3_upload_fileobj(stream, AWS_BUCKET, key)

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
# LOAD MESSAGES
# =========================================================
@app.route("/chat/messages")
@login_required
def chat_messages():

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
                    id,
                    user_id,
                    username,
                    message,
                    file_key,
                    file_name,
                    created_at,
                    COALESCE(is_read, 0) AS is_read
                FROM chat_messages
                ORDER BY id DESC
                LIMIT %s
            """, (limit_int,))
            rows = cur.fetchall()

        messages = []

        for r in reversed(rows):

            file_url = None

            if r["file_key"] and not LOCAL_MODE and s3:
                file_url = s3_presigned_url(r["file_key"])

            messages.append({
                "id": r["id"],
                "user_id": r["user_id"],
                "username": r["username"],
                "message": r["message"],
                "file_key": r["file_key"],
                "file_name": r["file_name"],
                "file_url": file_url,
                "created_at": _serialize_chat_datetime(r["created_at"]),
                "is_read": bool(r["is_read"]),
                "is_mine": r["user_id"] == user_id,
            })

        return jsonify({
            "success": True,
            "messages": messages,
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
@login_required
def chat_send():

    message = (request.form.get("message") or "").strip()
    user = session.get("user") or {}

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

            # MESSAGE SEUL
            if message and not uploaded_files:

                cur.execute("""
                    INSERT INTO chat_messages (
                        user_id,
                        username,
                        message,
                        is_read
                    )
                    VALUES (%s, %s, %s, 0)
                    RETURNING id
                """, (
                    user.get("id"),
                    user.get("username"),
                    message,
                ))

                inserted_ids.append(cur.fetchone()["id"])

            # FICHIERS
            for file_key, file_name in uploaded_files:

                cur.execute("""
                    INSERT INTO chat_messages (
                        user_id,
                        username,
                        message,
                        file_key,
                        file_name,
                        is_read
                    )
                    VALUES (%s, %s, %s, %s, %s, 0)
                    RETURNING id
                """, (
                    user.get("id"),
                    user.get("username"),
                    message if message else None,
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
@login_required
def chat_mark_read():

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
                UPDATE chat_messages
                SET is_read = 1
                WHERE COALESCE(is_read, 0) = 0
                  AND user_id <> %s
            """, (user_id,))

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


############################################################
# DEBUG — LISTE DES ROUTES CHARGÉES
############################################################
@app.route("/__routes__")
def debug_routes():
    return "<br>".join(sorted(app.view_functions.keys()))


# ============================
# FIN PARTIE 4/4
# ============================