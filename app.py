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

            # ================= LOG SUPPRESSION UPDATES =================
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
                cur.execute(
                    """
                    INSERT INTO users (username, password_hash, role)
                    VALUES (%s, %s, %s)
                    """,
                    (
                        "admin",
                        generate_password_hash(ADMIN_DEFAULT_PASSWORD),
                        "admin",
                    ),
                )

            # ================= MIGRATIONS SAFE =================
            # Alignement strict avec les routes existantes

            # crm_clients
            _try_add_column(conn, "crm_clients", "siret TEXT")

            # cotations
            _try_add_column(conn, "cotations", "type_compteur TEXT")
            _try_add_column(conn, "cotations", "heure_negociation TIME")
            _try_add_column(conn, "cotations", "signataire_mobile TEXT")

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


# 🚨 IMPORTANT
# ❌ NE PAS APPELER init_db() AUTOMATIQUEMENT
# ✅ À exécuter UNE SEULE FOIS manuellement si nécessaire


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
        )
        logger.info("S3 connecté | bucket=%s | region=%s", AWS_BUCKET, AWS_REGION)
    except Exception as e:
        logger.exception("❌ Erreur connexion S3 : %r", e)
        s3 = None
else:
    logger.info("ℹ️ Mode local actif : S3 désactivé.")


def allowed_file(filename: str) -> bool:
    """
    Vérifie extension + bloque doubles extensions dangereuses.
    """
    if not filename or "." not in filename:
        return False

    lowered = filename.lower()

    # Blocage extensions exécutables
    if re.search(r"\.(exe|js|bat|cmd|sh|php|pl|py)\b", lowered):
        return False

    ext = lowered.rsplit(".", 1)[1]
    return ext in ALLOWED_EXTENSIONS


def clean_filename(filename: str) -> str:
    """
    Nettoyage nom de fichier (ASCII / safe S3).
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
    text = re.sub(r"[^a-zA-Z0-9]+", "_", text).strip("_").lower()
    return text


def client_s3_prefix(client_id: int) -> str:
    """
    Préfixe S3 unique par client :
    clients/<slug_nom>_<id>/
    """
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            "SELECT name FROM crm_clients WHERE id = %s",
            (client_id,),
        )
        row = cur.fetchone()

    base = f"client_{client_id}"
    if row and row["name"]:
        slug = slugify(row["name"])
        if slug:
            base = f"{slug}_{client_id}"

    return f"clients/{base}/"


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

    s3.upload_fileobj(
        stream,
        bucket,
        key,
        ExtraArgs={
            "ContentType": getattr(
                fileobj, "mimetype", None
            ) or "application/octet-stream"
        },
    )


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
            getattr(e, "response", None)
        )
        return ""
    except Exception as e:
        logger.exception("Erreur presigned URL S3 : %r", e)
        return ""


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
        items.extend(resp.get("Contents") or [])

        if resp.get("IsTruncated"):
            token = resp.get("NextContinuationToken")
        else:
            break

    return items


def _s3_object_exists(bucket: str, key: str) -> bool:
    """
    Test existence objet S3, sans casser le comportement.
    """
    if not s3:
        return False

    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        code = (e.response or {}).get("Error", {}).get("Code", "")
        if code in ("404", "NoSuchKey", "NotFound"):
            return False
        return False
    except Exception:
        return False


def _s3_make_non_overwriting_key(bucket: str, key: str) -> str:
    """
    Conserve le nom original, mais si collision → suffixe aléatoire.
    """
    if not _s3_object_exists(bucket, key):
        return key

    base, ext = os.path.splitext(key)
    for _ in range(20):
        candidate = f"{base}_{secrets.token_hex(3)}{ext}"
        if not _s3_object_exists(bucket, candidate):
            return candidate

    return f"{base}_{secrets.token_hex(8)}{ext}"


def list_client_documents(client_id: int):
    """
    Liste documents d’un client.
    - PROD : URL signée
    - LOCAL : liste visible sans URL
    """
    if not s3:
        return []

    prefix = client_s3_prefix(client_id)
    docs = []

    try:
        items = s3_list_all_objects(AWS_BUCKET, prefix=prefix)

        for item in items:
            key = item.get("Key")
            if not key or key.endswith("/"):
                continue

            docs.append(
                {
                    "nom": key.replace(prefix, "", 1),
                    "key": key,
                    "taille": item.get("Size", 0),
                    "url": (
                        s3_presigned_url(key)
                        if not LOCAL_MODE
                        else None
                    ),
                }
            )

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
    if not client_id:
        return False

    user = session.get("user")
    if not user:
        return False

    # Admin = accès total
    if user.get("role") == "admin":
        return True

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            "SELECT owner_id FROM crm_clients WHERE id = %s",
            (client_id,),
        )
        row = cur.fetchone()

    if not row:
        return False

    return row["owner_id"] == user.get("id")


def get_current_user():
    """
    Retourne l'utilisateur courant sous forme d'objet
    utilisable dans Python ET Jinja.
    """
    u = session.get("user")
    return SimpleNamespace(**u) if u else None


def format_date_safe(value):
    """
    Sécurise l'affichage des dates dans les templates :
    - accepte datetime
    - accepte date
    - accepte string
    - empêche les erreurs .strftime sur str
    """
    if not value:
        return "—"

    # datetime / date
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d")

    # string ISO ou autre
    try:
        return str(value)[:10]
    except Exception:
        return "—"


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
    (Comportement conservé : flash + redirect dashboard)
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
# CSRF — VERSION SAFE (sans casser les endpoints existants)
############################################################

@app.before_request
def csrf_protect():
    """
    CSRF SAFE :
    - Génère toujours un token
    - Bloque toute requête mutante sans token (sauf endpoints exemptés)
    - Supporte token en form OU header
    """

    # Génération du token
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    # Méthodes non mutantes
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return

    # Endpoint exempté
    if request.endpoint in CSRF_EXEMPT_ENDPOINTS:
        return

    sent_token = (
        request.form.get("csrf_token")
        or request.headers.get("X-CSRF-Token")
        or request.headers.get("X-Csrf-Token")
    )

    # ✅ SAFE : token obligatoire (sinon fail) — évite contournement par absence de token
    if not sent_token or sent_token != session.get("csrf_token"):
        abort(403)


############################################################
# 6. VARIABLES GLOBALES POUR LES TEMPLATES
############################################################

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

    return dict(
        current_user=current_user,
        csrf_token=session.get("csrf_token"),
        format_date=format_date_safe,
        unread_cotations=unread_cotations,
        unread_updates=unread_updates,
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
############################################################

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

    # =====================================================
    # DONNÉES ADMIN (TOUJOURS CALCULÉES – SAFE)
    # =====================================================
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM crm_clients")
        total_clients = cur.fetchone()[0]

        cur.execute("""
            SELECT name, email, created_at
            FROM crm_clients
            ORDER BY created_at DESC
            LIMIT 5
        """)
        last_clients = cur.fetchall()

        cur.execute("SELECT COALESCE(SUM(montant), 0) FROM revenus")
        total_ca = cur.fetchone()[0]

        cur.execute("""
            SELECT montant, date, commercial
            FROM revenus
            ORDER BY date::date DESC, id DESC
            LIMIT 1
        """)
        last_rev = cur.fetchone()

    # =====================================================
    # DOCUMENTS (ADMIN)
    # =====================================================
    total_docs = 0
    if not LOCAL_MODE and s3:
        try:
            items = s3_list_all_objects(AWS_BUCKET)
            total_docs = len([f for f in items if not f["Key"].endswith("/")])
        except Exception:
            total_docs = 0

    # =====================================================
    # COTATIONS ADMIN
    # =====================================================
    unread_cotations = 0
    cotations_admin = []

    if role == "admin":
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM cotations WHERE COALESCE(is_read,0)=0")
            unread_cotations = cur.fetchone()[0]

            cur.execute("""
                SELECT cotations.*, crm_clients.name AS client_name
                FROM cotations
                JOIN crm_clients ON crm_clients.id = cotations.client_id
                WHERE COALESCE(cotations.is_read,0)=0
                ORDER BY cotations.date_creation DESC
            """)
            cotations_admin = cur.fetchall()

    # =====================================================
    # DONNÉES COMMERCIAL
    # =====================================================
    commercial_stats = None
    commercial_clients = []
    commercial_cotations = []

    if role == "commercial":
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM crm_clients WHERE owner_id=%s",
                (user_id,)
            )
            nb_clients = cur.fetchone()[0]

            cur.execute("""
                SELECT COALESCE(SUM(montant),0)
                FROM revenus
                WHERE commercial=%s
            """, (username,))
            ca_total_com = cur.fetchone()[0]

            cur.execute("""
                SELECT COALESCE(SUM(montant),0)
                FROM revenus
                WHERE commercial=%s
                  AND date_trunc('month', date::date)
                      = date_trunc('month', CURRENT_DATE)
            """, (username,))
            ca_mois_com = cur.fetchone()[0]

            cur.execute("""
                SELECT COUNT(*)
                FROM cotations
                WHERE created_by=%s
                  AND COALESCE(status,'')='nouvelle'
            """, (user_id,))
            cotations_attente = cur.fetchone()[0]

            commercial_stats = {
                "nb_clients": nb_clients,
                "ca_total": ca_total_com,
                "ca_mois": ca_mois_com,
                "cotations_attente": cotations_attente,
            }

            cur.execute("""
                SELECT id, name, status, created_at
                FROM crm_clients
                WHERE owner_id=%s
                ORDER BY created_at DESC
                LIMIT 5
            """, (user_id,))
            commercial_clients = cur.fetchall()

            cur.execute("""
                SELECT *
                FROM cotations
                WHERE created_by=%s
                ORDER BY date_creation DESC
                LIMIT 5
            """, (user_id,))
            commercial_cotations = cur.fetchall()

    # =====================================================
    # PIPELINE (ADMIN & COMMERCIAL)
    # =====================================================
    with conn.cursor() as cur:
        if role == "admin":
            cur.execute("""
                SELECT crm_clients.*, users.username AS commercial
                FROM crm_clients
                LEFT JOIN users ON users.id = crm_clients.owner_id
            """)
        else:
            cur.execute("""
                SELECT crm_clients.*, users.username AS commercial
                FROM crm_clients
                LEFT JOIN users ON users.id = crm_clients.owner_id
                WHERE crm_clients.owner_id = %s
            """, (user_id,))
        rows = cur.fetchall()

    pipeline_en_cours = []
    pipeline_gagnes = []
    pipeline_perdus = []

    for r in rows:
        status = (r["status"] or "en_cours").lower()
        obj = row_to_obj(r)

        if status == "gagne":
            pipeline_gagnes.append(obj)
        elif status == "perdu":
            pipeline_perdus.append(obj)
        else:
            pipeline_en_cours.append(obj)

    # =====================================================
    # RENDER DASHBOARD
    # =====================================================
    return render_template(
        "dashboard.html",

        total_clients=total_clients,
        total_ca=total_ca,
        total_docs=total_docs,
        last_clients=last_clients,
        last_rev=row_to_obj(last_rev) if last_rev else None,

        pipeline_en_cours=pipeline_en_cours,
        pipeline_gagnes=pipeline_gagnes,
        pipeline_perdus=pipeline_perdus,

        unread_cotations=unread_cotations,
        cotations_admin=[row_to_obj(r) for r in cotations_admin],

        commercial_stats=commercial_stats,
        commercial_clients=[row_to_obj(c) for c in commercial_clients],
        commercial_cotations=[row_to_obj(c) for c in commercial_cotations],
    )


# =========================
# CHIFFRE D’AFFAIRES (MENU)
# =========================
@app.route("/chiffre-affaire", endpoint="chiffre_affaire")
@login_required
def chiffre_affaire():
    conn = get_db()
    user = session.get("user")

    role = user["role"]
    username = user["username"]

    ca_annuel_perso = 0
    ca_mensuel_perso = 0
    ca_perso_par_mois = []

    clients = []
    global_par_mois = []
    historique_ca = []

    with conn.cursor() as cur:
        if role == "admin":
            cur.execute("SELECT COALESCE(SUM(montant),0) FROM revenus")
            ca_annuel_perso = cur.fetchone()[0]

            cur.execute("""
                SELECT COALESCE(SUM(montant),0)
                FROM revenus
                WHERE date_trunc('month', date::date)
                      = date_trunc('month', CURRENT_DATE)
            """)
            ca_mensuel_perso = cur.fetchone()[0]

            cur.execute("SELECT id, name FROM crm_clients ORDER BY name")
            clients = cur.fetchall()

            cur.execute("""
                SELECT TO_CHAR(date::date,'YYYY-MM') AS mois,
                       SUM(montant) AS total
                FROM revenus
                GROUP BY mois
                ORDER BY mois ASC
            """)
            global_par_mois = cur.fetchall()

            cur.execute("""
                SELECT revenus.id, revenus.date, revenus.montant,
                       revenus.commercial,
                       crm_clients.name AS client_name
                FROM revenus
                JOIN crm_clients ON crm_clients.id = revenus.client_id
                ORDER BY date::date DESC, revenus.id DESC
            """)
            historique_ca = cur.fetchall()

        else:
            cur.execute("""
                SELECT COALESCE(SUM(montant),0)
                FROM revenus
                WHERE commercial=%s
            """, (username,))
            ca_annuel_perso = cur.fetchone()[0]

            cur.execute("""
                SELECT COALESCE(SUM(montant),0)
                FROM revenus
                WHERE commercial=%s
                  AND date_trunc('month', date::date)
                      = date_trunc('month', CURRENT_DATE)
            """, (username,))
            ca_mensuel_perso = cur.fetchone()[0]

            cur.execute("""
                SELECT TO_CHAR(date::date,'YYYY-MM') AS mois,
                       SUM(montant) AS total
                FROM revenus
                WHERE commercial=%s
                GROUP BY mois
                ORDER BY mois ASC
            """, (username,))
            ca_perso_par_mois = cur.fetchall()

    return render_template(
        "chiffre_affaire.html",
        ca_annuel_perso=ca_annuel_perso,
        ca_mensuel_perso=ca_mensuel_perso,
        ca_perso_par_mois=[row_to_obj(r) for r in ca_perso_par_mois],
        clients=[row_to_obj(c) for c in clients],
        global_par_mois=[row_to_obj(r) for r in global_par_mois],
        historique_ca=[row_to_obj(r) for r in historique_ca],
    )



############################################################
# 9. ADMIN — UTILISATEURS
############################################################

@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    conn = get_db()

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        role = (request.form.get("role") or "").strip()

        if not username or not password or not role:
            flash("Tous les champs sont obligatoires.", "danger")
            return redirect(url_for("admin_users"))

        if len(password) < 10:
            flash("Mot de passe trop court (min 10 caractères).", "danger")
            return redirect(url_for("admin_users"))

        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE username=%s", (username,))
            if cur.fetchone():
                flash("Nom d'utilisateur déjà utilisé.", "danger")
                return redirect(url_for("admin_users"))

        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES (%s, %s, %s)
                """,
                (username, generate_password_hash(password), role),
            )

        conn.commit()
        flash("Utilisateur créé.", "success")
        return redirect(url_for("admin_users"))

    with conn.cursor() as cur:
        cur.execute("SELECT id, username, role FROM users ORDER BY id ASC")
        users = cur.fetchall()

    return render_template(
        "admin_users.html",
        users=[row_to_obj(u) for u in users],
    )


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    if user_id == 1:
        flash("Impossible de supprimer l’administrateur principal.", "danger")
        return redirect(url_for("admin_users"))

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM users WHERE id=%s", (user_id,))

    conn.commit()
    flash("Utilisateur supprimé.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/reset_password", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    new_password = (request.form.get("new_password") or "").strip()

    if len(new_password) < 10:
        flash("Mot de passe trop court (min 10 caractères).", "danger")
        return redirect(url_for("admin_users"))

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE users SET password_hash=%s WHERE id=%s",
            (generate_password_hash(new_password), user_id),
        )

    conn.commit()
    flash("Mot de passe réinitialisé.", "success")
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
        cur.execute("UPDATE cotations SET is_read=1 WHERE id=%s", (cotation_id,))
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
        cur.execute("DELETE FROM cotations WHERE id=%s", (cotation_id,))
    conn.commit()
    flash("Cotation supprimée.", "success")
    return redirect(url_for("admin_cotations"))


############################################################
# 11. DOCUMENTS GLOBAUX (ADMIN)
############################################################

@app.route("/documents")
@admin_required
def documents():
    if LOCAL_MODE or not s3:
        return render_template("documents.html", fichiers=[])

    fichiers = []
    for item in s3_list_all_objects(AWS_BUCKET, prefix="clients/"):
        key = item.get("Key")
        if key and not key.endswith("/"):
            fichiers.append(
                {
                    "nom": key,
                    "taille": item.get("Size", 0),
                    "url": s3_presigned_url(key),
                }
            )

    return render_template("documents.html", fichiers=fichiers)


############################################################
# 12. CLIENTS (LISTE / CRÉATION / DÉTAIL) + STATUT + COTATIONS
############################################################

# =========================
# CLIENT — CRÉATION
# =========================
@app.route("/clients/new", methods=["GET", "POST"])
@login_required
def new_client():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        address = (request.form.get("address") or "").strip()
        siret = (request.form.get("siret") or "").strip()

        if not name:
            flash("Le nom du client est obligatoire.", "danger")
            return render_template("new_client.html")

        user = session.get("user") or {}
        owner_id = user.get("id")

        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO crm_clients (
                    name, email, phone, address, siret, owner_id, status
                )
                VALUES (%s, %s, %s, %s, %s, %s, 'en_cours')
                RETURNING id
                """,
                (name, email, phone, address, siret, owner_id),
            )
            client_id = cur.fetchone()[0]

        conn.commit()
        flash("Dossier client créé.", "success")
        return redirect(url_for("client_detail", client_id=client_id))

    return render_template("new_client.html")


# =========================
# CLIENT — LISTE + RECHERCHE + PIPELINE (EN COURS / GAGNÉ / PERDU)
# =========================
@app.route("/clients")
@login_required
def clients():
    conn = get_db()
    q = (request.args.get("q") or "").strip()

    user = session.get("user") or {}
    role = user.get("role")
    user_id = user.get("id")

    with conn.cursor() as cur:
        if role == "admin":
            if q:
                cur.execute(
                    """
                    SELECT crm_clients.*, users.username AS commercial
                    FROM crm_clients
                    LEFT JOIN users ON users.id = crm_clients.owner_id
                    WHERE crm_clients.name ILIKE %s
                    ORDER BY crm_clients.created_at DESC
                    """,
                    (f"%{q}%",),
                )
            else:
                cur.execute(
                    """
                    SELECT crm_clients.*, users.username AS commercial
                    FROM crm_clients
                    LEFT JOIN users ON users.id = crm_clients.owner_id
                    ORDER BY crm_clients.created_at DESC
                    """
                )
        else:
            if q:
                cur.execute(
                    """
                    SELECT crm_clients.*, users.username AS commercial
                    FROM crm_clients
                    LEFT JOIN users ON users.id = crm_clients.owner_id
                    WHERE crm_clients.owner_id=%s
                      AND crm_clients.name ILIKE %s
                    ORDER BY crm_clients.created_at DESC
                    """,
                    (user_id, f"%{q}%"),
                )
            else:
                cur.execute(
                    """
                    SELECT crm_clients.*, users.username AS commercial
                    FROM crm_clients
                    LEFT JOIN users ON users.id = crm_clients.owner_id
                    WHERE crm_clients.owner_id=%s
                    ORDER BY crm_clients.created_at DESC
                    """,
                    (user_id,),
                )

        rows = cur.fetchall()

    en_cours, gagnes, perdus = [], [], []
    for r in rows:
        status = (r["status"] or "en_cours").lower()
        if status == "gagne":
            gagnes.append(r)
        elif status == "perdu":
            perdus.append(r)
        else:
            en_cours.append(r)

    return render_template(
        "clients.html",
        clients_en_cours=[row_to_obj(r) for r in en_cours],
        clients_gagnes=[row_to_obj(r) for r in gagnes],
        clients_perdus=[row_to_obj(r) for r in perdus],
        q=q,
    )


# =========================
# CLIENT — MISE À JOUR STATUT (ADMIN + PROPRIÉTAIRE)
# =========================
@app.route("/clients/<int:client_id>/status", methods=["POST"])
@login_required
def update_client_status(client_id):
    status = (request.form.get("status") or "").strip().lower()
    if status not in ("en_cours", "gagne", "perdu"):
        flash("Statut invalide.", "danger")
        return redirect(url_for("clients"))

    user = session.get("user") or {}
    role = user.get("role")
    user_id = user.get("id")

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT owner_id FROM crm_clients WHERE id=%s", (client_id,))
        row = cur.fetchone()

    if not row:
        flash("Dossier introuvable.", "danger")
        return redirect(url_for("clients"))

    # 🔒 Sécurité : admin ou propriétaire
    if role != "admin" and row["owner_id"] != user_id:
        abort(403)

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE crm_clients SET status=%s WHERE id=%s",
            (status, client_id),
        )

    conn.commit()
    flash("Statut du dossier mis à jour.", "success")
    return redirect(url_for("client_detail", client_id=client_id))


# =========================================================
# ALIAS ENDPOINT — compat dashboard / templates legacy
# (si un ancien code avait enregistré un endpoint différent)
# =========================================================
app.view_functions["update_client_status"] = update_client_status


# =========================
# CLIENT — DÉTAIL (FICHE + DOCS + UPDATES + COTATIONS CLIENT)
# =========================
@app.route("/clients/<int:client_id>")
@login_required
def client_detail(client_id):
    if not can_access_client(client_id):
        abort(403)

    conn = get_db()

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT crm_clients.*, users.username AS commercial
            FROM crm_clients
            LEFT JOIN users ON users.id = crm_clients.owner_id
            WHERE crm_clients.id=%s
            """,
            (client_id,),
        )
        client = cur.fetchone()

    if not client:
        abort(404)

    documents = list_client_documents(client_id)

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT *
            FROM client_updates
            WHERE client_id=%s
            ORDER BY created_at DESC
            """,
            (client_id,),
        )
        updates = cur.fetchall()

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT *
            FROM cotations
            WHERE client_id=%s
            ORDER BY date_creation DESC
            """,
            (client_id,),
        )
        cotations = cur.fetchall()

    return render_template(
        "client_detail.html",
        client=row_to_obj(client),
        documents=documents,
        updates=[row_to_obj(u) for u in updates],
        client_cotations=[row_to_obj(c) for c in cotations],
        can_request_update=True,
    )


# =========================
# CLIENT — SUPPRESSION (ADMIN)
# =========================
@app.route("/clients/<int:client_id>/delete", methods=["POST"])
@admin_required
def delete_client(client_id):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM cotations WHERE client_id=%s", (client_id,))
        cur.execute("DELETE FROM client_updates WHERE client_id=%s", (client_id,))
        cur.execute("DELETE FROM crm_clients WHERE id=%s", (client_id,))
    conn.commit()
    flash("Dossier client supprimé.", "success")
    return redirect(url_for("clients"))


# =========================
# CLIENT — UPLOAD DOCUMENT (S3)
# =========================
@app.route("/clients/<int:client_id>/documents/upload", methods=["POST"])
@login_required
def upload_client_document(client_id):
    if not can_access_client(client_id):
        abort(403)

    fichier = request.files.get("file")
    if not fichier or not allowed_file(fichier.filename):
        flash("Fichier invalide.", "danger")
        return redirect(url_for("client_detail", client_id=client_id))

    if LOCAL_MODE or not s3:
        flash("Upload indisponible en mode local.", "warning")
        return redirect(url_for("client_detail", client_id=client_id))

    prefix = client_s3_prefix(client_id)
    name = clean_filename(secure_filename(fichier.filename))
    key = _s3_make_non_overwriting_key(AWS_BUCKET, f"{prefix}{name}")

    s3_upload_fileobj(fichier, AWS_BUCKET, key)
    flash("Document ajouté.", "success")
    return redirect(url_for("client_detail", client_id=client_id))


# =========================
# CLIENT — ENVOI DEMANDE DE COTATION (COMPLET)
# =========================
@app.route("/clients/<int:client_id>/cotations/create", methods=["POST"])
@login_required
def create_cotation(client_id):
    if not can_access_client(client_id):
        abort(403)

    user = session.get("user") or {}
    conn = get_db()

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cotations (
                client_id,
                created_by,
                date_negociation,
                heure_negociation,
                energie_type,
                type_compteur,
                pdl_pce,
                date_echeance,
                fournisseur_actuel,
                entreprise_nom,
                siret,
                signataire_nom,
                signataire_tel,
                signataire_email,
                commentaire,
                status,
                is_read
            )
            VALUES (
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'nouvelle',0
            )
            """,
            (
                client_id,
                user.get("id"),
                request.form.get("date_negociation"),
                request.form.get("heure_negociation"),
                request.form.get("energie_type"),
                request.form.get("type_compteur"),
                request.form.get("pdl_pce"),
                request.form.get("date_echeance"),
                request.form.get("fournisseur_actuel"),
                request.form.get("entreprise_nom"),
                request.form.get("siret"),
                request.form.get("signataire_nom"),
                request.form.get("signataire_tel"),
                request.form.get("signataire_email"),
                request.form.get("commentaire"),
            ),
        )

    conn.commit()
    flash("Demande de cotation envoyée.", "success")
    return redirect(url_for("client_detail", client_id=client_id))



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
# 14. CHAT (BACKEND)
############################################################

def _chat_store_file(file_storage):
    """
    Stockage d’une pièce jointe du chat en S3 PRIVÉ.
    Retourne (file_key, file_name) ou (None, None)
    """
    if not file_storage:
        return (None, None)

    if not allowed_file(file_storage.filename):
        return (None, None)

    file_name_original = secure_filename(file_storage.filename)
    file_name_clean = clean_filename(file_name_original)

    if LOCAL_MODE or not s3:
        return (None, None)

    rnd = secrets.token_hex(6)
    key_raw = f"chat/{rnd}_{file_name_clean}"

    key = _s3_make_non_overwriting_key(AWS_BUCKET, key_raw)

    try:
        s3_upload_fileobj(file_storage, AWS_BUCKET, key)
        return (key, file_name_original)
    except ClientError as e:
        logger.error(
            "Erreur upload chat S3 (ClientError): %s",
            getattr(e, "response", None)
        )
        return (None, None)
    except Exception as e:
        logger.exception("Erreur upload chat S3: %r", e)
        return (None, None)


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
    with conn.cursor() as cur:
        cur.execute(
            """
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
            """,
            (limit_int,),
        )
        rows = cur.fetchall()

    messages = []
    for r in reversed(rows):
        messages.append(
            {
                "id": r["id"],
                "user_id": r["user_id"],
                "username": r["username"],
                "message": r["message"],
                "file_key": r["file_key"],
                "file_name": r["file_name"],
                "file_url": (
                    s3_presigned_url(r["file_key"])
                    if (r["file_key"] and not LOCAL_MODE and s3)
                    else None
                ),
                "created_at": r["created_at"],
                "is_read": bool(r["is_read"]),
                "is_mine": r["user_id"] == user_id,
            }
        )

    return jsonify({"success": True, "messages": messages})


@app.route("/chat/send", methods=["POST"])
@login_required
def chat_send():
    message = (request.form.get("message") or "").strip()
    file_obj = request.files.get("file")

    user = session.get("user") or {}

    # 🔒 SÉCURITÉ : seuls les ADMINS peuvent envoyer des fichiers
    if file_obj and user.get("role") != "admin":
        return jsonify(
            {
                "success": False,
                "message": "L’envoi de documents est réservé à l’administrateur."
            }
        ), 403

    file_key, file_name = _chat_store_file(file_obj)

    if not message and not file_key:
        return jsonify(
            {"success": False, "message": "Message ou fichier requis."}
        ), 400

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            """
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
            """,
            (
                user.get("id"),
                user.get("username"),
                message,
                file_key,
                file_name,
            ),
        )
        new_id = cur.fetchone()[0]

    conn.commit()

    return jsonify(
        {
            "success": True,
            "id": new_id,
            "user_id": user.get("id"),
            "username": user.get("username"),
        }
    )


@app.route("/chat/mark_read", methods=["POST"])
@login_required
def chat_mark_read():
    """
    Marque tous les messages NON envoyés par l'utilisateur courant comme lus
    (équivalent WhatsApp quand la fenêtre est ouverte)
    """
    u = session.get("user") or {}
    user_id = u.get("id")

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE chat_messages
            SET is_read = 1
            WHERE COALESCE(is_read, 0) = 0
              AND user_id <> %s
            """,
            (user_id,),
        )

    conn.commit()
    return jsonify({"success": True})


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


# ============================
# FIN PARTIE 4/4
# ============================
# =========================
# DEBUG — LISTE DES ROUTES CHARGÉES
# =========================
@app.route("/__routes__")
def debug_routes():
    return "<br>".join(sorted(app.view_functions.keys()))
# =========================================================
# ALIAS ENDPOINT — FIX CRASH MENU / DASHBOARD
# =========================================================


