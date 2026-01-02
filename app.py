import os
import re
import unicodedata
import secrets
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
ADMIN_DEFAULT_PASSWORD = getattr(Config, "ADMIN_DEFAULT_PASSWORD", "admin123")

# CSRF: endpoints JSON éventuellement exemptés (si vous ne voulez pas gérer le header côté front)
CSRF_EXEMPT_ENDPOINTS = {
    "chat_send",
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


############################################################
# 3. BASE DE DONNÉES (POSTGRESQL – PROD SAFE)
############################################################

def _connect_db():
    """
    Connexion PostgreSQL unique.
    AUCUNE initialisation automatique ici.
    """
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL manquant dans la configuration.")

    conn = psycopg2.connect(
        DATABASE_URL,
        cursor_factory=psycopg2.extras.DictCursor,
        sslmode="require",
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
    Convertit une row PostgreSQL en objet accessible via dot notation.
    Garde les types natifs (datetime, int, float, etc.)
    """
    if not row:
        return None
    return SimpleNamespace(**dict(row))


def _try_add_column(conn, table, column_sql):
    """
    Sécurité : ajout de colonne sans casser une base existante
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
                    password TEXT NOT NULL,
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
            # 👉 NOUVELLE TABLE (notifications admin)
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

            # ================= ADMIN BOOTSTRAP =================
            cur.execute("SELECT id FROM users WHERE username='admin'")
            if not cur.fetchone():
                cur.execute(
                    """
                    INSERT INTO users (username, password, role)
                    VALUES (%s, %s, %s)
                    """,
                    (
                        "admin",
                        generate_password_hash(ADMIN_DEFAULT_PASSWORD),
                        "admin",
                    ),
                )

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
        print(
            f"S3 connecté | bucket={AWS_BUCKET} | region={AWS_REGION}"
        )
    except Exception as e:
        print("❌ Erreur connexion S3 :", repr(e))
        s3 = None
else:
    print("ℹ️ Mode local actif : S3 désactivé.")


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
        print("Erreur presigned URL S3 :", e.response)
        return ""
    except Exception as e:
        print("Erreur presigned URL S3 :", repr(e))
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


def list_client_documents(client_id: int):
    """
    Liste documents d’un client (URL signée incluse).
    """
    if LOCAL_MODE or not s3:
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
                    "url": s3_presigned_url(key),
                }
            )

    except Exception as e:
        print("Erreur list_client_documents :", repr(e))

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
# CSRF — VERSION TOLÉRANTE & CONTRÔLÉE
############################################################

@app.before_request
def csrf_protect():
    """
    CSRF SAFE :
    - Génère toujours un token
    - Ne bloque QUE si un token est envoyé mais invalide
    - Permet les endpoints explicitement exemptés
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

    # Si token présent mais invalide → blocage
    if sent_token and sent_token != session.get("csrf_token"):
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

    # ===============================
    # BADGE : cotations non lues (ADMIN)
    # ===============================
    unread_cotations = 0

    # ===============================
    # BADGE : mises à jour non lues (ADMIN)
    # ===============================
    unread_updates = 0

    if hookup := (current_user and current_user.role == "admin"):
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

    # ===============================
    # INJECTION GLOBALE
    # ===============================
    return dict(
        # Utilisateur courant
        current_user=current_user,

        # Token CSRF (toujours présent)
        csrf_token=session.get("csrf_token"),

        # Helper date SAFE
        format_date=format_date_safe,

        # Badges admin
        unread_cotations=unread_cotations,
        unread_updates=unread_updates,
    )



############################################################
# 7. LOGIN / LOGOUT
############################################################

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username=%s", (username,))
            user = cur.fetchone()

        if user and check_password_hash(user["password"], password):
            session["user"] = {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
            }
            flash("Connexion réussie.", "success")
            return redirect(url_for("dashboard"))

        flash("Identifiants incorrects.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Déconnexion effectuée.", "info")
    return redirect(url_for("login"))


############################################################
# 8. DASHBOARD + SEARCH + OUVERTURE COTATION
############################################################

@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()

    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM crm_clients")
        total_clients = cur.fetchone()[0]

        # dashboard : on laisse datetime (votre template dashboard utilise strftime)
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
            ORDER BY date DESC, id DESC
            LIMIT 1
        """)
        last_rev = cur.fetchone()

    total_docs = 0
    if not LOCAL_MODE and s3:
        try:
            items = s3_list_all_objects(AWS_BUCKET)
            total_docs = len([f for f in items if not f["Key"].endswith("/")])
        except Exception:
            pass

    unread_cotations = 0
    cotations_admin = []

    if session.get("user", {}).get("role") == "admin":
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM cotations WHERE COALESCE(is_read,0)=0")
            unread_cotations = cur.fetchone()[0]

            # on renvoie date_creation en datetime ici (dashboard corrigé)
            cur.execute("""
                SELECT cotations.*, crm_clients.name AS client_name
                FROM cotations
                JOIN crm_clients ON crm_clients.id = cotations.client_id
                WHERE COALESCE(cotations.is_read,0)=0
                ORDER BY cotations.date_creation DESC
            """)
            rows = cur.fetchall()

        cotations_admin = [row_to_obj(r) for r in rows]

    return render_template(
        "dashboard.html",
        total_clients=total_clients,
        last_clients=last_clients,
        total_ca=total_ca,
        last_rev=row_to_obj(last_rev) if last_rev else None,
        total_docs=total_docs,
        unread_cotations=unread_cotations,
        cotations_admin=cotations_admin,
    )


@app.route("/cotations/<int:cotation_id>")
@login_required
def open_cotation(cotation_id):
    conn = get_db()

    with conn.cursor() as cur:
        cur.execute("SELECT * FROM cotations WHERE id=%s", (cotation_id,))
        cot = cur.fetchone()

    if not cot:
        flash("Demande de cotation introuvable.", "danger")
        return redirect(url_for("dashboard"))

    if not can_access_client(cot["client_id"]):
        flash("Accès non autorisé.", "danger")
        return redirect(url_for("dashboard"))

    with conn.cursor() as cur:
        cur.execute("UPDATE cotations SET is_read=1 WHERE id=%s", (cotation_id,))
    conn.commit()

    return redirect(url_for("client_detail", client_id=cot["client_id"], cotation_id=cotation_id))


@app.route("/search")
@login_required
def search():
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify({"results": []})

    user = session.get("user") or {}
    q_lower = q.lower()
    conn = get_db()

    with conn.cursor() as cur:
        if user.get("role") == "admin":
            cur.execute("""
                SELECT id, name
                FROM crm_clients
                WHERE name ILIKE %s
                ORDER BY created_at DESC
                LIMIT 10
            """, (f"%{q}%",))
            client_rows = cur.fetchall()
        else:
            cur.execute("""
                SELECT id, name
                FROM crm_clients
                WHERE owner_id=%s
                  AND name ILIKE %s
                ORDER BY created_at DESC
                LIMIT 10
            """, (user.get("id"), f"%{q}%"))
            client_rows = cur.fetchall()

    results = []
    for c in client_rows:
        docs = list_client_documents(c["id"])
        filtered_docs = [d for d in docs if q_lower in d["nom"].lower()]
        results.append(
            {
                "client_id": c["id"],
                "client_name": c["name"],
                "documents": filtered_docs[:10],
            }
        )

    return jsonify({"results": results})


############################################################
# 9. CHIFFRE D’AFFAIRES (ADMIN WRITE / COMMERCIAL READ)
############################################################

from datetime import date

@app.route("/chiffre_affaire", methods=["GET", "POST"])
@login_required
def chiffre_affaire():
    user = session.get("user") or {}
    role = user.get("role")
    username = user.get("username")

    conn = get_db()

    # ================== AJOUT CA (ADMIN SEULEMENT) ==================
    if request.method == "POST":
        if role != "admin":
            abort(403)

        date_rev = request.form.get("date")
        montant = request.form.get("montant")
        client_id = request.form.get("client_id")

        if not date_rev or not montant or not client_id:
            flash("Tous les champs sont obligatoires.", "danger")
            return redirect(url_for("chiffre_affaire"))

        try:
            montant_val = float(montant)
        except ValueError:
            flash("Montant invalide.", "danger")
            return redirect(url_for("chiffre_affaire"))

        with conn.cursor() as cur:
            cur.execute(
                "SELECT name, owner_id FROM crm_clients WHERE id=%s",
                (client_id,)
            )
            client = cur.fetchone()

        if not client:
            flash("Dossier client introuvable.", "danger")
            return redirect(url_for("chiffre_affaire"))

        with conn.cursor() as cur:
            cur.execute(
                "SELECT username FROM users WHERE id=%s",
                (client["owner_id"],)
            )
            commercial = cur.fetchone()

        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO revenus (date, montant, client_id, commercial, dossier)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    date_rev,
                    montant_val,
                    client_id,
                    commercial["username"] if commercial else None,
                    client["name"],
                )
            )

        conn.commit()
        flash("Chiffre d’affaires ajouté.", "success")
        return redirect(url_for("chiffre_affaire"))

    # ================== LECTURE ==================
    today = date.today()
    year = str(today.year)
    month = today.strftime("%Y-%m")

    with conn.cursor() as cur:
        # Global
        cur.execute(
            "SELECT COALESCE(SUM(montant),0) FROM revenus WHERE substr(date,1,4)=%s",
            (year,)
        )
        ca_annuel_global = cur.fetchone()[0]

        cur.execute(
            "SELECT COALESCE(SUM(montant),0) FROM revenus WHERE substr(date,1,7)=%s",
            (month,)
        )
        ca_mensuel_global = cur.fetchone()[0]

    if role == "admin":
        ca_annuel_perso = ca_annuel_global
        ca_mensuel_perso = ca_mensuel_global

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT commercial, SUM(montant) AS total
                FROM revenus
                WHERE substr(date,1,4)=%s
                GROUP BY commercial
                ORDER BY total DESC
                """,
                (year,)
            )
            annuel_par_com = cur.fetchall()

    else:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COALESCE(SUM(montant),0)
                FROM revenus
                WHERE substr(date,1,4)=%s
                  AND commercial=%s
                """,
                (year, username)
            )
            ca_annuel_perso = cur.fetchone()[0]

            cur.execute(
                """
                SELECT COALESCE(SUM(montant),0)
                FROM revenus
                WHERE substr(date,1,7)=%s
                  AND commercial=%s
                """,
                (month, username)
            )
            ca_mensuel_perso = cur.fetchone()[0]

        annuel_par_com = []

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT substr(date,1,7) AS mois, SUM(montant) AS total
            FROM revenus
            GROUP BY mois
            ORDER BY mois DESC
            """
        )
        global_par_mois = cur.fetchall()

    return render_template(
        "chiffre_affaire.html",
        role=role,
        ca_annuel_perso=ca_annuel_perso,
        ca_mensuel_perso=ca_mensuel_perso,
        ca_annuel_global=ca_annuel_global,
        ca_mensuel_global=ca_mensuel_global,
        annuel_par_com=annuel_par_com,
        global_par_mois=global_par_mois,
    )


############################################################
# 10. ADMIN UTILISATEURS + RESET PASSWORD
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
            flash("Champs obligatoires.", "danger")
            return redirect(url_for("admin_users"))

        if len(password) < 10:
            flash("Mot de passe trop court (min 10 caractères).", "danger")
            return redirect(url_for("admin_users"))

        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM users WHERE username=%s",
                (username,),
            )
            exists = cur.fetchone()[0]

        if exists > 0:
            flash("Nom d'utilisateur déjà utilisé.", "danger")
            return redirect(url_for("admin_users"))

        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (username, password, role)
                VALUES (%s, %s, %s)
                """,
                (username, generate_password_hash(password), role),
            )

        conn.commit()
        flash("Utilisateur créé.", "success")
        return redirect(url_for("admin_users"))

    with conn.cursor() as cur:
        cur.execute("SELECT * FROM users ORDER BY id ASC")
        users = cur.fetchall()

    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_user(user_id):
    conn = get_db()

    with conn.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cur.fetchone()

    if not user:
        flash("Utilisateur introuvable.", "danger")
        return redirect(url_for("admin_users"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        role = (request.form.get("role") or "").strip()

        if not username or not role:
            flash("Nom d’utilisateur et rôle obligatoires.", "danger")
            return redirect(url_for("admin_edit_user", user_id=user_id))

        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM users WHERE username=%s AND id<>%s",
                (username, user_id),
            )
            exists = cur.fetchone()[0]

        if exists > 0:
            flash("Nom déjà utilisé.", "danger")
            return redirect(url_for("admin_edit_user", user_id=user_id))

        if password:
            if len(password) < 10:
                flash("Mot de passe trop court (min 10 caractères).", "danger")
                return redirect(url_for("admin_edit_user", user_id=user_id))

            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE users
                    SET username=%s, password=%s, role=%s
                    WHERE id=%s
                    """,
                    (username, generate_password_hash(password), role, user_id),
                )
        else:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE users
                    SET username=%s, role=%s
                    WHERE id=%s
                    """,
                    (username, role, user_id),
                )

        conn.commit()
        flash("Utilisateur mis à jour.", "success")
        return redirect(url_for("admin_users"))

    return render_template(
        "admin_edit_user.html",
        user=row_to_obj(user),
    )


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    if user_id == 1:
        flash("Impossible de supprimer l'administrateur principal.", "danger")
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

    if not new_password:
        flash("Le nouveau mot de passe est obligatoire.", "danger")
        return redirect(url_for("admin_users"))

    if len(new_password) < 10:
        flash("Mot de passe trop court (min 10 caractères).", "danger")
        return redirect(url_for("admin_users"))

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM users WHERE id=%s", (user_id,))
        user = cur.fetchone()

    if not user:
        flash("Utilisateur introuvable.", "danger")
        return redirect(url_for("admin_users"))

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE users SET password=%s WHERE id=%s",
            (generate_password_hash(new_password), user_id),
        )

    conn.commit()
    flash("Mot de passe réinitialisé.", "success")
    return redirect(url_for("admin_users"))
############################################################
# 10 BIS. ADMIN — DEMANDES DE COTATION
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
        row = cur.fetchone()

    if not row:
        flash("Demande de cotation introuvable.", "danger")
        return redirect(url_for("admin_cotations"))

    # Marquer comme lue
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE cotations SET is_read = 1 WHERE id = %s",
            (cotation_id,)
        )
    conn.commit()

    return render_template(
        "admin_cotation_detail.html",
        cotation=row_to_obj(row)
    )


############################################################
# 11. DOCUMENTS GLOBAUX S3 (ADMIN UNIQUEMENT)
############################################################

def _validate_s3_key_for_admin_delete(key: str) -> str:
    if not key or not key.strip():
        raise BadRequest("Clé S3 invalide.")

    key = key.strip()

    # Sécurité basique
    if ".." in key:
        raise BadRequest("Clé S3 invalide.")

    return key


@app.route("/documents")
@admin_required
def documents():
    # Mode local ou S3 indisponible → page vide mais fonctionnelle
    if LOCAL_MODE or not s3:
        return render_template("documents.html", fichiers=[])

    fichiers = []

    try:
        # On liste UNIQUEMENT les objets sous "clients/"
        items = s3_list_all_objects(AWS_BUCKET, prefix="clients/")

        for item in items:
            key = item.get("Key")
            if not key or key.endswith("/"):
                continue

            fichiers.append(
                {
                    "nom": key,
                    "taille": item.get("Size", 0),
                    "url": s3_presigned_url(key),
                }
            )

    except ClientError as e:
        print("Erreur listing S3 (admin documents) :", e.response)
        flash("Erreur lors du listing des documents.", "danger")

    except Exception as e:
        print("Erreur listing S3 (admin documents) :", repr(e))
        flash("Erreur lors du listing des documents.", "danger")

    return render_template("documents.html", fichiers=fichiers)


@app.route("/documents/upload", methods=["POST"])
@admin_required
def upload_document():
    if LOCAL_MODE or not s3:
        flash("Upload désactivé en mode local.", "warning")
        return redirect(url_for("documents"))

    fichier = request.files.get("file")

    if not fichier or not allowed_file(fichier.filename):
        flash("Fichier non valide.", "danger")
        return redirect(url_for("documents"))

    nom = clean_filename(secure_filename(fichier.filename))
    key = f"clients/admin/{nom}"

    try:
        s3_upload_fileobj(fichier, AWS_BUCKET, key)
        flash("Document envoyé.", "success")

    except Exception as e:
        print("Erreur upload S3 (admin) :", repr(e))
        flash("Erreur lors de l’upload.", "danger")

    return redirect(url_for("documents"))


@app.route("/documents/delete/<path:key>", methods=["POST"])
@admin_required
def delete_document(key):
    if LOCAL_MODE or not s3:
        flash("Suppression désactivée en local.", "warning")
        return redirect(url_for("documents"))

    try:
        key = _validate_s3_key_for_admin_delete(key)
        s3.delete_object(Bucket=AWS_BUCKET, Key=key)
        flash("Document supprimé.", "success")

    except BadRequest as e:
        flash(str(e), "danger")

    except Exception as e:
        print("Erreur suppression S3 (admin) :", repr(e))
        flash("Erreur lors de la suppression.", "danger")

    return redirect(url_for("documents"))



############################################################
# 12. CLIENTS (LISTE / CRÉATION / DÉTAIL) + COTATIONS + DOCUMENTS CLIENT
############################################################

@app.route("/clients")
@login_required
def clients():
    conn = get_db()
    q = (request.args.get("q") or "").strip()

    with conn.cursor() as cur:
        if session["user"]["role"] == "admin":
            if q:
                cur.execute(
                    """
                    SELECT *
                    FROM crm_clients
                    WHERE name ILIKE %s
                    ORDER BY created_at DESC
                    """,
                    (f"%{q}%",),
                )
            else:
                cur.execute(
                    "SELECT * FROM crm_clients ORDER BY created_at DESC"
                )
        else:
            if q:
                cur.execute(
                    """
                    SELECT *
                    FROM crm_clients
                    WHERE owner_id = %s
                      AND name ILIKE %s
                    ORDER BY created_at DESC
                    """,
                    (session["user"]["id"], f"%{q}%"),
                )
            else:
                cur.execute(
                    """
                    SELECT *
                    FROM crm_clients
                    WHERE owner_id = %s
                    ORDER BY created_at DESC
                    """,
                    (session["user"]["id"],),
                )

        rows = cur.fetchall()

    return render_template(
        "clients.html",
        clients=[row_to_obj(r) for r in rows],
        q=q,
    )


@app.route("/clients/new", methods=["GET", "POST"])
@login_required
def new_client():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()

        if not name:
            flash("Nom du dossier obligatoire.", "danger")
            return redirect(url_for("new_client"))

        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO crm_clients (name, owner_id)
                VALUES (%s, %s)
                RETURNING id
                """,
                (name, session["user"]["id"]),
            )
            client_id = cur.fetchone()[0]

        conn.commit()
        flash("Dossier client créé.", "success")
        return redirect(url_for("client_detail", client_id=client_id))

    return render_template("new_client.html")


@app.route("/clients/<int:client_id>")
@login_required
def client_detail(client_id):
    if not can_access_client(client_id):
        abort(403)

    conn = get_db()

    with conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM crm_clients WHERE id = %s",
            (client_id,),
        )
        client = cur.fetchone()

        cur.execute(
            """
            SELECT *
            FROM cotations
            WHERE client_id = %s
            ORDER BY date_creation DESC
            """,
            (client_id,),
        )
        cotations = cur.fetchall()

        cur.execute(
            """
            SELECT substr(date,1,7) AS mois, SUM(montant) AS total
            FROM revenus
            WHERE client_id = %s
            GROUP BY mois
            ORDER BY mois DESC
            """,
            (client_id,),
        )
        ca_par_mois = cur.fetchall()

        cur.execute(
            """
            SELECT COALESCE(SUM(montant), 0)
            FROM revenus
            WHERE client_id = %s
            """,
            (client_id,),
        )
        ca_total = cur.fetchone()[0]

    documents = list_client_documents(client_id)

    return render_template(
        "client_detail.html",
        client=row_to_obj(client),
        cotations=[row_to_obj(c) for c in cotations],
        documents=documents,
        ca_par_mois=[row_to_obj(r) for r in ca_par_mois],
        ca_total=ca_total,
    )


# =========================================================
# UPLOAD DOCUMENT CLIENT (COMMERCIAL + ADMIN)
# =========================================================
@app.route("/clients/<int:client_id>/documents/upload", methods=["POST"])
@login_required
def upload_client_document(client_id):
    if not can_access_client(client_id):
        abort(403)

    fichier = request.files.get("file")

    if not fichier or not allowed_file(fichier.filename):
        flash("Fichier non valide.", "danger")
        return redirect(url_for("client_detail", client_id=client_id))

    if LOCAL_MODE or not s3:
        flash("Upload désactivé en mode local.", "warning")
        return redirect(url_for("client_detail", client_id=client_id))

    nom = clean_filename(secure_filename(fichier.filename))
    prefix = client_s3_prefix(client_id)
    key = f"{prefix}{nom}"

    try:
        s3_upload_fileobj(fichier, AWS_BUCKET, key)
        flash("Document ajouté au dossier.", "success")
    except Exception as e:
        print("Erreur upload document client :", repr(e))
        flash("Erreur lors de l’upload du document.", "danger")

    return redirect(url_for("client_detail", client_id=client_id))


# =========================================================
# SUPPRESSION DOCUMENT CLIENT (COMMERCIAL + ADMIN)
# =========================================================
@app.route("/clients/<int:client_id>/documents/delete", methods=["POST"])
@login_required
def delete_client_document(client_id):
    if not can_access_client(client_id):
        abort(403)

    key = (request.form.get("key") or "").strip()

    if not key:
        flash("Document invalide.", "danger")
        return redirect(url_for("client_detail", client_id=client_id))

    if ".." in key or not key.startswith("clients/"):
        flash("Clé de document invalide.", "danger")
        return redirect(url_for("client_detail", client_id=client_id))

    if LOCAL_MODE or not s3:
        flash("Suppression désactivée en mode local.", "warning")
        return redirect(url_for("client_detail", client_id=client_id))

    try:
        s3.delete_object(Bucket=AWS_BUCKET, Key=key)
        flash("Document supprimé.", "success")
    except Exception as e:
        print("Erreur suppression document client :", repr(e))
        flash("Erreur lors de la suppression.", "danger")

    return redirect(url_for("client_detail", client_id=client_id))


############################################################
# 13. DEMANDES DE MISE À JOUR DOSSIER (ADMIN)
############################################################

# ⚠️ IMPORTANT :
# - Ce bloc permet aux commerciaux de faire des demandes de mise à jour
# - Les admins les voient dans une section dédiée
# - AUCUNE donnée existante n’est écrasée


# =========================
# TABLE client_updates
# =========================
# 👉 À AJOUTER DANS init_db() (UNE SEULE FOIS)
#
# CREATE TABLE IF NOT EXISTS client_updates (
#     id SERIAL PRIMARY KEY,
#     client_id INTEGER NOT NULL,
#     client_name TEXT NOT NULL,
#     commercial_id INTEGER NOT NULL,
#     commercial_name TEXT NOT NULL,
#     update_date DATE NOT NULL,
#     commentaire TEXT,
#     is_read INTEGER DEFAULT 0,
#     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
# );


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

    update_date = request.form.get("update_date")
    commentaire = (request.form.get("update_commentaire") or "").strip()

    if not update_date:
        flash("La date de mise à jour est obligatoire.", "danger")
        return redirect(url_for("client_detail", client_id=client_id))

    with conn.cursor() as cur:
        cur.execute(
            "SELECT name FROM crm_clients WHERE id=%s",
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
                user["id"],
                user["username"],
                update_date,
                commentaire,
            )
        )

    conn.commit()

    flash("Demande de mise à jour envoyée à l’administrateur.", "success")
    return redirect(url_for("client_detail", client_id=client_id))


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
            ORDER BY is_read ASC, created_at DESC
            """
        )
        rows = cur.fetchall()

    return render_template(
        "admin_updates.html",
        updates=[row_to_obj(r) for r in rows]
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
            "SELECT * FROM client_updates WHERE id=%s",
            (update_id,)
        )
        upd = cur.fetchone()

    if not upd:
        flash("Mise à jour introuvable.", "danger")
        return redirect(url_for("admin_updates"))

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE client_updates SET is_read=1 WHERE id=%s",
            (update_id,)
        )
    conn.commit()

    return redirect(
        url_for(
            "client_detail",
            client_id=upd["client_id"]
        )
    )



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
    key = f"chat/{rnd}_{file_name_clean}"

    try:
        s3_upload_fileobj(file_storage, AWS_BUCKET, key)
        return (key, file_name_original)
    except ClientError as e:
        print("Erreur upload chat S3 (ClientError):", e.response)
        return (None, None)
    except Exception as e:
        print("Erreur upload chat S3:", repr(e))
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

    file_key, file_name = _chat_store_file(file_obj)

    if not message and not file_key:
        return jsonify(
            {"success": False, "message": "Message ou fichier requis."}
        ), 400

    u = session.get("user") or {}

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
                u.get("id"),
                u.get("username"),
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
            "user_id": u.get("id"),
            "username": u.get("username"),
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
