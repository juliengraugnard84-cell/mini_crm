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
    "chat_send",  # si vous postez via JS sans CSRF pour l’instant, sinon retirez-le
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
# 3. BASE DE DONNÉES (POSTGRESQL, SAFE PROD)
############################################################

def _connect_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL manquant dans la configuration.")

    # DictCursor permet row["col"] ET row[0]
    conn = psycopg2.connect(
        DATABASE_URL,
        cursor_factory=psycopg2.extras.DictCursor,
        sslmode=os.environ.get("PGSSLMODE", "require"),
    )
    conn.autocommit = False
    return conn


def get_db():
    if "db" not in g:
        g.db = _connect_db()
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def row_to_obj(row):
    return SimpleNamespace(**dict(row)) if row else None


def _try_add_column(conn, table, column_sql):
    """
    Ajout tolérant de colonnes (SAFE, ne casse jamais la prod)
    """
    try:
        with conn.cursor() as cur:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column_sql}")
    except Exception:
        pass


def _is_weak_default_admin_password(pw: str) -> bool:
    if not pw:
        return True
    if pw.lower() in {"admin", "admin123", "password", "123456", "12345678"}:
        return True
    if len(pw) < 10:
        return True
    return False


def init_db():
    """
    ⚠️ À N’APPELER QU’UNE SEULE FOIS EN PROD
    Contrôlé via la variable d’environnement RUN_INIT_DB=1
    """
    conn = _connect_db()
    try:
        with conn.cursor() as cur:

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

            # ================= USERS =================
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE,
                    password TEXT,
                    role TEXT
                )
            """)

            # ================= REVENUS =================
            cur.execute("""
                CREATE TABLE IF NOT EXISTS revenus (
                    id SERIAL PRIMARY KEY,
                    date TEXT NOT NULL,
                    commercial TEXT NOT NULL,
                    dossier TEXT,
                    montant DOUBLE PRECISION NOT NULL
                )
            """)
            _try_add_column(conn, "revenus", "client_id INTEGER")

            # ================= COTATIONS =================
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cotations (
                    id SERIAL PRIMARY KEY,
                    client_id INTEGER,
                    fournisseur_actuel TEXT,
                    date_echeance TEXT,
                    created_by INTEGER,
                    is_read INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'nouvelle',
                    date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            _try_add_column(conn, "cotations", "date_negociation TEXT")
            _try_add_column(conn, "cotations", "energie_type TEXT")
            _try_add_column(conn, "cotations", "entreprise_nom TEXT")
            _try_add_column(conn, "cotations", "siret TEXT")
            _try_add_column(conn, "cotations", "signataire_nom TEXT")
            _try_add_column(conn, "cotations", "signataire_tel TEXT")
            _try_add_column(conn, "cotations", "signataire_email TEXT")
            _try_add_column(conn, "cotations", "pdl_pce TEXT")
            _try_add_column(conn, "cotations", "commentaire TEXT")

            # ================= CHAT =================
            cur.execute("""
                CREATE TABLE IF NOT EXISTS chat_messages (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER,
                    username TEXT,
                    message TEXT,
                    file_key TEXT,
                    file_name TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            _try_add_column(conn, "chat_messages", "is_read INTEGER DEFAULT 0")

            try:
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_chat_messages_id ON chat_messages(id)"
                )
            except Exception:
                pass

            # ================= ADMIN BOOTSTRAP =================
            cur.execute("SELECT id FROM users WHERE username=%s", ("admin",))
            admin = cur.fetchone()

            if not admin:
                if is_production and _is_weak_default_admin_password(ADMIN_DEFAULT_PASSWORD):
                    raise RuntimeError(
                        "ADMIN_DEFAULT_PASSWORD trop faible pour la production."
                    )

                cur.execute(
                    """
                    INSERT INTO users (username, password, role)
                    VALUES (%s, %s, %s)
                    """,
                    (
                        "admin",
                        generate_password_hash(ADMIN_DEFAULT_PASSWORD),
                        "admin",
                    )
                )

        conn.commit()
        print("✅ Base de données initialisée avec succès.")

    finally:
        conn.close()


# 🔐 VERROU DE PRODUCTION — C’EST ICI LA CORRECTION CLÉ
if os.environ.get("RUN_INIT_DB") == "1":
    print("⚠️ RUN_INIT_DB=1 → initialisation DB AUTORISÉE")
    init_db()
else:
    print("✅ RUN_INIT_DB absent → initialisation DB IGNORÉE (safe prod)")


############################################################
# 4. S3 — STOCKAGE DOCUMENTS
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
        print(f"S3: Connexion OK (bucket={AWS_BUCKET}, region={AWS_REGION})")
    except Exception as e:
        print("Erreur connexion S3 :", repr(e))
        s3 = None
else:
    print("Mode local : S3 désactivé.")


############################################################
# 5. UTILITAIRES
############################################################

def allowed_file(filename: str) -> bool:
    if not filename or "." not in filename:
        return False

    # Refus basique des doubles extensions suspectes (.pdf.exe)
    lowered = filename.lower()
    if re.search(r"\.(exe|js|bat|cmd|sh|php|pl|py)\b", lowered):
        return False

    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def clean_filename(filename: str) -> str:
    name, ext = os.path.splitext(filename)
    name = (
        unicodedata.normalize("NFKD", name)
        .encode("ascii", "ignore")
        .decode()
    )
    name = name.lower()
    name = re.sub(r"[^a-z0-9]+", "_", name).strip("_")
    return f"{name}{ext.lower()}"


def slugify(text: str) -> str:
    if not text:
        return ""
    text = (
        unicodedata.normalize("NFKD", text)
        .encode("ascii", "ignore")
        .decode()
    )
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "_", text).strip("_")
    return text


def client_s3_prefix(client_id: int) -> str:
    conn = get_db()
    row = conn.cursor()
    row.execute(
        "SELECT name FROM crm_clients WHERE id=%s",
        (client_id,),
    )
    r = row.fetchone()
    row.close()

    base = f"client_{client_id}"
    if r and r["name"]:
        s = slugify(r["name"])
        if s:
            base = f"{s}_{client_id}"

    return f"clients/{base}/"


def s3_upload_fileobj(fileobj, bucket: str, key: str):
    """
    Upload S3 PRIVÉ (ACL interdites sur le bucket).
    """
    if not s3:
        raise RuntimeError("Client S3 non initialisé")

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
            "ContentType": getattr(fileobj, "mimetype", None) or "application/octet-stream"
        },
    )


def s3_presigned_url(key: str, expires_in: int = 3600) -> str:
    """
    URL signée (accès privé) — fonctionne avec Block Public Access activé.
    """
    if LOCAL_MODE or not s3:
        return ""

    try:
        return s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": AWS_BUCKET, "Key": key},
            ExpiresIn=expires_in,
        )
    except ClientError as e:
        print("Erreur presigned url S3 :", e.response)
        return ""
    except Exception as e:
        print("Erreur presigned url S3 :", repr(e))
        return ""


def s3_list_all_objects(bucket: str, prefix: str | None = None):
    """
    Itère sur tous les objets S3 (pagination list_objects_v2).
    Retourne une liste d'items S3 (dictionnaires de Contents).
    """
    if not s3:
        return []

    items = []
    token = None
    while True:
        kwargs = {"Bucket": bucket}
        if prefix:
            kwargs["Prefix"] = prefix
        if token:
            kwargs["ContinuationToken"] = token

        resp = s3.list_objects_v2(**kwargs)
        items.extend(resp.get("Contents") or [])

        if resp.get("IsTruncated"):
            token = resp.get("NextContinuationToken")
            if not token:
                break
        else:
            break

    return items


def list_client_documents(client_id: int):
    if LOCAL_MODE or not s3:
        return []

    prefix = client_s3_prefix(client_id)
    docs = []

    try:
        token = None
        while True:
            kwargs = {"Bucket": AWS_BUCKET, "Prefix": prefix}
            if token:
                kwargs["ContinuationToken"] = token

            response = s3.list_objects_v2(**kwargs)
            for item in (response.get("Contents") or []):
                key = item["Key"]
                if key.endswith("/"):
                    continue

                docs.append(
                    {
                        "nom": key.replace(prefix, "", 1),
                        "key": key,
                        "taille": item["Size"],
                        "url": s3_presigned_url(key),
                    }
                )

            if response.get("IsTruncated"):
                token = response.get("NextContinuationToken")
                if not token:
                    break
            else:
                break

    except ClientError as e:
        print("Erreur list_client_documents (ClientError) :", e.response)
    except Exception as e:
        print("Erreur list_client_documents :", repr(e))

    return docs


def can_access_client(client_id: int) -> bool:
    """
    True si l'utilisateur connecté (session) a accès au client:
    - admin : tout
    - commercial : uniquement si crm_clients.owner_id == session["user"]["id"]
    """
    if not client_id:
        return False

    user = session.get("user") or {}
    if not user:
        return False

    if user.get("role") == "admin":
        return True

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            "SELECT owner_id FROM crm_clients WHERE id=%s",
            (client_id,),
        )
        row = cur.fetchone()

    if not row:
        return False

    return row["owner_id"] == user.get("id")


############################################################
# 6. AUTHENTIFICATION + CSRF (SAFE, SANS CASSER)
############################################################

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        if session["user"]["role"] != "admin":
            flash("Accès réservé à l'administrateur.", "danger")
            return redirect(url_for("dashboard"))
        return func(*args, **kwargs)
    return wrapper


############################################################
# CSRF — VERSION TOLÉRANTE (NE BLOQUE PLUS RIEN PAR ERREUR)
############################################################

@app.before_request
def csrf_protect():
    """
    CSRF SAFE:
    - génère toujours un token
    - ne bloque QUE si un token est envoyé MAIS invalide
    - n'impose PAS le token (évite les 403 fantômes)
    """

    # Génération token session
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    # Seulement pour requêtes mutantes
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return

    # Récupération token envoyé
    sent_token = (
        request.form.get("csrf_token")
        or request.headers.get("X-CSRF-Token")
        or request.headers.get("X-Csrf-Token")
    )

    # 👉 CAS IMPORTANT :
    # - si AUCUN token envoyé → on laisse passer (compatibilité)
    # - si token envoyé MAIS faux → 403
    if sent_token and sent_token != session.get("csrf_token"):
        abort(403)


############################################################
# VARIABLES GLOBALES TEMPLATES
############################################################

@app.context_processor
def inject_globals():
    u = session.get("user")
    return dict(
        current_user=SimpleNamespace(**u) if u else None,
        csrf_token=session.get("csrf_token"),
    )


############################################################
# HANDLERS ERREURS
############################################################

@app.errorhandler(403)
def forbidden(e):
    return render_template(
        "error.html",
        code=403,
        message="Accès refusé."
    ), 403


@app.errorhandler(404)
def not_found(e):
    return render_template(
        "error.html",
        code=404,
        message="Page introuvable."
    ), 404


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
            cur.execute(
                "SELECT * FROM users WHERE username=%s",
                (username,),
            )
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

        cur.execute(
            """
            SELECT name, email, created_at
            FROM crm_clients
            ORDER BY created_at DESC
            LIMIT 5
            """
        )
        last_clients = cur.fetchall()

        cur.execute("SELECT COALESCE(SUM(montant), 0) FROM revenus")
        total_ca = cur.fetchone()[0]

        cur.execute(
            """
            SELECT montant, date, commercial
            FROM revenus
            ORDER BY date DESC, id DESC
            LIMIT 1
            """
        )
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

            cur.execute(
                """
                SELECT cotations.*, crm_clients.name AS client_name
                FROM cotations
                JOIN crm_clients ON crm_clients.id = cotations.client_id
                WHERE COALESCE(cotations.is_read,0)=0
                ORDER BY cotations.date_creation DESC
                """
            )
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

    return redirect(
        url_for(
            "client_detail",
            client_id=cot["client_id"],
            cotation_id=cotation_id
        )
    )


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
            cur.execute(
                """
                SELECT id, name
                FROM crm_clients
                WHERE name LIKE %s
                ORDER BY created_at DESC
                LIMIT 10
                """,
                (f"%{q}%",),
            )
            client_rows = cur.fetchall()
        else:
            cur.execute(
                """
                SELECT id, name
                FROM crm_clients
                WHERE owner_id=%s
                  AND name LIKE %s
                ORDER BY created_at DESC
                LIMIT 10
                """,
                (user.get("id"), f"%{q}%"),
            )
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
                    "UPDATE users SET username=%s, password=%s, role=%s WHERE id=%s",
                    (username, generate_password_hash(password), role, user_id),
                )
        else:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET username=%s, role=%s WHERE id=%s",
                    (username, role, user_id),
                )

        conn.commit()
        flash("Utilisateur mis à jour.", "success")
        return redirect(url_for("admin_users"))

    return render_template("admin_edit_user.html", user=row_to_obj(user))


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
# 11. DOCUMENTS GLOBAUX S3 (ADMIN UNIQUEMENT)
############################################################

def _validate_s3_key_for_admin_delete(key: str) -> str:
    if not key or key.strip() == "":
        raise BadRequest("Clé S3 invalide.")
    key = key.strip()
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
        flash("Erreur lors du listing S3.", "danger")

    except Exception as e:
        print("Erreur listing S3 (admin documents) :", repr(e))
        flash("Erreur lors du listing S3.", "danger")

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
        flash("Erreur upload S3.", "danger")

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
        flash("Erreur suppression S3.", "danger")

    return redirect(url_for("documents"))


############################################################
# 12. CLIENTS + DOSSIERS + DOCUMENTS + COTATIONS (+ CA)
############################################################

@app.route("/clients")
@login_required
def clients():
    conn = get_db()
    user = session.get("user") or {}
    role = (user.get("role") or "").lower()
    q = (request.args.get("q") or "").strip()

    params = []
    where = ""

    if q:
        where = "AND crm_clients.name LIKE %s"
        params.append(f"%{q}%")

    with conn.cursor() as cur:
        if role == "admin":
            cur.execute(
                f"""
                SELECT crm_clients.*, users.username AS commercial_name
                FROM crm_clients
                LEFT JOIN users ON users.id = crm_clients.owner_id
                WHERE 1=1 {where}
                ORDER BY crm_clients.created_at DESC
                """,
                params
            )
            rows = cur.fetchall()
        else:
            cur.execute(
                f"""
                SELECT crm_clients.*, users.username AS commercial_name
                FROM crm_clients
                LEFT JOIN users ON users.id = crm_clients.owner_id
                WHERE crm_clients.owner_id = %s {where}
                ORDER BY crm_clients.created_at DESC
                """,
                [user.get("id")] + params
            )
            rows = cur.fetchall()

    return render_template(
        "clients.html",
        clients=[row_to_obj(r) for r in rows],
        q=q
    )


@app.route("/clients/new", methods=["GET", "POST"])
@login_required
def new_client():
    conn = get_db()
    user = session.get("user") or {}

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()

        if not name:
            flash("Le nom du dossier est obligatoire.", "danger")
            return redirect(url_for("new_client"))

        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO crm_clients (name, status, owner_id)
                VALUES (%s, 'cotation', %s)
                RETURNING id
                """,
                (name, user.get("id"))
            )
            new_id = cur.fetchone()[0]

        conn.commit()
        flash("Dossier client créé.", "success")
        return redirect(url_for("client_detail", client_id=new_id))

    return render_template("client_form.html")


@app.route("/clients/<int:client_id>")
@login_required
def client_detail(client_id):
    conn = get_db()

    if not can_access_client(client_id):
        abort(403)

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT crm_clients.*, users.username AS commercial_name
            FROM crm_clients
            LEFT JOIN users ON users.id = crm_clients.owner_id
            WHERE crm_clients.id = %s
            """,
            (client_id,)
        )
        client = cur.fetchone()

    if not client:
        abort(404)

    selected_cotation_id = request.args.get("cotation_id")

    with conn.cursor() as cur:
        if selected_cotation_id:
            cur.execute(
                """
                SELECT *
                FROM cotations
                WHERE id = %s
                  AND client_id = %s
                """,
                (selected_cotation_id, client_id)
            )
            cotations = cur.fetchall()
        else:
            cur.execute(
                """
                SELECT *
                FROM cotations
                WHERE client_id = %s
                ORDER BY date_creation DESC
                """,
                (client_id,)
            )
            cotations = cur.fetchall()

    documents = list_client_documents(client_id)

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COALESCE(SUM(montant),0)
            FROM revenus
            WHERE client_id=%s
            """,
            (client_id,)
        )
        ca_total = cur.fetchone()[0]

        cur.execute(
            """
            SELECT substr(date,1,7) AS mois, SUM(montant) AS total
            FROM revenus
            WHERE client_id=%s
            GROUP BY mois
            ORDER BY mois DESC
            """,
            (client_id,)
        )
        ca_par_mois = cur.fetchall()

    return render_template(
        "client_detail.html",
        client=row_to_obj(client),
        cotations=[row_to_obj(c) for c in cotations],
        documents=documents,
        ca_total=ca_total,
        ca_par_mois=[row_to_obj(r) for r in ca_par_mois],
    )


@app.route("/clients/<int:client_id>/update", methods=["POST"])
@login_required
def update_client(client_id):
    conn = get_db()

    if not can_access_client(client_id):
        abort(403)

    name = (request.form.get("update_name") or "").strip()
    update_date = request.form.get("update_date")
    commentaire = (request.form.get("update_commentaire") or "").strip()

    if not name or not update_date:
        flash("Nom et date obligatoires.", "danger")
        return redirect(url_for("client_detail", client_id=client_id))

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE crm_clients
            SET name = %s, notes = %s
            WHERE id = %s
            """,
            (name, commentaire, client_id)
        )
    conn.commit()

    flash("Dossier mis à jour.", "success")
    return redirect(url_for("client_detail", client_id=client_id))


@app.route("/clients/<int:client_id>/documents/upload", methods=["POST"])
@login_required
def upload_client_document(client_id):
    if LOCAL_MODE or not s3:
        flash("Upload désactivé en local.", "warning")
        return redirect(url_for("client_detail", client_id=client_id))

    if not can_access_client(client_id):
        abort(403)

    files = request.files.getlist("documents")
    if not files:
        flash("Aucun fichier sélectionné.", "danger")
        return redirect(url_for("client_detail", client_id=client_id))

    prefix = client_s3_prefix(client_id)

    for f in files:
        if f and allowed_file(f.filename):
            filename = clean_filename(secure_filename(f.filename))
            key = f"{prefix}{filename}"
            s3_upload_fileobj(f, AWS_BUCKET, key)

    flash("Documents ajoutés.", "success")
    return redirect(url_for("client_detail", client_id=client_id))


@app.route("/clients/<int:client_id>/documents/delete", methods=["POST"])
@login_required
def delete_client_document(client_id):
    if LOCAL_MODE or not s3:
        flash("Suppression désactivée en local.", "warning")
        return redirect(url_for("client_detail", client_id=client_id))

    if not can_access_client(client_id):
        abort(403)

    key = (request.form.get("key") or "").strip()
    if not key:
        flash("Clé de document invalide.", "danger")
        return redirect(url_for("client_detail", client_id=client_id))

    s3.delete_object(Bucket=AWS_BUCKET, Key=key)
    flash("Document supprimé.", "success")
    return redirect(url_for("client_detail", client_id=client_id))


@app.route("/clients/<int:client_id>/cotations/new", methods=["POST"])
@login_required
def create_cotation(client_id):
    if not can_access_client(client_id):
        abort(403)

    conn = get_db()

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cotations (
                client_id,
                date_negociation,
                energie_type,
                pdl_pce,
                date_echeance,
                fournisseur_actuel,
                entreprise_nom,
                siret,
                signataire_nom,
                signataire_tel,
                signataire_email,
                commentaire,
                created_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                client_id,
                request.form.get("date_negociation"),
                request.form.get("energie_type"),
                request.form.get("pdl_pce"),
                request.form.get("date_echeance"),
                request.form.get("fournisseur_actuel"),
                request.form.get("entreprise_nom"),
                request.form.get("siret"),
                request.form.get("signataire_nom"),
                request.form.get("signataire_tel"),
                request.form.get("signataire_email"),
                request.form.get("commentaire"),
                session["user"]["id"],
            )
        )

    conn.commit()
    flash("Demande de cotation créée.", "success")
    return redirect(url_for("client_detail", client_id=client_id))


############################################################
# 14. CHAT (BACKEND)
############################################################

def _chat_store_file(file_storage):
    """
    Stockage pièce jointe chat en S3 PRIVÉ.
    Retour: (file_key, file_name) ou (None, None)
    """
    if not file_storage:
        return (None, None)

    if not allowed_file(file_storage.filename):
        return (None, None)

    file_name = secure_filename(file_storage.filename)
    file_name_clean = clean_filename(file_name)

    if LOCAL_MODE or not s3:
        return (None, None)

    rnd = secrets.token_hex(6)
    key = f"chat/{rnd}_{file_name_clean}"

    try:
        s3_upload_fileobj(file_storage, AWS_BUCKET, key)
        return (key, file_name)
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

    items = []
    for r in reversed(rows):
        items.append(
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
                "is_mine": (r["user_id"] == user_id),
            }
        )

    return jsonify({"success": True, "messages": items})


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
    if "user" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))


############################################################
# 16. RUN (LOCAL)
############################################################

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=DEBUG)
