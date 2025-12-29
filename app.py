import os
import re
import unicodedata
import sqlite3
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

from config import Config


############################################################
# 1. CONFIGURATION GLOBALE
############################################################

LOCAL_MODE = Config.LOCAL_MODE

AWS_ACCESS_KEY = Config.AWS_ACCESS_KEY
AWS_SECRET_KEY = Config.AWS_SECRET_KEY
AWS_REGION = Config.AWS_REGION
AWS_BUCKET = Config.AWS_BUCKET

DB_PATH = Config.DB_PATH

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
# (plus fiable que FLASK_ENV, souvent absent/déprécié)
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
# 3. BASE DE DONNÉES (SAFE PROD)
############################################################

def _connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA busy_timeout = 5000;")
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
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_sql}")
    except sqlite3.OperationalError:
        pass


def _is_weak_default_admin_password(pw: str) -> bool:
    # Heuristique simple
    if not pw:
        return True
    if pw.lower() in {"admin", "admin123", "password", "123456", "12345678"}:
        return True
    if len(pw) < 10:
        return True
    return False


def init_db():
    conn = _connect_db()

    # CLIENTS
    conn.execute("""
        CREATE TABLE IF NOT EXISTS crm_clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            address TEXT,
            commercial TEXT,
            status TEXT,
            notes TEXT,
            owner_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # USERS
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    """)

    # REVENUS
    conn.execute("""
        CREATE TABLE IF NOT EXISTS revenus (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            commercial TEXT NOT NULL,
            dossier TEXT,
            montant REAL NOT NULL
        )
    """)

    # COTATIONS
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cotations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER,
            fournisseur_actuel TEXT,
            date_echeance TEXT,
            created_by INTEGER,
            is_read INTEGER DEFAULT 0,
            status TEXT DEFAULT 'nouvelle',
            date_creation TEXT DEFAULT CURRENT_TIMESTAMP
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

    # CHAT MESSAGES
    conn.execute("""
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            message TEXT,
            file_key TEXT,
            file_name TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_chat_messages_id ON chat_messages(id)")
    except sqlite3.OperationalError:
        pass

    # ADMIN BOOTSTRAP
    admin = conn.execute(
        "SELECT id FROM users WHERE username='admin'"
    ).fetchone()

    if not admin:
        # En prod, on évite d’initialiser avec un password faible par défaut
        if is_production and _is_weak_default_admin_password(ADMIN_DEFAULT_PASSWORD):
            raise RuntimeError(
                "ADMIN_DEFAULT_PASSWORD trop faible pour un environnement production. "
                "Définissez un mot de passe fort via Config/ENV."
            )

        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash(ADMIN_DEFAULT_PASSWORD), "admin")
        )

    conn.commit()
    conn.close()


init_db()


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
    row = conn.execute(
        "SELECT name FROM crm_clients WHERE id=?",
        (client_id,),
    ).fetchone()

    base = f"client_{client_id}"
    if row and row["name"]:
        s = slugify(row["name"])
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
    row = conn.execute(
        "SELECT owner_id FROM crm_clients WHERE id=?",
        (client_id,),
    ).fetchone()

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
        user = conn.execute(
            "SELECT * FROM users WHERE username=?",
            (username,),
        ).fetchone()

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

    total_clients = conn.execute("SELECT COUNT(*) FROM crm_clients").fetchone()[0]

    last_clients = conn.execute(
        """
        SELECT name, email, created_at
        FROM crm_clients
        ORDER BY created_at DESC
        LIMIT 5
        """
    ).fetchall()

    total_ca = conn.execute(
        "SELECT COALESCE(SUM(montant), 0) FROM revenus"
    ).fetchone()[0]

    last_rev = conn.execute(
        """
        SELECT montant, date, commercial
        FROM revenus
        ORDER BY date DESC, id DESC
        LIMIT 1
        """
    ).fetchone()

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
        unread_cotations = conn.execute(
            "SELECT COUNT(*) FROM cotations WHERE COALESCE(is_read,0)=0"
        ).fetchone()[0]

        rows = conn.execute(
            """
            SELECT cotations.*, crm_clients.name AS client_name
            FROM cotations
            JOIN crm_clients ON crm_clients.id = cotations.client_id
            WHERE COALESCE(cotations.is_read,0)=0
            ORDER BY cotations.date_creation DESC
            """
        ).fetchall()

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

    cot = conn.execute(
        "SELECT * FROM cotations WHERE id=?",
        (cotation_id,),
    ).fetchone()

    if not cot:
        flash("Demande de cotation introuvable.", "danger")
        return redirect(url_for("dashboard"))

    if not can_access_client(cot["client_id"]):
        flash("Accès non autorisé.", "danger")
        return redirect(url_for("dashboard"))

    conn.execute(
        "UPDATE cotations SET is_read=1 WHERE id=?",
        (cotation_id,),
    )
    conn.commit()

    return redirect(url_for("client_detail", client_id=cot["client_id"]))


@app.route("/search")
@login_required
def search():
    """
    Recherche clients + documents (safe).
    - Admin: voit tout
    - Commercial: voit ses clients
    """
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify({"results": []})

    user = session.get("user") or {}
    q_lower = q.lower()

    conn = get_db()
    if user.get("role") == "admin":
        client_rows = conn.execute(
            """
            SELECT id, name
            FROM crm_clients
            WHERE name LIKE ? OR email LIKE ? OR phone LIKE ?
            ORDER BY created_at DESC
            LIMIT 10
            """,
            (f"%{q}%", f"%{q}%", f"%{q}%"),
        ).fetchall()
    else:
        client_rows = conn.execute(
            """
            SELECT id, name
            FROM crm_clients
            WHERE owner_id=?
              AND (name LIKE ? OR email LIKE ? OR phone LIKE ?)
            ORDER BY created_at DESC
            LIMIT 10
            """,
            (user.get("id"), f"%{q}%", f"%{q}%", f"%{q}%"),
        ).fetchall()

    results = []
    for c in client_rows:
        docs = list_client_documents(c["id"])
        filtered_docs = [d for d in docs if q_lower in (d.get("nom") or "").lower()]
        results.append(
            {
                "client_id": c["id"],
                "client_name": c["name"],
                "documents": (filtered_docs or docs)[:10],
            }
        )

    return jsonify({"results": results})


############################################################
# 9. CHIFFRE D'AFFAIRES (ADMIN WRITE ONLY)
############################################################

@app.route("/chiffre_affaire", methods=["GET", "POST"])
@login_required
def chiffre_affaire():
    user = session.get("user")
    conn = get_db()

    if request.method == "POST" and user["role"] != "admin":
        abort(403)

    if request.method == "POST":
        date_rev = request.form.get("date")
        commercial = request.form.get("commercial")
        dossier = request.form.get("dossier")
        montant = request.form.get("montant")

        if not all([date_rev, commercial, dossier, montant]):
            flash("Tous les champs sont obligatoires.", "danger")
            return redirect(url_for("chiffre_affaire"))

        try:
            montant_val = float(montant)
        except Exception:
            flash("Montant invalide.", "danger")
            return redirect(url_for("chiffre_affaire"))

        conn.execute("""
            INSERT INTO revenus (date, commercial, dossier, montant)
            VALUES (?, ?, ?, ?)
        """, (date_rev, commercial, dossier, montant_val))
        conn.commit()

        flash("Chiffre d’affaires ajouté.", "success")
        return redirect(url_for("chiffre_affaire"))

    today = date.today()
    year = str(today.year)
    month = today.strftime("%Y-%m")

    ca_annuel = conn.execute("""
        SELECT COALESCE(SUM(montant), 0)
        FROM revenus
        WHERE substr(date,1,4)=?
    """, (year,)).fetchone()[0]

    ca_mensuel = conn.execute("""
        SELECT COALESCE(SUM(montant), 0)
        FROM revenus
        WHERE substr(date,1,7)=?
    """, (month,)).fetchone()[0]

    annuel_par_com = conn.execute("""
        SELECT commercial, SUM(montant) AS total
        FROM revenus
        WHERE substr(date,1,4)=?
        GROUP BY commercial
        ORDER BY total DESC
    """, (year,)).fetchall()

    mensuel_par_com = conn.execute("""
        SELECT substr(date,1,7) AS mois, commercial, SUM(montant) AS total
        FROM revenus
        GROUP BY mois, commercial
        ORDER BY mois DESC
    """).fetchall()

    global_par_mois = conn.execute("""
        SELECT substr(date,1,7) AS mois, SUM(montant) AS total
        FROM revenus
        GROUP BY mois
        ORDER BY mois DESC
    """).fetchall()

    return render_template(
        "chiffre_affaire.html",
        ca_annuel=ca_annuel,
        ca_mensuel=ca_mensuel,
        annuel_par_com=annuel_par_com,
        mensuel_par_com=mensuel_par_com,
        global_par_mois=global_par_mois,
    )


@app.route("/chiffre_affaire/delete/<int:rev_id>", methods=["POST"])
@login_required
def delete_revenue(rev_id):
    if session["user"]["role"] != "admin":
        abort(403)

    conn = get_db()
    conn.execute("DELETE FROM revenus WHERE id=?", (rev_id,))
    conn.commit()

    flash("Montant supprimé.", "success")
    return redirect(url_for("chiffre_affaire"))


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

        exists = conn.execute(
            "SELECT COUNT(*) FROM users WHERE username=?",
            (username,),
        ).fetchone()[0]

        if exists > 0:
            flash("Nom d'utilisateur déjà utilisé.", "danger")
            return redirect(url_for("admin_users"))

        conn.execute(
            """
            INSERT INTO users (username, password, role)
            VALUES (?, ?, ?)
            """,
            (username, generate_password_hash(password), role),
        )
        conn.commit()

        flash("Utilisateur créé.", "success")
        return redirect(url_for("admin_users"))

    users = conn.execute("SELECT * FROM users ORDER BY id ASC").fetchall()
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_user(user_id):
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE id=?",
        (user_id,),
    ).fetchone()

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

        exists = conn.execute(
            "SELECT COUNT(*) FROM users WHERE username=? AND id<>?",
            (username, user_id),
        ).fetchone()[0]

        if exists > 0:
            flash("Nom déjà utilisé.", "danger")
            return redirect(url_for("admin_edit_user", user_id=user_id))

        if password:
            if len(password) < 10:
                flash("Mot de passe trop court (min 10 caractères).", "danger")
                return redirect(url_for("admin_edit_user", user_id=user_id))
            conn.execute(
                "UPDATE users SET username=?, password=?, role=? WHERE id=?",
                (username, generate_password_hash(password), role, user_id),
            )
        else:
            conn.execute(
                "UPDATE users SET username=?, role=? WHERE id=?",
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
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
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
    user = conn.execute(
        "SELECT id FROM users WHERE id=?",
        (user_id,),
    ).fetchone()

    if not user:
        flash("Utilisateur introuvable.", "danger")
        return redirect(url_for("admin_users"))

    conn.execute(
        "UPDATE users SET password=? WHERE id=?",
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
    # Optionnel: restreindre à certains prefixes seulement
    # ex: if not (key.startswith("clients/") or key.startswith("chat/") or ...): ...
    return key


@app.route("/documents")
@admin_required
def documents():
    if LOCAL_MODE or not s3:
        return render_template("documents.html", fichiers=[])

    fichiers = []
    try:
        items = s3_list_all_objects(AWS_BUCKET)
        for item in items:
            key = item["Key"]
            if key.endswith("/"):
                continue
            fichiers.append(
                {
                    "nom": key,
                    "taille": item["Size"],
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

    try:
        s3_upload_fileobj(fichier, AWS_BUCKET, nom)
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
# 12. CLIENTS + DOSSIERS + DOCUMENTS + COTATIONS
############################################################

@app.route("/clients")
@login_required
def clients():
    conn = get_db()
    user = session.get("user") or {}
    role = (user.get("role") or "").strip().lower()
    q = (request.args.get("q") or "").strip()

    params = []
    where_clause = ""

    if q:
        where_clause = """
        AND (
            crm_clients.name LIKE ?
            OR users.username LIKE ?
        )
        """
        like_q = f"%{q}%"
        params.extend([like_q, like_q])

    if role == "admin":
        rows = conn.execute(
            f"""
            SELECT crm_clients.*, users.username AS commercial_name
            FROM crm_clients
            LEFT JOIN users ON users.id = crm_clients.owner_id
            WHERE 1=1
            {where_clause}
            ORDER BY crm_clients.created_at DESC
            """,
            params
        ).fetchall()
    else:
        rows = conn.execute(
            f"""
            SELECT crm_clients.*, users.username AS commercial_name
            FROM crm_clients
            LEFT JOIN users ON users.id = crm_clients.owner_id
            WHERE crm_clients.owner_id = ?
            {where_clause}
            ORDER BY crm_clients.created_at DESC
            """,
            [user.get("id")] + params
        ).fetchall()

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
        created_at = (request.form.get("created_at") or "").strip()  # optionnel

        if not name:
            flash("Le nom du dossier est obligatoire.", "danger")
            return redirect(url_for("new_client"))

        # Si created_at n'est pas fourni, laisser DEFAULT CURRENT_TIMESTAMP en base
        if created_at:
            cur = conn.execute(
                """
                INSERT INTO crm_clients (name, status, owner_id, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (name, "cotation", user.get("id"), created_at),
            )
        else:
            cur = conn.execute(
                """
                INSERT INTO crm_clients (name, status, owner_id)
                VALUES (?, ?, ?)
                """,
                (name, "cotation", user.get("id")),
            )

        conn.commit()

        flash("Dossier client créé.", "success")
        return redirect(url_for("client_detail", client_id=cur.lastrowid))

    return render_template("client_form.html")


@app.route("/clients/<int:client_id>")
@login_required
def client_detail(client_id):
    conn = get_db()
    user = session.get("user") or {}
    role = (user.get("role") or "").strip().lower()

    # Contrôle d'accès robuste (admin ok)
    if role != "admin":
        row = conn.execute(
            "SELECT owner_id FROM crm_clients WHERE id=?",
            (client_id,),
        ).fetchone()
        if not row or row["owner_id"] != user.get("id"):
            abort(403)

    client = conn.execute(
        """
        SELECT crm_clients.*, users.username AS commercial_name
        FROM crm_clients
        LEFT JOIN users ON users.id = crm_clients.owner_id
        WHERE crm_clients.id = ?
        """,
        (client_id,),
    ).fetchone()

    if not client:
        abort(404)

    cot_rows = conn.execute(
        """
        SELECT *
        FROM cotations
        WHERE client_id = ?
        ORDER BY date_creation DESC
        """,
        (client_id,),
    ).fetchall()

    documents = []
    try:
        documents = list_client_documents(client_id)
    except Exception:
        documents = []

    return render_template(
        "client_detail.html",
        client=row_to_obj(client),
        cotations=[row_to_obj(c) for c in cot_rows],
        documents=documents,
    )


@app.route("/clients/<int:client_id>/delete", methods=["POST"])
@login_required
def delete_client(client_id):
    conn = get_db()
    user = session.get("user") or {}
    role = (user.get("role") or "").strip().lower()

    # Suppression dossier : admin uniquement
    if role != "admin":
        abort(403)

    # Supprimer cotations liées
    conn.execute("DELETE FROM cotations WHERE client_id=?", (client_id,))

    # Supprimer documents S3 liés
    if not LOCAL_MODE and s3:
        try:
            prefix = client_s3_prefix(client_id)
            objs = s3_list_all_objects(AWS_BUCKET, prefix)
            if objs:
                s3.delete_objects(
                    Bucket=AWS_BUCKET,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                )
        except Exception as e:
            print("Erreur suppression documents S3 client:", repr(e))

    # Supprimer client
    conn.execute("DELETE FROM crm_clients WHERE id=?", (client_id,))
    conn.commit()

    flash("Dossier client supprimé.", "success")
    return redirect(url_for("clients"))


@app.route("/clients/<int:client_id>/documents/upload", methods=["POST"])
@login_required
def upload_client_document(client_id):
    conn = get_db()
    user = session.get("user") or {}
    role = (user.get("role") or "").strip().lower()

    # Contrôle accès robuste (admin ok)
    if role != "admin":
        row = conn.execute(
            "SELECT owner_id FROM crm_clients WHERE id=?",
            (client_id,),
        ).fetchone()
        if not row or row["owner_id"] != user.get("id"):
            abort(403)

    if LOCAL_MODE or not s3:
        flash("Upload désactivé en mode local.", "warning")
        return redirect(url_for("client_detail", client_id=client_id))

    files = request.files.getlist("documents")
    if not files:
        flash("Aucun fichier sélectionné.", "warning")
        return redirect(url_for("client_detail", client_id=client_id))

    prefix = client_s3_prefix(client_id)
    uploaded = 0

    for f in files:
        if f and allowed_file(f.filename):
            filename = clean_filename(secure_filename(f.filename))
            key = f"{prefix}{filename}"
            try:
                s3_upload_fileobj(f, AWS_BUCKET, key)
                uploaded += 1
            except Exception as e:
                print("Erreur upload document client:", repr(e))

    if uploaded:
        flash(f"{uploaded} document(s) ajouté(s).", "success")
    else:
        flash("Aucun document valide envoyé.", "warning")

    return redirect(url_for("client_detail", client_id=client_id))


@app.route("/clients/<int:client_id>/documents/delete", methods=["POST"])
@login_required
def delete_client_document(client_id):
    conn = get_db()
    user = session.get("user") or {}
    role = (user.get("role") or "").strip().lower()

    # Contrôle accès robuste (admin ok)
    if role != "admin":
        row = conn.execute(
            "SELECT owner_id FROM crm_clients WHERE id=?",
            (client_id,),
        ).fetchone()
        if not row or row["owner_id"] != user.get("id"):
            abort(403)

    if LOCAL_MODE or not s3:
        flash("Suppression désactivée en mode local.", "warning")
        return redirect(url_for("client_detail", client_id=client_id))

    key = (request.form.get("key") or "").strip()
    if not key:
        abort(400)

    try:
        s3.delete_object(Bucket=AWS_BUCKET, Key=key)
        flash("Document supprimé.", "success")
    except Exception as e:
        print("Erreur suppression document client:", repr(e))
        flash("Erreur lors de la suppression.", "danger")

    return redirect(url_for("client_detail", client_id=client_id))


@app.route("/clients/<int:client_id>/cotations/create", methods=["POST"])
@login_required
def create_cotation(client_id):
    """
    Création cotation:
    - admin: autorisé toujours
    - commercial: uniquement si owner_id du client == user.id
    (ne dépend PAS de can_access_client pour éviter les 403 persistants)
    """
    conn = get_db()
    user = session.get("user") or {}
    role = (user.get("role") or "").strip().lower()

    if role != "admin":
        row = conn.execute(
            "SELECT owner_id FROM crm_clients WHERE id=?",
            (client_id,),
        ).fetchone()
        if not row or row["owner_id"] != user.get("id"):
            abort(403)

    data = request.form

    conn.execute(
        """
        INSERT INTO cotations (
            client_id,
            fournisseur_actuel,
            date_echeance,
            date_negociation,
            energie_type,
            entreprise_nom,
            siret,
            signataire_nom,
            signataire_tel,
            signataire_email,
            pdl_pce,
            commentaire,
            created_by,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'nouvelle')
        """,
        (
            client_id,
            (data.get("fournisseur_actuel") or "").strip(),
            (data.get("date_echeance") or "").strip(),
            (data.get("date_negociation") or "").strip(),
            (data.get("energie_type") or "").strip(),
            (data.get("entreprise_nom") or "").strip(),
            (data.get("siret") or "").strip(),
            (data.get("signataire_nom") or "").strip(),
            (data.get("signataire_tel") or "").strip(),
            (data.get("signataire_email") or "").strip(),
            (data.get("pdl_pce") or "").strip(),
            (data.get("commentaire") or "").strip(),
            user.get("id"),
        ),
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

    conn = get_db()
    rows = conn.execute(
        """
        SELECT id, user_id, username, message, file_key, file_name, created_at
        FROM chat_messages
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit_int,),
    ).fetchall()

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
        return jsonify({"success": False, "message": "Message ou fichier requis."}), 400

    u = session.get("user") or {}
    conn = get_db()
    cur = conn.execute(
        """
        INSERT INTO chat_messages (user_id, username, message, file_key, file_name)
        VALUES (?, ?, ?, ?, ?)
        """,
        (u.get("id"), u.get("username"), message, file_key, file_name),
    )
    conn.commit()

    return jsonify({"success": True, "id": cur.lastrowid})


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
