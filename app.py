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


############################################################
# 2. INITIALISATION FLASK
############################################################

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = app.config["SECRET_KEY"]

# Sécurité cookies session (prod-friendly)
app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
if os.environ.get("FLASK_ENV") == "production":
    app.config["SESSION_COOKIE_SECURE"] = True

# Limite upload (évite DOS)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024


############################################################
# 3. BASE DE DONNÉES
############################################################

def _connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_db():
    if "db" not in g:
        g.db = _connect_db()
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        try:
            db.close()
        except Exception:
            pass


def row_to_obj(row):
    return SimpleNamespace(**dict(row)) if row else None


def _try_add_column(conn, table, col_def_sql):
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_def_sql}")
    except sqlite3.OperationalError:
        pass


def init_db():
    conn = _connect_db()

    # =======================
    # TABLE CLIENTS
    # =======================
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

    # =======================
    # TABLE UTILISATEURS
    # =======================
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    """)

    # =======================
    # TABLE REVENUS
    # =======================
    conn.execute("""
        CREATE TABLE IF NOT EXISTS revenus (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            commercial TEXT NOT NULL,
            montant REAL NOT NULL
        )
    """)

    # =======================
    # TABLE RENDEZ-VOUS (AGENDA) ✅ CORRIGÉE
    # =======================
    conn.execute("""
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            date TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            description TEXT,
            color TEXT,
            client_id INTEGER,
            created_by INTEGER NOT NULL,
            FOREIGN KEY (client_id) REFERENCES crm_clients(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    """)

    # =======================
    # TABLE COTATIONS
    # =======================
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cotations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            description TEXT NOT NULL,
            fournisseur_actuel TEXT,
            date_echeance TEXT,
            date_negociation_date TEXT,
            date_negociation_time TEXT,
            created_by INTEGER,
            is_read INTEGER DEFAULT 0,
            status TEXT DEFAULT 'nouvelle',
            date_creation TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (client_id) REFERENCES crm_clients(id)
        )
    """)

    # =======================
    # TABLE CHAT
    # =======================
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

    # =======================
    # BOOTSTRAP ADMIN
    # =======================
    admin = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not admin:
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("admin123"), "admin"),
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
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


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

    try:
        fileobj.stream.seek(0)
    except Exception:
        pass

    s3.upload_fileobj(
        fileobj,
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


def list_client_documents(client_id: int):
    if LOCAL_MODE or not s3:
        return []

    prefix = client_s3_prefix(client_id)
    docs = []

    try:
        response = s3.list_objects_v2(Bucket=AWS_BUCKET, Prefix=prefix)
        for item in (response.get("Contents") or []):
            key = item["Key"]
            if key.endswith("/"):
                continue

            docs.append(
                {
                    "nom": key.replace(prefix, ""),
                    "key": key,
                    "taille": item["Size"],
                    "url": s3_presigned_url(key),
                }
            )
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
# 6. AUTHENTIFICATION — DÉCORATEURS
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
# 6bis. CSRF + CONTEXT GLOBALS (SAFE / NON BLOQUANT)
############################################################

# Génère un token en session (utile si un jour tu veux le réactiver)
@app.before_request
def ensure_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)


# ⚠️ CSRF DÉSACTIVÉ VOLONTAIREMENT
# --------------------------------
# IMPORTANT :
# - AUCUNE validation CSRF
# - ZÉRO impact sur les formulaires existants
# - Compatible AJAX / JSON / FullCalendar
# - Comportement IDENTIQUE à ton ancien CRM fonctionnel
#
# (Ne rien ajouter ici)


@app.context_processor
def inject_globals():
    u = session.get("user")
    return dict(
        current_user=SimpleNamespace(**u) if u else None,
        csrf_token=session.get("csrf_token"),
    )


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
# 8. DASHBOARD + SEARCH
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
    last_docs = []

    if not LOCAL_MODE and s3:
        try:
            response = s3.list_objects_v2(Bucket=AWS_BUCKET)
            files = response.get("Contents") or []
            files = [f for f in files if not f["Key"].endswith("/")]
            total_docs = len(files)

            files_sorted = sorted(files, key=lambda x: x["LastModified"], reverse=True)
            last_docs = [
                {"nom": f["Key"], "taille": f["Size"], "date": f["LastModified"]}
                for f in files_sorted[:5]
            ]
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
        last_rev=last_rev,
        total_docs=total_docs,
        last_docs=last_docs,
        unread_cotations=unread_cotations,
        cotations_admin=cotations_admin,
    )


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
# 9. REVENUS (CHIFFRE D'AFFAIRE)
############################################################

@app.route("/chiffre_affaire", methods=["GET", "POST"])
@login_required
def chiffre_affaire():
    user = session.get("user") or {}

    if request.method == "POST":
        montant = request.form.get("montant")
        date_rev = request.form.get("date")

        # Le commercial est l'utilisateur connecté
        commercial = user.get("username")

        if not montant or not date_rev:
            flash("Tous les champs sont obligatoires.", "danger")
            return redirect(url_for("chiffre_affaire"))

        conn = get_db()
        conn.execute(
            """
            INSERT INTO revenus (date, commercial, montant)
            VALUES (?, ?, ?)
            """,
            (date_rev, commercial, montant),
        )
        conn.commit()

        flash("Revenu enregistré.", "success")
        return redirect(url_for("chiffre_affaire"))

    conn = get_db()

    if user.get("role") == "admin":
        revenus = conn.execute(
            """
            SELECT id, date, commercial, montant
            FROM revenus
            ORDER BY date DESC
            """
        ).fetchall()
    else:
        revenus = conn.execute(
            """
            SELECT id, date, commercial, montant
            FROM revenus
            WHERE commercial = ?
            ORDER BY date DESC
            """,
            (user.get("username"),),
        ).fetchall()

    today_obj = date.today()
    year_str = str(today_obj.year)
    month_str = today_obj.strftime("%Y-%m")

    if user.get("role") == "admin":
        total_annuel = conn.execute(
            """
            SELECT COALESCE(SUM(montant), 0)
            FROM revenus
            WHERE substr(date, 1, 4) = ?
            """,
            (year_str,),
        ).fetchone()[0]

        total_mensuel = conn.execute(
            """
            SELECT COALESCE(SUM(montant), 0)
            FROM revenus
            WHERE substr(date, 1, 7) = ?
            """,
            (month_str,),
        ).fetchone()[0]
    else:
        total_annuel = conn.execute(
            """
            SELECT COALESCE(SUM(montant), 0)
            FROM revenus
            WHERE substr(date, 1, 4) = ?
              AND commercial = ?
            """,
            (year_str, user.get("username")),
        ).fetchone()[0]

        total_mensuel = conn.execute(
            """
            SELECT COALESCE(SUM(montant), 0)
            FROM revenus
            WHERE substr(date, 1, 7) = ?
              AND commercial = ?
            """,
            (month_str, user.get("username")),
        ).fetchone()[0]

    annuel_par_com = conn.execute(
        """
        SELECT commercial, COALESCE(SUM(montant), 0) AS total
        FROM revenus
        WHERE substr(date, 1, 4) = ?
        GROUP BY commercial
        ORDER BY total DESC
        """,
        (year_str,),
    ).fetchall()

    mensuel_par_com = conn.execute(
        """
        SELECT commercial, COALESCE(SUM(montant), 0) AS total
        FROM revenus
        WHERE substr(date, 1, 7) = ?
        GROUP BY commercial
        ORDER BY total DESC
        """,
        (month_str,),
    ).fetchall()

    return render_template(
        "chiffre_affaire.html",
        today=today_obj.isoformat(),
        revenus=revenus,
        total_mensuel=total_mensuel,
        total_annuel=total_annuel,
        mensuel_par_com=mensuel_par_com,
        annuel_par_com=annuel_par_com,
    )


@app.route("/chiffre_affaire/data")
@login_required
def chiffre_affaire_data():
    user = session.get("user") or {}
    conn = get_db()

    if user.get("role") == "admin":
        rows = conn.execute("SELECT date, montant FROM revenus").fetchall()
    else:
        rows = conn.execute(
            """
            SELECT date, montant FROM revenus
            WHERE commercial = ?
            """,
            (user.get("username"),),
        ).fetchall()

    mois_noms = {
        "01": "Janvier", "02": "Février", "03": "Mars",
        "04": "Avril", "05": "Mai", "06": "Juin",
        "07": "Juillet", "08": "Août", "09": "Septembre",
        "10": "Octobre", "11": "Novembre", "12": "Décembre",
    }

    data_par_mois = {}
    for r in rows:
        month = r["date"][5:7]
        data_par_mois.setdefault(month, 0)
        data_par_mois[month] += float(r["montant"])

    labels = [mois_noms[m] for m in sorted(data_par_mois.keys())]
    data_vals = [data_par_mois[m] for m in sorted(data_par_mois.keys())]

    return jsonify({"labels": labels, "data": data_vals})


@app.route("/chiffre_affaire/delete/<int:rev_id>", methods=["POST"])
@login_required
def delete_revenue(rev_id):
    user = session.get("user") or {}
    conn = get_db()

    row = conn.execute(
        "SELECT commercial FROM revenus WHERE id=?",
        (rev_id,),
    ).fetchone()

    if not row:
        flash("Entrée introuvable.", "danger")
        return redirect(url_for("chiffre_affaire"))

    if user.get("role") != "admin" and row["commercial"] != user.get("username"):
        flash("Accès refusé.", "danger")
        return redirect(url_for("chiffre_affaire"))

    conn.execute("DELETE FROM revenus WHERE id=?", (rev_id,))
    conn.commit()

    flash("Entrée supprimée.", "success")
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

        exists = conn.execute(
            """
            SELECT COUNT(*) FROM users WHERE username=? AND id<>?
            """,
            (username, user_id),
        ).fetchone()[0]

        if exists > 0:
            flash("Nom déjà utilisé.", "danger")
            return redirect(url_for("admin_edit_user", user_id=user_id))

        if password:
            conn.execute(
                """
                UPDATE users SET username=?, password=?, role=? WHERE id=?
                """,
                (username, generate_password_hash(password), role, user_id),
            )
        else:
            conn.execute(
                """
                UPDATE users SET username=?, role=? WHERE id=?
                """,
                (username, role, user_id),
            )

        conn.commit()
        flash("Utilisateur mis à jour.", "success")
        return redirect(url_for("admin_users"))

    return render_template("admin_edit_user.html", user=user)


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

@app.route("/documents")
@admin_required
def documents():
    if LOCAL_MODE or not s3:
        return render_template("documents.html", fichiers=[])

    fichiers = []
    try:
        response = s3.list_objects_v2(Bucket=AWS_BUCKET)
        for item in (response.get("Contents") or []):
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
        s3.delete_object(Bucket=AWS_BUCKET, Key=key)
        flash("Document supprimé.", "success")
    except Exception as e:
        print("Erreur suppression S3 (admin) :", repr(e))
        flash("Erreur suppression S3.", "danger")

    return redirect(url_for("documents"))


############################################################
# 12. CLIENTS (sécurisé multi-commerciaux) + EDIT/DELETE + DOCS
############################################################

@app.route("/clients")
@login_required
def clients():
    user = session.get("user") or {}
    conn = get_db()

    if user.get("role") == "admin":
        rows = conn.execute(
            "SELECT * FROM crm_clients ORDER BY created_at DESC"
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT * FROM crm_clients
            WHERE owner_id = ?
            ORDER BY created_at DESC
            """,
            (user.get("id"),),
        ).fetchall()

    return render_template("clients.html", clients=[row_to_obj(r) for r in rows])


@app.route("/clients/new", methods=["GET", "POST"])
@login_required
def new_client():
    statuses = ["demande de cotation", "en cours", "signé", "perdu"]
    user = session.get("user") or {}

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Nom obligatoire.", "danger")
            return redirect(url_for("new_client"))

        commercial = (
            request.form.get("commercial")
            if user.get("role") == "admin"
            else user.get("username")
        )

        conn = get_db()
        conn.execute(
            """
            INSERT INTO crm_clients
            (name, email, phone, address, commercial, status, notes, owner_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                (request.form.get("email") or "").strip(),
                (request.form.get("phone") or "").strip(),
                (request.form.get("address") or "").strip(),
                commercial,
                (request.form.get("status") or "").strip(),
                (request.form.get("notes") or "").strip(),
                user.get("id"),
            ),
        )
        conn.commit()

        flash("Client créé.", "success")
        return redirect(url_for("clients"))

    return render_template(
        "client_form.html",
        action="new",
        client=None,
        statuses=statuses,
    )


@app.route("/clients/<int:client_id>")
@login_required
def client_detail(client_id):
    try:
        if not can_access_client(client_id):
            flash("Accès non autorisé à ce dossier.", "danger")
            return redirect(url_for("clients"))

        conn = get_db()
        row = conn.execute(
            "SELECT * FROM crm_clients WHERE id=?",
            (client_id,),
        ).fetchone()

        if not row:
            flash("Client introuvable.", "danger")
            return redirect(url_for("clients"))

        cot_rows = conn.execute(
            """
            SELECT * FROM cotations
            WHERE client_id=?
            ORDER BY date_creation DESC, id DESC
            """,
            (client_id,),
        ).fetchall()

        client = row_to_obj(row)
        cotations = [row_to_obj(r) for r in cot_rows]
        documents = list_client_documents(client_id)

        return render_template(
            "client_detail.html",
            client=client,
            cotations=cotations,
            documents=documents,
        )

    except Exception as e:
        print("ERREUR client_detail :", repr(e))
        flash("Erreur lors de l'ouverture du dossier client.", "danger")
        return redirect(url_for("clients"))


@app.route("/clients/<int:client_id>/edit", methods=["GET", "POST"])
@login_required
def edit_client(client_id):
    if not can_access_client(client_id):
        flash("Accès non autorisé à ce dossier.", "danger")
        return redirect(url_for("clients"))

    statuses = ["demande de cotation", "en cours", "signé", "perdu"]
    user = session.get("user") or {}

    conn = get_db()
    row = conn.execute(
        "SELECT * FROM crm_clients WHERE id=?",
        (client_id,),
    ).fetchone()

    if not row:
        flash("Client introuvable.", "danger")
        return redirect(url_for("clients"))

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Nom obligatoire.", "danger")
            return redirect(url_for("edit_client", client_id=client_id))

        commercial = (request.form.get("commercial") or "").strip()
        if user.get("role") != "admin":
            commercial = row["commercial"]

        conn.execute(
            """
            UPDATE crm_clients
            SET name=?, email=?, phone=?, address=?, commercial=?, status=?, notes=?
            WHERE id=?
            """,
            (
                name,
                (request.form.get("email") or "").strip(),
                (request.form.get("phone") or "").strip(),
                (request.form.get("address") or "").strip(),
                commercial,
                (request.form.get("status") or "").strip(),
                (request.form.get("notes") or "").strip(),
                client_id,
            ),
        )
        conn.commit()

        flash("Client mis à jour.", "success")
        return redirect(url_for("client_detail", client_id=client_id))

    return render_template(
        "client_form.html",
        action="edit",
        client=row_to_obj(row),
        statuses=statuses,
    )


@app.route("/clients/<int:client_id>/delete", methods=["POST"])
@login_required
def delete_client(client_id):
    if not can_access_client(client_id):
        flash("Accès refusé.", "danger")
        return redirect(url_for("clients"))

    conn = get_db()
    conn.execute("DELETE FROM crm_clients WHERE id=?", (client_id,))
    conn.commit()

    flash("Client supprimé.", "success")
    return redirect(url_for("clients"))


@app.route("/clients/<int:client_id>/documents/upload", methods=["POST"])
@login_required
def client_upload_document(client_id):
    if not can_access_client(client_id):
        flash("Accès refusé.", "danger")
        return redirect(url_for("clients"))

    if LOCAL_MODE or not s3:
        flash("Upload désactivé en mode local.", "warning")
        return redirect(url_for("client_detail", client_id=client_id))

    fichier = request.files.get("file")
    if not fichier or not allowed_file(fichier.filename):
        flash("Fichier non valide.", "danger")
        return redirect(url_for("client_detail", client_id=client_id))

    filename = clean_filename(secure_filename(fichier.filename))
    key = client_s3_prefix(client_id) + filename

    try:
        s3_upload_fileobj(fichier, AWS_BUCKET, key)
        flash("Document envoyé.", "success")
    except Exception as e:
        print("Erreur upload doc client:", repr(e))
        flash("Erreur upload document.", "danger")

    return redirect(url_for("client_detail", client_id=client_id))


@app.route("/clients/<int:client_id>/documents/delete/<path:key>", methods=["POST"])
@login_required
def client_delete_document(client_id, key):
    if not can_access_client(client_id):
        flash("Accès refusé.", "danger")
        return redirect(url_for("clients"))

    if LOCAL_MODE or not s3:
        flash("Suppression désactivée en mode local.", "warning")
        return redirect(url_for("client_detail", client_id=client_id))

    full_key = client_s3_prefix(client_id) + key

    try:
        s3.delete_object(Bucket=AWS_BUCKET, Key=full_key)
        flash("Document supprimé.", "success")
    except Exception as e:
        print("Erreur suppression doc client:", repr(e))
        flash("Erreur suppression document.", "danger")

    return redirect(url_for("client_detail", client_id=client_id))


############################################################
# 12bis. COTATIONS: création + suppression (AJAX/JSON)
############################################################

@app.route("/clients/<int:client_id>/cotations/new", methods=["POST"])
@login_required
def create_cotation(client_id):
    if not can_access_client(client_id):
        flash("Accès refusé.", "danger")
        return redirect(url_for("clients"))

    description = (request.form.get("description") or "").strip()
    fournisseur = (request.form.get("fournisseur_actuel") or "").strip()
    date_echeance = (request.form.get("date_echeance") or "").strip()
    date_negociation_date = (request.form.get("date_negociation_date") or "").strip()
    date_negociation_time = (request.form.get("date_negociation_time") or "").strip()

    if not description:
        flash("Description obligatoire.", "danger")
        return redirect(url_for("client_detail", client_id=client_id))

    user = session.get("user") or {}

    conn = get_db()
    conn.execute(
        """
        INSERT INTO cotations
        (client_id, description, fournisseur_actuel, date_echeance,
         date_negociation_date, date_negociation_time, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            client_id,
            description,
            fournisseur,
            date_echeance,
            date_negociation_date or None,
            date_negociation_time or None,
            user.get("id"),
        ),
    )
    conn.commit()

    flash("Cotation ajoutée.", "success")
    return redirect(url_for("client_detail", client_id=client_id))


@app.route("/cotations/<int:cotation_id>/delete", methods=["POST"])
@login_required
def delete_cotation(cotation_id):
    """
    Suppression cotation: admin ou créateur.
    Retour JSON.
    """
    user = session.get("user") or {}
    conn = get_db()

    row = conn.execute(
        "SELECT id, client_id, created_by FROM cotations WHERE id=?",
        (cotation_id,),
    ).fetchone()

    if not row:
        return jsonify(success=False, message="Cotation introuvable"), 404

    if user.get("role") != "admin" and row["created_by"] != user.get("id"):
        return jsonify(success=False, message="Accès refusé"), 403

    if user.get("role") != "admin":
        if not can_access_client(row["client_id"]):
            return jsonify(success=False, message="Accès refusé"), 403

    conn.execute("DELETE FROM cotations WHERE id=?", (cotation_id,))
    conn.commit()

    return jsonify(success=True)


############################################################
# 13. AGENDA / FULLCALENDAR (FONCTIONNEL COMPLET)
############################################################

@app.route("/agenda")
@login_required
def agenda():
    return render_template("calendar.html")


@app.route("/appointments/events_json")
@login_required
def appointments_events_json():
    user = session.get("user")
    conn = get_db()

    if user["role"] == "admin":
        rows = conn.execute("""
            SELECT a.*, u.username AS created_by_name, c.name AS client_name
            FROM appointments a
            JOIN users u ON u.id = a.created_by
            LEFT JOIN crm_clients c ON c.id = a.client_id
        """).fetchall()
    else:
        rows = conn.execute("""
            SELECT a.*, u.username AS created_by_name, c.name AS client_name
            FROM appointments a
            JOIN users u ON u.id = a.created_by
            JOIN crm_clients c ON c.id = a.client_id
            WHERE c.owner_id = ?
        """, (user["id"],)).fetchall()

    events = []
    for r in rows:
        title = r["title"]
        if r["client_name"]:
            title += f" — {r['client_name']}"

        events.append({
            "id": r["id"],
            "title": title,
            "start": f"{r['date']}T{r['start_time']}",
            "end": f"{r['date']}T{r['end_time']}",
            "backgroundColor": r["color"] or "#2563eb",
            "borderColor": r["color"] or "#2563eb",
            "extendedProps": {
                "created_by": r["created_by_name"],
                "description": r["description"]
            }
        })

    return jsonify(events)


@app.route("/appointments/create", methods=["POST"])
@login_required
def appointments_create():
    data = request.get_json() or {}

    title = (data.get("title") or "").strip()
    date_str = data.get("date")

    # Compat: accepte "time" (ancien) ou "start_time"
    start_time = data.get("start_time") or data.get("time") or "09:00"
    end_time = data.get("end_time") or "10:00"

    description = data.get("description") or ""
    color = data.get("color") or "#2563eb"
    client_id = data.get("client_id")
    if client_id in ("", None):
        client_id = None

    if not title or not date_str:
        return jsonify(success=False, message="Titre et date obligatoires"), 400

    user = session.get("user")
    conn = get_db()

    cur = conn.execute("""
        INSERT INTO appointments
        (title, date, start_time, end_time, description, color, client_id, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (title, date_str, start_time, end_time, description, color, client_id, user["id"]))
    conn.commit()

    return jsonify(success=True, id=cur.lastrowid)


@app.route("/appointments/update_from_calendar", methods=["POST"])
@login_required
def appointments_update_from_calendar():
    data = request.get_json() or {}

    appt_id = data.get("id")
    date_str = data.get("date")

    # Compat: accepte "time" -> start_time
    start_time = data.get("start_time") or data.get("time")
    end_time = data.get("end_time")

    if not appt_id or not date_str:
        return jsonify(success=False, message="Données manquantes"), 400

    # Si le front n'envoie pas les heures pendant un drag/drop
    if not start_time:
        start_time = "09:00"
    if not end_time:
        end_time = "10:00"

    user = session.get("user")
    conn = get_db()

    rdv = conn.execute(
        "SELECT created_by FROM appointments WHERE id=?",
        (appt_id,)
    ).fetchone()

    if not rdv:
        return jsonify(success=False, message="RDV introuvable"), 404

    if user["role"] != "admin" and rdv["created_by"] != user["id"]:
        return jsonify(success=False, message="Accès refusé"), 403

    conn.execute("""
        UPDATE appointments
        SET date=?, start_time=?, end_time=?
        WHERE id=?
    """, (date_str, start_time, end_time, appt_id))

    conn.commit()
    return jsonify(success=True)


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

    # évite collisions
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
    app.run(host="0.0.0.0", port=5000, debug=True)
