import os
import re
import unicodedata
import sqlite3
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
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

import boto3
from botocore.exceptions import ClientError

import psycopg2
from psycopg2.extras import RealDictCursor

from config import Config


############################################################
# 1. CONFIGURATION GLOBALE
############################################################

LOCAL_MODE = Config.LOCAL_MODE

AWS_ACCESS_KEY = Config.AWS_ACCESS_KEY
AWS_SECRET_KEY = Config.AWS_SECRET_KEY
AWS_REGION = Config.AWS_REGION
AWS_BUCKET = Config.AWS_BUCKET

SQLITE_DB_PATH = Config.SQLITE_DB_PATH
DATABASE_URL = Config.DATABASE_URL

ALLOWED_EXTENSIONS = {"pdf", "jpg", "jpeg", "png", "doc", "docx"}


############################################################
# 2. INITIALISATION FLASK
############################################################

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = app.config["SECRET_KEY"]


############################################################
# 3. BASE DE DONNÉES
############################################################

def get_db():
    if DATABASE_URL:
        return psycopg2.connect(
            DATABASE_URL,
            cursor_factory=RealDictCursor,
            sslmode="require"
        )

    conn = sqlite3.connect(SQLITE_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def row_to_obj(row):
    return SimpleNamespace(**dict(row)) if row else None


def _try_add_column(conn, table: str, col_def_sql: str):
    try:
        if DATABASE_URL:
            conn.cursor().execute(f"ALTER TABLE {table} ADD COLUMN {col_def_sql}")
        else:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_def_sql}")
    except Exception:
        pass


def has_column(table: str, column: str) -> bool:
    conn = get_db()
    try:
        if DATABASE_URL:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name=%s AND column_name=%s
                """,
                (table, column),
            )
            return cur.fetchone() is not None
        else:
            rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
            return any(r["name"] == column for r in rows)
    finally:
        conn.close()


def ensure_cotations_schema():
    conn = get_db()
    try:
        _try_add_column(conn, "cotations", "is_read INTEGER DEFAULT 0")
        _try_add_column(conn, "cotations", "status TEXT DEFAULT 'nouvelle'")
        _try_add_column(conn, "cotations", "created_by INTEGER")
        conn.commit()
    finally:
        conn.close()


def init_db():
    if DATABASE_URL:
        return

    conn = get_db()

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS crm_clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            address TEXT,
            commercial TEXT,
            status TEXT,
            notes TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS revenus (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            commercial TEXT NOT NULL,
            montant REAL NOT NULL
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            date TEXT NOT NULL,
            time TEXT,
            client_id INTEGER,
            description TEXT,
            color TEXT
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS cotations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            description TEXT NOT NULL,
            fournisseur_actuel TEXT,
            date_echeance TEXT,
            date_negociation_date TEXT,
            date_negociation_time TEXT,
            date_creation TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    _try_add_column(conn, "cotations", "is_read INTEGER DEFAULT 0")
    _try_add_column(conn, "cotations", "status TEXT DEFAULT 'nouvelle'")
    _try_add_column(conn, "cotations", "created_by INTEGER")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            message TEXT,
            file_key TEXT,
            file_name TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    existing = conn.execute(
        "SELECT id FROM users WHERE username='admin'"
    ).fetchone()

    if not existing:
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
    cur = conn.cursor() if DATABASE_URL else conn
    row = cur.execute(
        "SELECT name FROM crm_clients WHERE id=%s" if DATABASE_URL else
        "SELECT name FROM crm_clients WHERE id=?",
        (client_id,),
    ).fetchone()
    conn.close()

    base = f"client_{client_id}"
    if row and row["name"]:
        s = slugify(row["name"])
        if s:
            base = f"{s}_{client_id}"

    return f"clients/{base}/"


def s3_upload_fileobj(fileobj, bucket: str, key: str):
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
            "ContentType": getattr(fileobj, "mimetype", None)
            or "application/octet-stream"
        },
    )


def s3_presigned_url(key: str, expires_in: int = 3600) -> str:
    if LOCAL_MODE or not s3:
        return ""

    try:
        return s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": AWS_BUCKET, "Key": key},
            ExpiresIn=expires_in,
        )
    except Exception:
        return ""


def list_client_documents(client_id: int):
    if LOCAL_MODE or not s3:
        return []

    prefix = client_s3_prefix(client_id)
    docs = []

    try:
        response = s3.list_objects_v2(Bucket=AWS_BUCKET, Prefix=prefix)
        for item in response.get("Contents", []):
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
    except Exception:
        pass

    return docs


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


@app.context_processor
def inject_current_user():
    return dict(current_user=session.get("user"))


############################################################
# 7. LOGIN / LOGOUT
############################################################

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db()
        cur = conn.cursor() if DATABASE_URL else conn
        user = cur.execute(
            "SELECT * FROM users WHERE username=%s" if DATABASE_URL else
            "SELECT * FROM users WHERE username=?",
            (username,),
        ).fetchone()
        conn.close()

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
# 8. DASHBOARD
############################################################

@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    cur = conn.cursor() if DATABASE_URL else conn

    total_clients = cur.execute(
        "SELECT COUNT(*) FROM crm_clients"
    ).fetchone()[0]

    last_clients = cur.execute(
        """
        SELECT name, email, created_at
        FROM crm_clients
        ORDER BY created_at DESC
        LIMIT 5
        """
    ).fetchall()

    total_ca = cur.execute(
        "SELECT COALESCE(SUM(montant), 0) FROM revenus"
    ).fetchone()[0]

    last_rev = cur.execute(
        """
        SELECT montant, date, commercial
        FROM revenus
        ORDER BY date DESC, id DESC
        LIMIT 1
        """
    ).fetchone()

    conn.close()

    total_docs = 0
    last_docs = []

    if not LOCAL_MODE and s3:
        try:
            response = s3.list_objects_v2(Bucket=AWS_BUCKET)
            files = response.get("Contents", [])
            total_docs = len(files)

            files_sorted = sorted(
                files, key=lambda x: x["LastModified"], reverse=True
            )
            last_docs = [
                {
                    "nom": f["Key"],
                    "taille": f["Size"],
                    "date": f["LastModified"],
                }
                for f in files_sorted[:5]
            ]
        except Exception:
            pass

    unread_cotations = 0
    if session["user"]["role"] == "admin":
        conn2 = get_db()
        cur2 = conn2.cursor() if DATABASE_URL else conn2
        unread_cotations = cur2.execute(
            "SELECT COUNT(*) FROM cotations WHERE COALESCE(is_read,0)=0"
        ).fetchone()[0]
        conn2.close()

    return render_template(
        "dashboard.html",
        total_clients=total_clients,
        last_clients=last_clients,
        total_ca=total_ca,
        last_rev=last_rev,
        total_docs=total_docs,
        last_docs=last_docs,
        unread_cotations=unread_cotations,
    )


############################################################
# 9. REVENUS
############################################################

@app.route("/chiffre_affaire", methods=["GET", "POST"])
@login_required
def chiffre_affaire():
    conn = get_db()
    cur = conn.cursor() if DATABASE_URL else conn

    if request.method == "POST":
        montant = request.form.get("montant")
        commercial = request.form.get("commercial")
        date_rev = request.form.get("date")

        if not montant or not commercial or not date_rev:
            flash("Tous les champs sont obligatoires.", "danger")
            return redirect(url_for("chiffre_affaire"))

        cur.execute(
            """
            INSERT INTO revenus (date, commercial, montant)
            VALUES (%s, %s, %s)
            """ if DATABASE_URL else
            """
            INSERT INTO revenus (date, commercial, montant)
            VALUES (?, ?, ?)
            """,
            (date_rev, commercial, montant),
        )
        conn.commit()
        conn.close()

        flash("Revenu enregistré.", "success")
        return redirect(url_for("chiffre_affaire"))

    revenus = cur.execute(
        """
        SELECT id, date, commercial, montant
        FROM revenus
        ORDER BY date DESC
        """
    ).fetchall()

    today = date.today()
    year = str(today.year)
    month = today.strftime("%Y-%m")

    total_annuel = cur.execute(
        """
        SELECT COALESCE(SUM(montant),0)
        FROM revenus
        WHERE substr(date,1,4)=?
        """ if not DATABASE_URL else
        """
        SELECT COALESCE(SUM(montant),0)
        FROM revenus
        WHERE LEFT(date,4)=%s
        """,
        (year,),
    ).fetchone()[0]

    total_mensuel = cur.execute(
        """
        SELECT COALESCE(SUM(montant),0)
        FROM revenus
        WHERE substr(date,1,7)=?
        """ if not DATABASE_URL else
        """
        SELECT COALESCE(SUM(montant),0)
        FROM revenus
        WHERE LEFT(date,7)=%s
        """,
        (month,),
    ).fetchone()[0]

    conn.close()

    return render_template(
        "chiffre_affaire.html",
        today=today.isoformat(),
        revenus=revenus,
        total_annuel=total_annuel,
        total_mensuel=total_mensuel,
    )


############################################################
# 10. ADMIN — UTILISATEURS
############################################################

@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    conn = get_db()
    cur = conn.cursor() if DATABASE_URL else conn

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "").strip()

        if not username or not password or not role:
            flash("Champs obligatoires.", "danger")
            return redirect(url_for("admin_users"))

        cur.execute(
            """
            INSERT INTO users (username, password, role)
            VALUES (%s, %s, %s)
            """ if DATABASE_URL else
            """
            INSERT INTO users (username, password, role)
            VALUES (?, ?, ?)
            """,
            (username, generate_password_hash(password), role),
        )
        conn.commit()
        flash("Utilisateur créé.", "success")

    users = cur.execute("SELECT * FROM users ORDER BY id").fetchall()
    conn.close()

    return render_template("admin_users.html", users=users)
############################################################
# 11. DOCUMENTS GLOBAUX S3
############################################################

@app.route("/documents")
@login_required
def documents():
    if LOCAL_MODE or not s3:
        return render_template("documents.html", fichiers=[])

    fichiers = []
    try:
        response = s3.list_objects_v2(Bucket=AWS_BUCKET)
        for item in response.get("Contents", []):
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
    except Exception:
        flash("Erreur lors du listing S3.", "danger")

    return render_template("documents.html", fichiers=fichiers)


@app.route("/documents/upload", methods=["POST"])
@login_required
def upload_document():
    if LOCAL_MODE or not s3:
        flash("Upload désactivé.", "warning")
        return redirect(url_for("documents"))

    fichier = request.files.get("file")
    if not fichier or not allowed_file(fichier.filename):
        flash("Fichier non valide.", "danger")
        return redirect(url_for("documents"))

    nom = clean_filename(secure_filename(fichier.filename))
    s3_upload_fileobj(fichier, AWS_BUCKET, nom)
    flash("Document envoyé.", "success")
    return redirect(url_for("documents"))


############################################################
# 12. CLIENTS
############################################################

@app.route("/clients")
@login_required
def clients():
    conn = get_db()
    cur = conn.cursor() if DATABASE_URL else conn
    rows = cur.execute("SELECT * FROM crm_clients ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template("clients.html", clients=[row_to_obj(r) for r in rows])


@app.route("/clients/<int:client_id>")
@login_required
def client_detail(client_id):
    conn = get_db()
    cur = conn.cursor() if DATABASE_URL else conn

    client = cur.execute(
        "SELECT * FROM crm_clients WHERE id=%s" if DATABASE_URL else
        "SELECT * FROM crm_clients WHERE id=?",
        (client_id,),
    ).fetchone()

    cotations = cur.execute(
        "SELECT * FROM cotations WHERE client_id=%s ORDER BY id DESC"
        if DATABASE_URL else
        "SELECT * FROM cotations WHERE client_id=? ORDER BY id DESC",
        (client_id,),
    ).fetchall()

    conn.close()

    if not client:
        flash("Client introuvable.", "danger")
        return redirect(url_for("clients"))

    return render_template(
        "client_detail.html",
        client=row_to_obj(client),
        cotations=[row_to_obj(c) for c in cotations],
        documents=list_client_documents(client_id),
    )


############################################################
# 13. AGENDA
############################################################

@app.route("/agenda")
@login_required
def agenda():
    return render_template("calendar.html")


############################################################
# 14. CHAT
############################################################

@app.route("/chat/messages")
@login_required
def chat_messages():
    conn = get_db()
    cur = conn.cursor() if DATABASE_URL else conn

    rows = cur.execute(
        "SELECT * FROM chat_messages ORDER BY id DESC LIMIT 100"
    ).fetchall()

    conn.close()

    messages = []
    for r in reversed(rows):
        messages.append(
            {
                "username": r["username"],
                "message": r["message"],
                "file_url": s3_presigned_url(r["file_key"]) if r["file_key"] else None,
                "created_at": r["created_at"],
            }
        )

    return jsonify({"success": True, "messages": messages})


############################################################
# 15. ROOT
############################################################

@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user" in session else url_for("login"))


############################################################
# 16. RUN
############################################################

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
