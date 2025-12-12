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
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def row_to_obj(row):
    return SimpleNamespace(**dict(row)) if row else None


def _try_add_column(conn: sqlite3.Connection, table: str, col_def_sql: str):
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_def_sql}")
    except sqlite3.OperationalError as e:
        if "duplicate" in str(e).lower() or "exists" in str(e).lower():
            return
        raise


def has_column(table: str, column: str) -> bool:
    conn = get_db()
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    conn.close()
    return any(r["name"] == column for r in rows)


def ensure_cotations_schema():
    try:
        conn = get_db()
        _try_add_column(conn, "cotations", "created_by INTEGER")
        conn.commit()
        conn.close()
    except Exception:
        pass


def init_db():
    conn = get_db()

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
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS revenus (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            commercial TEXT NOT NULL,
            montant REAL NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            date TEXT NOT NULL,
            time TEXT,
            client_id INTEGER,
            description TEXT,
            color TEXT
        )
    """)

    conn.execute("""
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
    """)

    _try_add_column(conn, "cotations", "is_read INTEGER DEFAULT 0")
    _try_add_column(conn, "cotations", "status TEXT DEFAULT 'nouvelle'")
    _try_add_column(conn, "cotations", "created_by INTEGER")

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
# 4. S3
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
    except Exception:
        s3 = None


############################################################
# 5. UTILITAIRES
############################################################

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def clean_filename(filename: str) -> str:
    name, ext = os.path.splitext(filename)
    name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    name = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return f"{name}{ext.lower()}"


def s3_upload_fileobj(fileobj, bucket: str, key: str):
    if not s3:
        raise RuntimeError("S3 non initialisé")

    try:
        fileobj.stream.seek(0)
    except Exception:
        pass

    try:
        s3.upload_fileobj(fileobj, bucket, key, ExtraArgs={"ACL": "public-read"})
    except ClientError:
        try:
            fileobj.stream.seek(0)
        except Exception:
            pass
        s3.upload_fileobj(fileobj, bucket, key)


def slugify(text: str) -> str:
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def client_s3_prefix(client_id: int) -> str:
    return f"clients/client_{client_id}/"


def s3_url(key: str) -> str:
    return f"https://{AWS_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{key}"


############################################################
# 6. AUTH
############################################################

def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return w


def admin_required(f):
    @wraps(f)
    def w(*a, **kw):
        if session.get("user", {}).get("role") != "admin":
            return redirect(url_for("dashboard"))
        return f(*a, **kw)
    return w


############################################################
# 7. DOCUMENTS S3
############################################################

@app.route("/documents")
@login_required
def documents():
    fichiers = []
    if s3:
        res = s3.list_objects_v2(Bucket=AWS_BUCKET)
        for o in res.get("Contents", []):
            fichiers.append({"nom": o["Key"], "url": s3_url(o["Key"])})
    return render_template("documents.html", fichiers=fichiers)


@app.route("/documents/upload", methods=["POST"])
@login_required
def upload_document():
    f = request.files.get("file")
    if not f or not allowed_file(f.filename):
        return redirect(url_for("documents"))

    key = clean_filename(secure_filename(f.filename))
    s3_upload_fileobj(f, AWS_BUCKET, key)
    return redirect(url_for("documents"))


############################################################
# 8. CLIENTS — UPLOAD
############################################################

@app.route("/clients/<int:client_id>/upload_document", methods=["POST"])
@login_required
def client_upload_document(client_id):
    f = request.files.get("file")
    if not f or not allowed_file(f.filename):
        return redirect(url_for("client_detail", client_id=client_id))

    key = client_s3_prefix(client_id) + clean_filename(secure_filename(f.filename))
    s3_upload_fileobj(f, AWS_BUCKET, key)
    return redirect(url_for("client_detail", client_id=client_id))


############################################################
# 9. CHAT — UPLOAD
############################################################

def _chat_store_file(file):
    if not file or not allowed_file(file.filename):
        return None, None

    key = "chat/" + clean_filename(file.filename)
    s3_upload_fileobj(file, AWS_BUCKET, key)
    return key, file.filename


############################################################
# ROOT
############################################################

@app.route("/")
def index():
    return redirect(url_for("documents"))
