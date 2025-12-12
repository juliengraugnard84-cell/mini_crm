import os
import re
import unicodedata
import sqlite3
from datetime import date
from types import SimpleNamespace
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, jsonify, session
)

from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

import boto3
from botocore.exceptions import ClientError

from config import Config


############################################################
# 1. CONFIG
############################################################

LOCAL_MODE = Config.LOCAL_MODE

AWS_ACCESS_KEY = Config.AWS_ACCESS_KEY
AWS_SECRET_KEY = Config.AWS_SECRET_KEY
AWS_REGION = Config.AWS_REGION
AWS_BUCKET = Config.AWS_BUCKET

DB_PATH = Config.DB_PATH

ALLOWED_EXTENSIONS = {"pdf", "jpg", "jpeg", "png", "doc", "docx"}


############################################################
# 2. FLASK
############################################################

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = app.config["SECRET_KEY"]


############################################################
# 3. DB
############################################################

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def row_to_obj(row):
    return SimpleNamespace(**dict(row)) if row else None


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    s3 = boto3.client(
        "s3",
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
    )


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

    # ✅ UPLOAD PRIVÉ — AUCUNE ACL
    s3.upload_fileobj(
        fileobj,
        bucket,
        key,
        ExtraArgs={
            "ContentType": fileobj.mimetype or "application/octet-stream"
        }
    )


def s3_presigned_url(key: str, expires_in: int = 3600) -> str:
    if not s3:
        return ""

    try:
        return s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": AWS_BUCKET, "Key": key},
            ExpiresIn=expires_in,
        )
    except ClientError as e:
        print("Erreur URL signée S3:", e.response)
        return ""


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


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=?", (u,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], p):
            session["user"] = {
                "username": user["username"],
                "role": user["role"]
            }
            return redirect(url_for("documents"))

        flash("Identifiants incorrects", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


############################################################
# 7. DOCUMENTS S3 (PRIVÉ)
############################################################

@app.route("/documents")
@login_required
def documents():
    fichiers = []

    if s3:
        res = s3.list_objects_v2(Bucket=AWS_BUCKET)
        for o in res.get("Contents", []):
            fichiers.append({
                "nom": o["Key"],
                "url": s3_presigned_url(o["Key"])
            })

    return render_template("documents.html", fichiers=fichiers)


@app.route("/documents/upload", methods=["POST"])
@login_required
def upload_document():
    f = request.files.get("file")

    if not f or not allowed_file(f.filename):
        flash("Fichier invalide", "danger")
        return redirect(url_for("documents"))

    key = clean_filename(secure_filename(f.filename))
    s3_upload_fileobj(f, AWS_BUCKET, key)

    flash("Document envoyé", "success")
    return redirect(url_for("documents"))


############################################################
# 8. CHAT (UPLOAD PRIVÉ)
############################################################

@app.route("/chat/send", methods=["POST"])
@login_required
def chat_send():
    message = request.form.get("message", "").strip()
    file = request.files.get("file")

    file_key = None
    file_name = None

    if file and allowed_file(file.filename):
        file_name = secure_filename(file.filename)
        file_key = "chat/" + clean_filename(file_name)
        s3_upload_fileobj(file, AWS_BUCKET, file_key)

    if not message and not file_key:
        return jsonify({"success": False})

    conn = get_db()
    conn.execute(
        """
        INSERT INTO chat_messages (username, message, file_key, file_name)
        VALUES (?, ?, ?, ?)
        """,
        (
            session["user"]["username"],
            message,
            file_key,
            file_name,
        ),
    )
    conn.commit()
    conn.close()

    return jsonify({"success": True})


@app.route("/chat/messages")
@login_required
def chat_messages():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM chat_messages ORDER BY id DESC LIMIT 50"
    ).fetchall()
    conn.close()

    messages = []
    for r in reversed(rows):
        messages.append({
            "username": r["username"],
            "message": r["message"],
            "file_name": r["file_name"],
            "file_url": (
                s3_presigned_url(r["file_key"])
                if r["file_key"] else None
            ),
            "created_at": r["created_at"]
        })

    return jsonify(messages)


############################################################
# ROOT
############################################################

@app.route("/")
def index():
    return redirect(url_for("documents"))


############################################################
# RUN
############################################################

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
