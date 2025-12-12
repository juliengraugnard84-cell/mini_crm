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
    """
    Ajoute une colonne si elle n'existe pas.
    col_def_sql exemple: "is_read INTEGER DEFAULT 0"
    """
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_def_sql}")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            return
        if "already exists" in str(e).lower():
            return
        raise


def init_db():
    conn = get_db()

    # TABLE CLIENTS
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

    # TABLE UTILISATEURS
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

    # TABLE REVENUS
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

    # TABLE RENDEZ-VOUS
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            date TEXT NOT NULL,
            time TEXT,
            client_id INTEGER,
            description TEXT,
            color TEXT,
            FOREIGN KEY (client_id) REFERENCES crm_clients(id)
        )
        """
    )

    # TABLE COTATIONS
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
            date_creation TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (client_id) REFERENCES crm_clients(id)
        )
        """
    )

    # ✅ AJOUTS SÉCURISÉS (NE CASSENT RIEN)
    _try_add_column(conn, "cotations", "is_read INTEGER DEFAULT 0")
    _try_add_column(conn, "cotations", "status TEXT DEFAULT 'nouvelle'")
    _try_add_column(conn, "cotations", "created_by INTEGER")

    # TABLE CHAT
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

    # BOOTSTRAP ADMIN
    def create_user_if_missing(username, password, role):
        existing = conn.execute(
            "SELECT id FROM users WHERE username=?", (username,)
        ).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), role),
            )

    create_user_if_missing("admin", "admin123", "admin")

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


def slugify(text: str) -> str:
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


############################################################
# 6. AUTHENTIFICATION
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
        user = conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)
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
        else:
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

    total_clients = conn.execute(
        "SELECT COUNT(*) FROM crm_clients"
    ).fetchone()[0]

    last_clients = conn.execute(
        """
        SELECT name, email, created_at
        FROM crm_clients
        ORDER BY created_at DESC LIMIT 5
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

    conn.close()

    total_docs = 0
    last_docs = []

    if not LOCAL_MODE and s3:
        try:
            response = s3.list_objects_v2(Bucket=AWS_BUCKET)
            files = (response.get("Contents") or [])
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
    if session.get("user", {}).get("role") == "admin":
        conn2 = get_db()
        unread_cotations = conn2.execute(
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
# 9. REVENUS (CHIFFRE D'AFFAIRE)
############################################################

@app.route("/chiffre_affaire", methods=["GET", "POST"])
@login_required
def chiffre_affaire():
    if request.method == "POST":
        montant = request.form.get("montant")
        commercial = request.form.get("commercial")
        date_rev = request.form.get("date")

        if not montant or not commercial or not date_rev:
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
        conn.close()

        flash("Revenu enregistré.", "success")
        return redirect(url_for("chiffre_affaire"))

    conn = get_db()

    revenus = conn.execute(
        """
        SELECT id, date, commercial, montant
        FROM revenus
        ORDER BY date DESC
        """
    ).fetchall()

    today_obj = date.today()
    year_str = str(today_obj.year)
    month_str = today_obj.strftime("%Y-%m")

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

    conn.close()

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
    conn = get_db()
    rows = conn.execute("SELECT date, montant FROM revenus").fetchall()
    conn.close()

    mois_noms = {
        "01": "Janvier", "02": "Février", "03": "Mars", "04": "Avril",
        "05": "Mai", "06": "Juin", "07": "Juillet", "08": "Août",
        "09": "Septembre", "10": "Octobre", "11": "Novembre", "12": "Décembre",
    }

    data_par_mois = {}
    for r in rows:
        month = r["date"][5:7]
        data_par_mois.setdefault(month, 0)
        data_par_mois[month] += float(r["montant"])

    labels = [mois_noms[m] for m in sorted(data_par_mois)]
    data = [data_par_mois[m] for m in sorted(data_par_mois)]

    return jsonify({"labels": labels, "data": data})


@app.route("/chiffre_affaire/delete/<int:rev_id>", methods=["POST"])
@login_required
def delete_revenue(rev_id):
    conn = get_db()
    conn.execute("DELETE FROM revenus WHERE id=?", (rev_id,))
    conn.commit()
    conn.close()

    flash("Entrée supprimée.", "success")
    return redirect(url_for("chiffre_affaire"))


############################################################
# 10. ADMIN UTILISATEURS
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
            conn.close()
            return redirect(url_for("admin_users"))

        exists = conn.execute(
            "SELECT COUNT(*) FROM users WHERE username=?", (username,)
        ).fetchone()[0]

        if exists > 0:
            flash("Nom d'utilisateur déjà utilisé.", "danger")
            conn.close()
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

    users = conn.execute(
        "SELECT * FROM users ORDER BY id ASC"
    ).fetchall()
    conn.close()

    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_user(user_id):
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE id=?", (user_id,)
    ).fetchone()

    if not user:
        flash("Utilisateur introuvable.", "danger")
        conn.close()
        return redirect(url_for("admin_users"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        role = (request.form.get("role") or "").strip()

        exists = conn.execute(
            "SELECT COUNT(*) FROM users WHERE username=? AND id<>?",
            (username, user_id),
        ).fetchone()[0]

        if exists > 0:
            flash("Nom déjà utilisé.", "danger")
            conn.close()
            return redirect(url_for("admin_edit_user", user_id=user_id))

        if password:
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
        conn.close()
        flash("Utilisateur mis à jour.", "success")
        return redirect(url_for("admin_users"))

    conn.close()
    return render_template("admin_edit_user.html", user=user)
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
        for item in (response.get("Contents") or []):
            fichiers.append(
                {
                    "nom": item["Key"],
                    "taille": item["Size"],
                    "url": f"https://{AWS_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{item['Key']}",
                }
            )
    except Exception:
        flash("Erreur lors du listing S3.", "danger")

    return render_template("documents.html", fichiers=fichiers)


@app.route("/documents/upload", methods=["POST"])
@login_required
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
        s3.upload_fileobj(fichier, AWS_BUCKET, nom)
        flash("Document envoyé.", "success")
    except Exception:
        flash("Erreur upload S3.", "danger")

    return redirect(url_for("documents"))


@app.route("/documents/delete/<path:key>", methods=["POST"])
@login_required
def delete_document(key):
    if LOCAL_MODE or not s3:
        flash("Suppression désactivée en local.", "warning")
        return redirect(url_for("documents"))

    try:
        s3.delete_object(Bucket=AWS_BUCKET, Key=key)
        flash("Document supprimé.", "success")
    except Exception:
        flash("Erreur suppression S3.", "danger")

    return redirect(url_for("documents"))


############################################################
# 12. CLIENTS
############################################################

@app.route("/clients")
@login_required
def clients():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM crm_clients ORDER BY created_at DESC"
    ).fetchall()
    conn.close()

    return render_template("clients.html", clients=[row_to_obj(r) for r in rows])


@app.route("/clients/new", methods=["GET", "POST"])
@login_required
def new_client():
    statuses = ["demande de cotation", "en cours", "signé", "perdu"]

    if request.method == "POST":
        data = (
            request.form.get("name").strip(),
            request.form.get("email").strip(),
            request.form.get("phone").strip(),
            request.form.get("address").strip(),
            request.form.get("commercial").strip(),
            request.form.get("status").strip(),
            request.form.get("notes").strip(),
        )

        if not data[0]:
            flash("Nom obligatoire.", "danger")
            return redirect(url_for("new_client"))

        conn = get_db()
        conn.execute(
            """
            INSERT INTO crm_clients
            (name, email, phone, address, commercial, status, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            data,
        )
        conn.commit()
        conn.close()

        flash("Client créé.", "success")
        return redirect(url_for("clients"))

    return render_template(
        "client_form.html", action="new", client=None, statuses=statuses
    )


@app.route("/clients/<int:client_id>")
@login_required
def client_detail(client_id):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM crm_clients WHERE id=?", (client_id,)
    ).fetchone()
    cot_rows = conn.execute(
        """
        SELECT * FROM cotations
        WHERE client_id=?
        ORDER BY date_creation DESC, id DESC
        """,
        (client_id,),
    ).fetchall()
    conn.close()

    if not row:
        flash("Client introuvable.", "danger")
        return redirect(url_for("clients"))

    # ADMIN : marquer les cotations comme lues
    if session.get("user", {}).get("role") == "admin":
        conn2 = get_db()
        conn2.execute(
            "UPDATE cotations SET is_read=1 WHERE client_id=?",
            (client_id,),
        )
        conn2.commit()
        conn2.close()

    client = row_to_obj(row)
    cotations = [row_to_obj(r) for r in cot_rows]

    return render_template(
        "client_detail.html",
        client=client,
        cotations=cotations,
    )


@app.route("/clients/<int:client_id>/edit", methods=["GET", "POST"])
@login_required
def edit_client(client_id):
    statuses = ["demande de cotation", "en cours", "signé", "perdu"]

    conn = get_db()
    row = conn.execute(
        "SELECT * FROM crm_clients WHERE id=?", (client_id,)
    ).fetchone()
    client = row_to_obj(row)
    conn.close()

    if not client:
        flash("Client introuvable.", "danger")
        return redirect(url_for("clients"))

    if request.method == "POST":
        data = (
            request.form.get("name").strip(),
            request.form.get("email").strip(),
            request.form.get("phone").strip(),
            request.form.get("address").strip(),
            request.form.get("commercial").strip(),
            request.form.get("status").strip(),
            request.form.get("notes").strip(),
        )

        if not data[0]:
            flash("Nom obligatoire.", "danger")
            return redirect(url_for("edit_client", client_id=client_id))

        conn = get_db()
        conn.execute(
            """
            UPDATE crm_clients
            SET name=?, email=?, phone=?, address=?, commercial=?, status=?, notes=?
            WHERE id=?
            """,
            (*data, client_id),
        )
        conn.commit()
        conn.close()

        flash("Client mis à jour.", "success")
        return redirect(url_for("client_detail", client_id=client_id))

    return render_template(
        "client_form.html", action="edit", client=client, statuses=statuses
    )


@app.route("/clients/<int:client_id>/delete", methods=["POST"])
@login_required
def delete_client(client_id):
    conn = get_db()
    conn.execute("DELETE FROM crm_clients WHERE id=?", (client_id,))
    conn.commit()
    conn.close()

    flash("Client supprimé.", "success")
    return redirect(url_for("clients"))


############################################################
# 13. COTATIONS — CORRIGÉES (RÈGLE MÉTIER STRICTE)
############################################################

@app.route("/clients/<int:client_id>/cotations/create", methods=["POST"])
@login_required
def create_cotation(client_id):
    description = (request.form.get("description") or "").strip()
    fournisseur_actuel = (request.form.get("fournisseur_actuel") or "").strip()
    date_echeance = (request.form.get("date_echeance") or "").strip()
    date_negociation_date = (request.form.get("date_negociation_date") or "").strip()
    date_negociation_time = (request.form.get("date_negociation_time") or "").strip()

    if not description:
        flash("La description est obligatoire.", "danger")
        return redirect(url_for("client_detail", client_id=client_id))

    conn = get_db()
    conn.execute(
        """
        INSERT INTO cotations
        (client_id, description, fournisseur_actuel,
         date_echeance, date_negociation_date,
         date_negociation_time, status, is_read, created_by)
        VALUES (?, ?, ?, ?, ?, ?, 'nouvelle', 0, ?)
        """,
        (
            client_id,
            description,
            fournisseur_actuel,
            date_echeance,
            date_negociation_date,
            date_negociation_time,
            session["user"]["id"],
        ),
    )
    conn.commit()
    conn.close()

    flash("Demande de cotation créée.", "success")
    return redirect(url_for("client_detail", client_id=client_id))


@app.route("/cotations/<int:cotation_id>/update", methods=["POST"])
@login_required
def update_cotation(cotation_id):
    conn = get_db()
    cot = conn.execute(
        "SELECT * FROM cotations WHERE id=?", (cotation_id,)
    ).fetchone()

    if not cot:
        conn.close()
        return jsonify({"success": False}), 404

    user = session["user"]
    if user["role"] != "admin" and cot["created_by"] != user["id"]:
        conn.close()
        return jsonify({"success": False}), 403

    data = request.get_json() or {}

    conn.execute(
        """
        UPDATE cotations
        SET description=?, fournisseur_actuel=?,
            date_echeance=?, date_negociation_date=?,
            date_negociation_time=?
        WHERE id=?
        """,
        (
            data.get("description"),
            data.get("fournisseur_actuel"),
            data.get("date_echeance"),
            data.get("date_negociation_date"),
            data.get("date_negociation_time"),
            cotation_id,
        ),
    )
    conn.commit()
    conn.close()

    return jsonify({"success": True})


@app.route("/cotations/<int:cotation_id>/delete", methods=["POST"])
@login_required
def delete_cotation(cotation_id):
    conn = get_db()
    cot = conn.execute(
        "SELECT * FROM cotations WHERE id=?", (cotation_id,)
    ).fetchone()

    if not cot:
        conn.close()
        return jsonify({"success": False}), 404

    user = session["user"]
    if user["role"] != "admin" and cot["created_by"] != user["id"]:
        conn.close()
        return jsonify({"success": False}), 403

    conn.execute("DELETE FROM cotations WHERE id=?", (cotation_id,))
    conn.commit()
    conn.close()

    return jsonify({"success": True})


@app.route("/admin/cotations/unread_count")
@admin_required
def cotations_unread_count():
    conn = get_db()
    count = conn.execute(
        "SELECT COUNT(*) FROM cotations WHERE COALESCE(is_read,0)=0"
    ).fetchone()[0]
    conn.close()
    return jsonify({"count": count})
############################################################
# 14. AGENDA / FULLCALENDAR
############################################################

@app.route("/agenda")
@login_required
def agenda():
    return render_template("calendar.html")


@app.route("/appointments/events_json")
@login_required
def appointments_events_json():
    conn = get_db()
    rows = conn.execute(
        """
        SELECT a.id, a.title, a.date, a.time, a.color,
               a.client_id, c.name AS client_name
        FROM appointments a
        LEFT JOIN crm_clients c ON c.id = a.client_id
        """
    ).fetchall()
    conn.close()

    events = []
    for r in rows:
        title = r["title"]
        if r["client_name"]:
            title += f" — {r['client_name']}"

        time_part = (r["time"] or "09:00").strip()
        start = f"{r['date']}T{time_part}:00"

        events.append(
            {
                "id": r["id"],
                "title": title,
                "start": start,
                "backgroundColor": r["color"] or "#2563eb",
                "borderColor": r["color"] or "#2563eb",
            }
        )

    return jsonify(events)


@app.route("/appointments/update_from_calendar", methods=["POST"])
@login_required
def appointments_update_from_calendar():
    data = request.get_json() or {}
    appt_id = data.get("id")
    new_date = data.get("date")
    new_time = data.get("time")

    if not appt_id or not new_date:
        return jsonify({"status": "error", "message": "id/date manquants"}), 400

    new_time = (new_time or "").strip() or None

    conn = get_db()
    conn.execute(
        "UPDATE appointments SET date=?, time=? WHERE id=?",
        (new_date, new_time, appt_id),
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "ok"})


@app.route("/appointments/create", methods=["POST"])
@login_required
def appointments_create():
    data = request.get_json() or {}
    title = (data.get("title") or "").strip()
    date_str = (data.get("date") or "").strip()
    time_str = (data.get("time") or "").strip() or None
    description = (data.get("description") or "").strip()
    color = (data.get("color") or "").strip() or "#2563eb"
    client_id = data.get("client_id")

    if client_id in ("", None):
        client_id = None

    if not title or not date_str:
        return jsonify({"success": False, "message": "Titre et date obligatoires."}), 400

    conn = get_db()
    cur = conn.execute(
        """
        INSERT INTO appointments (title, date, time, client_id, description, color)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (title, date_str, time_str, client_id, description, color),
    )
    conn.commit()
    new_id = cur.lastrowid
    conn.close()

    return jsonify({"success": True, "id": new_id})


@app.route("/appointments/<int:appt_id>", methods=["GET"])
@login_required
def appointments_get(appt_id):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM appointments WHERE id=?",
        (appt_id,),
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"success": False, "message": "RDV introuvable"}), 404
    return jsonify({"success": True, "appointment": dict(row)})


@app.route("/appointments/<int:appt_id>/update", methods=["POST"])
@login_required
def appointments_update(appt_id):
    data = request.get_json() or {}

    title = (data.get("title") or "").strip()
    date_str = (data.get("date") or "").strip()
    time_str = (data.get("time") or "").strip() or None
    description = (data.get("description") or "").strip()
    color = (data.get("color") or "").strip() or "#2563eb"
    client_id = data.get("client_id")

    if client_id in ("", None):
        client_id = None

    if not title or not date_str:
        return jsonify({"success": False, "message": "Titre et date obligatoires."}), 400

    conn = get_db()
    exists = conn.execute(
        "SELECT id FROM appointments WHERE id=?",
        (appt_id,),
    ).fetchone()
    if not exists:
        conn.close()
        return jsonify({"success": False, "message": "RDV introuvable"}), 404

    conn.execute(
        """
        UPDATE appointments
        SET title=?, date=?, time=?, client_id=?, description=?, color=?
        WHERE id=?
        """,
        (title, date_str, time_str, client_id, description, color, appt_id),
    )
    conn.commit()
    conn.close()

    return jsonify({"success": True})


@app.route("/appointments/<int:appt_id>/delete", methods=["POST"])
@login_required
def appointments_delete(appt_id):
    conn = get_db()
    conn.execute("DELETE FROM appointments WHERE id=?", (appt_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


############################################################
# 15. CHAT (BACKEND)
############################################################

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
    conn.close()

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
                    f"https://{AWS_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{r['file_key']}"
                    if (r["file_key"] and (not LOCAL_MODE) and s3)
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

    file_key = None
    file_name = None

    if file_obj and allowed_file(file_obj.filename):
        file_name = secure_filename(file_obj.filename)
        file_name_clean = clean_filename(file_name)

        if (not LOCAL_MODE) and s3:
            key = f"chat/{file_name_clean}"
            try:
                s3.upload_fileobj(file_obj, AWS_BUCKET, key)
                file_key = key
            except Exception:
                file_key = None
                file_name = None

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
    new_id = cur.lastrowid
    conn.close()

    return jsonify({"success": True, "id": new_id})


############################################################
# 16. ROOT
############################################################

@app.route("/")
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))


############################################################
# 17. RUN (LOCAL)
############################################################

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
