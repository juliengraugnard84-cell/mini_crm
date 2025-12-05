import os
from pathlib import Path
from datetime import datetime, date, time
from functools import wraps
from collections import defaultdict

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from dotenv import load_dotenv

import cloudinary
import cloudinary.uploader


# -----------------------------------------------------
#                 CHARGEMENT .env
# -----------------------------------------------------

load_dotenv()


# -----------------------------------------------------
#                 CONFIG FLASK / SQLALCHEMY
# -----------------------------------------------------

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev_secret_change_me")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DATA_DIR / 'crm.db'}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Dossier local (peu utilisé désormais)
UPLOAD_FOLDER = DATA_DIR / "uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)


# -----------------------------------------------------
#                 EXTENSIONS AUTORISÉES
# -----------------------------------------------------

ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "png", "jpg", "jpeg", "gif", "webp"}
IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


def allowed_file(filename: str) -> bool:
    """Vérifie l’extension."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def is_image(filename: str) -> bool:
    """Détecte si c'est une image."""
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in IMAGE_EXTENSIONS


# -----------------------------------------------------
#                 CONFIG CLOUDINARY
# -----------------------------------------------------

cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key=os.environ.get("CLOUDINARY_API_KEY"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET"),
)


# -----------------------------------------------------
#                 LOGIN REQUIRED
# -----------------------------------------------------

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Section réservée à l'administrateur.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapper
from flask_sqlalchemy import SQLAlchemy
import hashlib  # pour le filtre hash des commerciaux


# -----------------------------------------------------
#                 BASE DE DONNÉES
# -----------------------------------------------------

db = SQLAlchemy(app)

CLIENT_STATUS = [
    "en cours",
    "accepté",
    "refusé",
    "en attente",
]


# -----------------------------------------------------
#                FILTRES JINJA
# -----------------------------------------------------

@app.template_filter("hash")
def jinja_hash(value):
    """
    Hash stable utilisé pour générer des couleurs uniques
    pour les commerciaux (et autres étiquettes).
    """
    if value is None:
        return 0
    h = hashlib.md5(str(value).encode("utf-8")).hexdigest()
    return int(h[:8], 16)


# -----------------------------------------------------
#                       MODELS
# -----------------------------------------------------


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(60), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="commercial")  # "admin" ou "commercial"

    messages = db.relationship("Message", backref="user", lazy=True)
    documents = db.relationship("Document", backref="user", lazy=True)

    def set_password(self, pwd: str) -> None:
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd: str) -> bool:
        return check_password_hash(self.password_hash, pwd)


class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(50))
    address = db.Column(db.String(255))
    commercial = db.Column(db.String(120))
    status = db.Column(db.String(50), default="en cours")
    notes = db.Column(db.Text)

    documents = db.relationship("Document", backref="client", lazy=True)
    appointments = db.relationship("Appointment", backref="client", lazy=True)


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(255), nullable=False)

    # Stockage Cloudinary
    cloudinary_public_id = db.Column(db.String(255), nullable=False)
    cloudinary_url = db.Column(db.String(500), nullable=False)

    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    client_id = db.Column(db.Integer, db.ForeignKey("client.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    # Dossier logique (ex: crm_julien/clients/<id>/images)
    folder = db.Column(db.String(255))


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)

    client_id = db.Column(db.Integer, db.ForeignKey("client.id"), nullable=True)
    client_name = db.Column(db.String(200), nullable=True)

    date = db.Column(db.Date, default=date.today)
    time = db.Column(
        db.Time,
        default=lambda: datetime.now().time().replace(second=0, microsecond=0),
    )

    notes = db.Column(db.Text)


class Revenue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    montant = db.Column(db.Float, nullable=False)
    date = db.Column(db.Date, default=date.today)
    commercial = db.Column(db.String(120), nullable=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    # Fichiers stockés dans Cloudinary
    file_public_id = db.Column(db.String(255))
    file_url = db.Column(db.String(500))
    file_name = db.Column(db.String(255))
# -----------------------------------------------------
#               AUTHENTIFICATION
# -----------------------------------------------------


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            flash("Identifiants invalides", "danger")
            return redirect(url_for("login"))

        session["user_id"] = user.id
        session["username"] = user.username
        session["role"] = user.role

        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


# -----------------------------------------------------
#                   DASHBOARD
# -----------------------------------------------------


@app.route("/dashboard")
@login_required
def dashboard():
    clients_total = Client.query.count()
    documents_partages = Document.query.count()

    opportunites_ouvertes = (
        Client.query.filter(Client.status.in_(["en cours", "en attente"])).count()
    )

    today = date.today()
    week_start = today
    week_end = today

    rdv_cette_semaine = (
        Appointment.query.filter(Appointment.date.between(week_start, week_end)).count()
    )

    stats = {
        "clients_total": clients_total,
        "documents_partages": documents_partages,
        "opportunites_ouvertes": opportunites_ouvertes,
        "rdv_cette_semaine": rdv_cette_semaine,
    }

    upcoming_appointments = (
        Appointment.query.filter(Appointment.date >= date.today())
        .order_by(Appointment.date.asc(), Appointment.time.asc())
        .limit(5)
        .all()
    )

    latest_docs = (
        Document.query.order_by(Document.uploaded_at.desc()).limit(5).all()
    )

    return render_template(
        "dashboard.html",
        stats=stats,
        upcoming_appointments=upcoming_appointments,
        latest_docs=latest_docs,
    )


# -----------------------------------------------------
#                   CLIENTS
# -----------------------------------------------------


@app.route("/clients")
@login_required
def clients():
    q = (request.args.get("q") or "").strip()
    query = Client.query
    if q:
        like = f"%{q}%"
        query = query.filter(
            db.or_(
                Client.name.ilike(like),
                Client.email.ilike(like),
                Client.phone.ilike(like),
                Client.commercial.ilike(like),
            )
        )
    all_clients = query.order_by(Client.name.asc()).all()
    return render_template("clients.html", clients=all_clients, q=q)


@app.route("/clients/new", methods=["GET", "POST"])
@login_required
def new_client():
    if request.method == "POST":
        c = Client(
            name=request.form.get("name"),
            email=request.form.get("email"),
            phone=request.form.get("phone"),
            address=request.form.get("address"),
            commercial=request.form.get("commercial"),
            status=request.form.get("status") or "en cours",
            notes=request.form.get("notes"),
        )
        db.session.add(c)
        db.session.commit()
        flash("Client créé.", "success")
        return redirect(url_for("clients"))

    return render_template(
        "client_form.html",
        action="new",
        client=None,
        statuses=CLIENT_STATUS,
    )


@app.route("/clients/<int:client_id>/edit", methods=["GET", "POST"])
@login_required
def edit_client(client_id):
    client = Client.query.get_or_404(client_id)

    if request.method == "POST":
        client.name = request.form.get("name")
        client.email = request.form.get("email")
        client.phone = request.form.get("phone")
        client.address = request.form.get("address")
        client.commercial = request.form.get("commercial")
        client.status = request.form.get("status") or client.status
        client.notes = request.form.get("notes")
        db.session.commit()
        flash("Client mis à jour.", "success")
        return redirect(url_for("clients"))

    return render_template(
        "client_form.html",
        action="edit",
        client=client,
        statuses=CLIENT_STATUS,
    )


@app.route("/clients/<int:client_id>/delete", methods=["POST"])
@login_required
def delete_client(client_id):
    client = Client.query.get_or_404(client_id)
    db.session.delete(client)
    db.session.commit()
    flash("Client supprimé.", "success")
    return redirect(url_for("clients"))


@app.route("/clients/<int:client_id>")
@login_required
def client_detail(client_id):
    client = Client.query.get_or_404(client_id)
    documents = (
        Document.query.filter_by(client_id=client.id)
        .order_by(Document.uploaded_at.desc())
        .all()
    )
    appointments = (
        Appointment.query.filter_by(client_id=client.id)
        .order_by(Appointment.date.desc(), Appointment.time.desc())
        .all()
    )
    return render_template(
        "client_detail.html",
        client=client,
        documents=documents,
        appointments=appointments,
    )


# -----------------------------------------------------
#                   DOCUMENTS (CLOUDINARY)
# -----------------------------------------------------


@app.route("/documents")
@login_required
def documents():
    docs = (
        Document.query.outerjoin(Client, Client.id == Document.client_id)
        .outerjoin(User, User.id == Document.user_id)
        .order_by(Document.uploaded_at.desc())
        .all()
    )

    folders = {}
    for d in docs:
        folder_name = d.client.name if d.client else "Sans client"
        folders.setdefault(folder_name, []).append(d)

    return render_template("documents.html", folders=folders)


@app.route("/documents/upload", methods=["POST"])
@login_required
def upload_document():
    client_id = request.form.get("client_id", type=int)
    client = Client.query.get_or_404(client_id)

    files = request.files.getlist("files")
    if not files:
        flash("Aucun fichier reçu.", "warning")
        return redirect(url_for("client_detail", client_id=client.id))

    for file in files:
        if not file or file.filename == "":
            continue
        if not allowed_file(file.filename):
            flash(f"Extension non autorisée pour {file.filename}", "danger")
            continue

        filename = secure_filename(file.filename)
        # Déterminer si c'est une image ou un document "classique"
        if is_image(filename):
            folder = f"crm_julien/clients/{client.id}/images"
            resource_type = "image"
        else:
            folder = f"crm_julien/clients/{client.id}/documents"
            resource_type = "raw"

        uploaded = cloudinary.uploader.upload(
            file,
            resource_type=resource_type,
            folder=folder,
            overwrite=True,
        )

        public_id = uploaded.get("public_id")
        url = uploaded.get("secure_url")

        doc = Document(
            original_name=filename,
            cloudinary_public_id=public_id,
            cloudinary_url=url,
            client_id=client.id,
            user_id=session.get("user_id"),
            folder=folder,
        )
        db.session.add(doc)

    db.session.commit()
    flash("Document(s) ajouté(s) dans le cloud.", "success")
    return redirect(url_for("client_detail", client_id=client.id))


@app.route("/documents/<int:doc_id>/download")
@login_required
def download_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    # Fichiers servis directement par Cloudinary (CDN)
    return redirect(doc.cloudinary_url)


@app.route("/documents/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete_document(doc_id):
    doc = Document.query.get_or_404(doc_id)

    if doc.cloudinary_public_id:
        # Déterminer le type de ressource (image ou raw) à partir de l’extension
        ext = (doc.original_name.rsplit(".", 1)[-1] or "").lower()
        if ext in IMAGE_EXTENSIONS:
            resource_type = "image"
        else:
            resource_type = "raw"

        try:
            cloudinary.uploader.destroy(doc.cloudinary_public_id, resource_type=resource_type)
        except Exception:
            # On ne bloque pas si Cloudinary plante
            pass

    db.session.delete(doc)
    db.session.commit()
    flash("Document supprimé.", "success")
    return redirect(request.referrer or url_for("documents"))
# -----------------------------------------------------
#               RENDEZ-VOUS / CALENDRIER
# -----------------------------------------------------


@app.route("/appointments")
@login_required
def list_appointments():
    date_str = request.args.get("date")
    query = Appointment.query

    if date_str:
        try:
            y, m, d = map(int, date_str.split("-"))
            d_obj = date(y, m, d)
            query = query.filter(Appointment.date == d_obj)
        except ValueError:
            pass

    appointments = query.order_by(Appointment.date.asc(), Appointment.time.asc()).all()
    return render_template("appointments.html", appointments=appointments)


@app.route("/appointments/new", methods=["GET", "POST"])
@login_required
def new_appointment():
    client_id = request.args.get("client_id", type=int)
    client = Client.query.get(client_id) if client_id else None

    if request.method == "POST":
        title = request.form.get("title")
        date_str = request.form.get("date")
        time_str = request.form.get("time")
        notes = request.form.get("notes")

        client_id_form = request.form.get("client_id", type=int)
        client_name = request.form.get("client_name") or None

        d_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
        t_obj = datetime.strptime(time_str, "%H:%M").time()

        rdv = Appointment(
            title=title,
            date=d_obj,
            time=t_obj,
            notes=notes,
            client_id=client_id_form,
            client_name=client_name,
        )
        db.session.add(rdv)
        db.session.commit()
        flash("Rendez-vous ajouté.", "success")
        return redirect(url_for("list_appointments"))

    rdv = None
    if request.args.get("date"):
        try:
            d_obj = datetime.strptime(request.args["date"], "%Y-%m-%d").date()
            rdv = Appointment(date=d_obj, time=datetime.now().time())
        except ValueError:
            pass

    return render_template(
        "appointment_form.html", action="new", rdv=rdv, client=client
    )


@app.route("/appointments/<int:appointment_id>/edit", methods=["GET", "POST"])
@login_required
def edit_appointment(appointment_id):
    rdv = Appointment.query.get_or_404(appointment_id)
    client = rdv.client

    if request.method == "POST":
        rdv.title = request.form.get("title")
        date_str = request.form.get("date")
        time_str = request.form.get("time")
        rdv.notes = request.form.get("notes")

        if date_str:
            rdv.date = datetime.strptime(date_str, "%Y-%m-%d").date()
        if time_str:
            rdv.time = datetime.strptime(time_str, "%H:%M").time()

        if client:
            rdv.client_id = client.id
        else:
            rdv.client_name = request.form.get("client_name")

        db.session.commit()
        flash("Rendez-vous mis à jour.", "success")
        return redirect(url_for("list_appointments"))

    return render_template(
        "appointment_form.html", action="edit", rdv=rdv, client=client
    )


@app.route("/appointments/<int:appointment_id>/delete", methods=["POST"])
@login_required
def delete_appointment(appointment_id):
    rdv = Appointment.query.get_or_404(appointment_id)
    db.session.delete(rdv)
    db.session.commit()
    flash("Rendez-vous supprimé.", "success")
    return redirect(url_for("list_appointments"))


# -------- Agenda FullCalendar --------

@app.route("/calendar")
@login_required
def calendar_view():
    return render_template("calendar.html")


def _serialize_appointment(rdv: Appointment) -> dict:
    dt_start = datetime.combine(rdv.date, rdv.time or time(9, 0))
    title = rdv.title

    if rdv.client and rdv.client.name:
        title = f"{title} - {rdv.client.name}"
    elif rdv.client_name:
        title = f"{title} - {rdv.client_name}"

    return {
        "id": rdv.id,
        "title": title,
        "start": dt_start.isoformat(),
    }


@app.route("/api/appointments", methods=["GET", "POST"])
@login_required
def api_appointments():
    if request.method == "GET":
        events = [_serialize_appointment(rdv) for rdv in Appointment.query.all()]
        return jsonify(events)

    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    date_str = data.get("date")
    time_str = data.get("time") or "09:00"
    client_name = (data.get("client_name") or "").strip() or None

    if not title or not date_str:
        return jsonify({"success": False, "error": "missing_fields"}), 400

    try:
        d_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
        t_obj = datetime.strptime(time_str, "%H:%M").time()
    except ValueError:
        return jsonify({"success": False, "error": "bad_date"}), 400

    rdv = Appointment(
        title=title,
        date=d_obj,
        time=t_obj,
        client_name=client_name,
    )
    db.session.add(rdv)
    db.session.commit()

    return jsonify({"success": True, "event": _serialize_appointment(rdv)})
# -----------------------------------------------------
#               CHIFFRE D'AFFAIRES
# -----------------------------------------------------

def _compute_ca_stats(revenus):
    monthly_totals = defaultdict(float)
    yearly_totals = defaultdict(float)
    per_commercial = defaultdict(float)

    for r in revenus:
        montant = float(r.montant or 0)
        if r.date:
            month_key = r.date.strftime("%Y-%m")
            year_key = str(r.date.year)

            monthly_totals[month_key] += montant
            yearly_totals[year_key] += montant

        per_commercial[r.commercial] += montant

    ca_global = sum(float(r.montant or 0) for r in revenus)

    return {
        "ca_global": round(ca_global, 2),
        "monthly_totals": {k: round(v, 2) for k, v in monthly_totals.items()},
        "yearly_totals": {k: round(v, 2) for k, v in yearly_totals.items()},
        "per_commercial": {k: round(v, 2) for k, v in per_commercial.items()},
    }


@app.route("/chiffre_affaire", methods=["GET", "POST"])
@login_required
def chiffre_affaire():
    if request.method == "POST":
        if session.get("role") != "admin":
            flash("Seul l'administrateur peut ajouter du chiffre d'affaires.", "danger")
            return redirect(url_for("chiffre_affaire"))

        montant = request.form.get("montant", type=float)
        date_str = request.form.get("date")
        commercial = request.form.get("commercial")

        if not montant or not date_str or not commercial:
            flash("Tous les champs sont obligatoires.", "danger")
            return redirect(url_for("chiffre_affaire"))

        try:
            d_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            flash("Date invalide.", "danger")
            return redirect(url_for("chiffre_affaire"))

        r = Revenue(montant=montant, date=d_obj, commercial=commercial)
        db.session.add(r)
        db.session.commit()
        flash("Entrée ajoutée.", "success")
        return redirect(url_for("chiffre_affaire"))

    revenus = Revenue.query.order_by(Revenue.date.desc()).all()
    stats = _compute_ca_stats(revenus)
    today_str = date.today().strftime("%Y-%m-%d")

    return render_template(
        "chiffre_affaire.html",
        revenus=revenus,
        ca_global=stats["ca_global"],
        ca_par_com=stats["per_commercial"],
        monthly_totals=stats["monthly_totals"],
        yearly_totals=stats["yearly_totals"],
        today=today_str,
    )


@app.route("/chiffre_affaire/data")
@login_required
def chiffre_affaire_data():
    revenus = Revenue.query.order_by(Revenue.date.asc()).all()
    stats = _compute_ca_stats(revenus)

    labels = sorted(stats["monthly_totals"].keys())
    data = [stats["monthly_totals"][k] for k in labels]

    return jsonify({
        "labels": labels,
        "data": data,
        "ca_global": stats["ca_global"],
        "yearly_totals": stats["yearly_totals"],
        "per_commercial": stats["per_commercial"],
    })


@app.route("/chiffre_affaire/<int:rev_id>/delete", methods=["POST"])
@login_required
def delete_revenue(rev_id):
    if session.get("role") != "admin":
        flash("Action réservée à l'administrateur.", "danger")
        return redirect(url_for("chiffre_affaire"))

    r = Revenue.query.get_or_404(rev_id)
    db.session.delete(r)
    db.session.commit()
    flash("Entrée supprimée.", "success")
    return redirect(url_for("chiffre_affaire"))
# -----------------------------------------------------
#               ADMIN : UTILISATEURS
# -----------------------------------------------------

@app.route("/admin/users", methods=["GET", "POST"])
@login_required
@admin_required
def admin_users():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not username or not password:
            flash("Nom d'utilisateur et mot de passe requis.", "danger")
        elif User.query.filter_by(username=username).first():
            flash("Cet utilisateur existe déjà.", "danger")
        else:
            u = User(username=username, role="commercial")
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            flash("Utilisateur créé.", "success")

        return redirect(url_for("admin_users"))

    users = User.query.order_by(User.id.asc()).all()
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == "POST":
        new_username = (request.form.get("username") or "").strip()
        new_password = request.form.get("password") or ""
        role = request.form.get("role") or user.role

        if new_username:
            user.username = new_username
        if new_password:
            user.set_password(new_password)

        user.role = role
        db.session.commit()

        flash("Utilisateur mis à jour.", "success")
        return redirect(url_for("admin_users"))

    return render_template("admin_edit_user.html", user=user)


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.role == "admin":
        flash("Impossible de supprimer l'administrateur principal.", "danger")
        return redirect(url_for("admin_users"))

    db.session.delete(user)
    db.session.commit()

    flash("Utilisateur supprimé.", "success")
    return redirect(url_for("admin_users"))
# -----------------------------------------------------
#                    CHAT WIDGET
# -----------------------------------------------------


@app.route("/chat/messages_json")
@login_required
def chat_messages_json():
    messages = Message.query.order_by(Message.created_at.asc()).limit(200).all()

    res = []
    current_user_id = session.get("user_id")

    for m in messages:
        res.append({
            "id": m.id,
            "username": m.user.username if m.user else "Inconnu",
            "content": m.content or "",
            "time": m.created_at.strftime("%d/%m %H:%M"),
            "me": m.user_id == current_user_id,
            "file_url": m.file_url,
            "file_name": m.file_name,
        })

    return jsonify(res)


@app.route("/chat/send_widget", methods=["POST"])
@login_required
def chat_send_widget():
    data = request.get_json(silent=True) or {}
    content = (data.get("message") or "").strip()

    if not content:
        return jsonify({"success": False, "error": "empty"})

    msg = Message(
        content=content,
        user_id=session.get("user_id"),
    )
    db.session.add(msg)
    db.session.commit()

    return jsonify({"success": True})


@app.route("/chat/upload_file", methods=["POST"])
@login_required
def chat_upload_file():
    file = request.files.get("file")

    if not file or file.filename == "":
        return jsonify({"success": False, "error": "no_file"})

    if not allowed_file(file.filename):
        return jsonify({"success": False, "error": "bad_extension"})

    filename = secure_filename(file.filename)
    ext = filename.rsplit(".", 1)[1].lower()

    # On classe les fichiers chat dans deux dossiers différents
    if ext in IMAGE_EXTENSIONS:
        folder = "crm_julien/chat/images"
        resource_type = "image"
    else:
        folder = "crm_julien/chat/files"
        resource_type = "raw"

    try:
        uploaded = cloudinary.uploader.upload(
            file,
            folder=folder,
            resource_type=resource_type,
            overwrite=True
        )
    except Exception as e:
        print("Erreur Cloudinary:", e)
        return jsonify({"success": False, "error": "upload_failed"})

    public_id = uploaded.get("public_id")
    url = uploaded.get("secure_url")

    msg = Message(
        user_id=session.get("user_id"),
        file_public_id=public_id,
        file_url=url,
        file_name=filename,
    )
    db.session.add(msg)
    db.session.commit()

    return jsonify({"success": True})
# -----------------------------------------------------
#         COMMANDE POUR INIT DB
# -----------------------------------------------------

@app.cli.command("init-db")
def init_db_command():
    """Initialise la base et crée un admin par défaut."""
    db.create_all()

    if not User.query.filter_by(username="admin").first():
        admin_user = User(username="admin", role="admin")
        admin_user.set_password("admin")
        db.session.add(admin_user)
        db.session.commit()
        print("Admin créé : admin / admin")
    else:
        print("Admin déjà existant.")
# -----------------------------------------------------
#                       MAIN
# -----------------------------------------------------

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
