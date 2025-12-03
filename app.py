###############################################
#              MINI CRM COMPLET               #
#         Version adaptée pour Render         #
###############################################

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_file,
    send_from_directory, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import os
from datetime import datetime, date
from io import BytesIO

from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from sqlalchemy import inspect, text

# -----------------------------------------------------
#                     FLASK CONFIG
# -----------------------------------------------------

app = Flask(__name__)

# Clé secrète (utilise SECRET_KEY sur Render)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

# ----------- Dossier DATA (persistant sur Render) -----------
BASE_DIR = os.getcwd()
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

# Base SQLite persistante
DB_PATH = os.path.join(DATA_DIR, "crm.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Dossiers uploads persistants
UPLOAD_FOLDER = os.path.join(DATA_DIR, "uploads")
CHAT_UPLOAD_FOLDER = os.path.join(DATA_DIR, "chat_uploads")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CHAT_UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["CHAT_UPLOAD_FOLDER"] = CHAT_UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {"pdf"}

db = SQLAlchemy(app)

CLIENT_STATUSES = [
    "en cours", "demande de cotation", "rdv fixé",
    "contrat signé", "refusé", "en attente de retour client"
]


# -----------------------------------------------------
#                       HELPERS
# -----------------------------------------------------

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Veuillez vous connecter.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Accès réservé à l’administrateur.", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapper


# -----------------------------------------------------
#                       MODELS
# -----------------------------------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="commercial")
    color = db.Column(db.String(20), default="#2196F3")

    clients = db.relationship("Client", backref="user", lazy=True)
    appointments = db.relationship("Appointment", backref="user", lazy=True)
    documents = db.relationship("Document", backref="user", lazy=True)
    messages = db.relationship("Message", backref="user", lazy=True)

    def set_password(self, pwd):
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd):
        return check_password_hash(self.password_hash, pwd)


class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(50))
    address = db.Column(db.String(255))
    notes = db.Column(db.Text)
    commercial = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(50), default="en cours")
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    appointments = db.relationship("Appointment", backref="client", lazy=True)
    documents = db.relationship("Document", backref="client", lazy=True)


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    client_name = db.Column(db.String(120), nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    notes = db.Column(db.Text)
    client_id = db.Column(db.Integer, db.ForeignKey("client.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    client_id = db.Column(db.Integer, db.ForeignKey("client.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class Revenue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    commercial = db.Column(db.String(120), nullable=False)
    montant = db.Column(db.Float, nullable=False)
    date = db.Column(db.Date, default=date.today)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    filename = db.Column(db.String(255))
    original_name = db.Column(db.String(255))


# -----------------------------------------------------
#                           LOGIN
# -----------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            flash("Connexion réussie.", "success")
            return redirect(url_for("dashboard"))

        flash("Identifiants incorrects.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Déconnexion réussie.", "info")
    return redirect(url_for("login"))


# -----------------------------------------------------
#                        DASHBOARD
# -----------------------------------------------------

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session["user_id"]
    role = session["role"]

    if role == "admin":
        clients_total = Client.query.count()
        docs_total = Document.query.count()
        rdv_total = Appointment.query.count()

        upcoming = Appointment.query.order_by(
            Appointment.date.asc(), Appointment.time.asc()
        ).limit(5).all()

        latest_docs = Document.query.order_by(
            Document.uploaded_at.desc()
        ).limit(5).all()

    else:
        clients_total = Client.query.filter_by(user_id=user_id).count()
        docs_total = Document.query.filter_by(user_id=user_id).count()
        rdv_total = Appointment.query.filter_by(user_id=user_id).count()

        upcoming = Appointment.query.filter_by(user_id=user_id).order_by(
            Appointment.date.asc(), Appointment.time.asc()
        ).limit(5).all()

        latest_docs = Document.query.filter_by(user_id=user_id).order_by(
            Document.uploaded_at.desc()
        ).limit(5).all()

    stats = {
        "clients_total": clients_total,
        "documents_partages": docs_total,
        "opportunites_ouvertes": rdv_total,
        "rdv_cette_semaine": rdv_total,
    }

    return render_template(
        "dashboard.html",
        stats=stats,
        upcoming_appointments=upcoming,
        latest_docs=latest_docs,
        username=session.get("username"),
    )


# -----------------------------------------------------
#                       ADMIN USERS
# -----------------------------------------------------

@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    if request.method == "POST":
        username = request.form.get("username") or ""
        password = request.form.get("password") or ""

        if not username or not password:
            flash("Nom d’utilisateur et mot de passe requis.", "error")
            return redirect(url_for("admin_users"))

        if User.query.filter_by(username=username).first():
            flash("Ce nom existe déjà.", "error")
            return redirect(url_for("admin_users"))

        new_user = User(username=username, role="commercial")
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash("Utilisateur créé.", "success")
        return redirect(url_for("admin_users"))

    users = User.query.order_by(User.id.asc()).all()
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == "POST":
        new_username = (request.form.get("username") or "").strip()
        new_password = request.form.get("password") or ""

        if new_username:
            user.username = new_username

        if new_password.strip():
            user.set_password(new_password)

        db.session.commit()
        flash("Utilisateur modifié.", "success")
        return redirect(url_for("admin_users"))

    return render_template("admin_edit_user.html", user=user)


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.role == "admin":
        flash("Impossible de supprimer l’administrateur.", "error")
        return redirect(url_for("admin_users"))

    admin_user = User.query.filter_by(role="admin").first()

    for c in Client.query.filter_by(user_id=user.id).all():
        c.user_id = admin_user.id

    for r in Appointment.query.filter_by(user_id=user.id).all():
        r.user_id = admin_user.id

    for d in Document.query.filter_by(user_id=user.id).all():
        d.user_id = admin_user.id

    for m in Message.query.filter_by(user_id=user.id).all():
        m.user_id = admin_user.id

    db.session.delete(user)
    db.session.commit()

    flash("Utilisateur supprimé.", "info")
    return redirect(url_for("admin_users"))


# (⚠️ ATTENTION : pour éviter une réponse trop longue, je coupe ici le message)

# ============================================================
#                            CLIENTS
# ============================================================

@app.route("/clients")
@login_required
def clients():
    q = request.args.get("q", "")
    role = session["role"]
    user_id = session["user_id"]

    base = Client.query if role == "admin" else Client.query.filter_by(user_id=user_id)

    if q:
        like = f"%{q}%"
        base = base.filter(
            (Client.name.ilike(like))
            | (Client.email.ilike(like))
            | (Client.phone.ilike(like))
            | (Client.commercial.ilike(like))
            | (Client.status.ilike(like))
        )

    all_clients = base.order_by(Client.name.asc()).all()
    return render_template("clients.html", clients=all_clients, q=q)


@app.route("/clients/new", methods=["GET", "POST"])
@login_required
def new_client():
    if request.method == "POST":
        client = Client(
            name=request.form.get("name"),
            email=request.form.get("email"),
            phone=request.form.get("phone"),
            address=request.form.get("address"),
            notes=request.form.get("notes"),
            commercial=request.form.get("commercial"),
            status=request.form.get("status") or "en cours",
            user_id=session["user_id"],
        )

        db.session.add(client)
        db.session.commit()

        flash("Client ajouté.", "success")
        return redirect(url_for("clients"))

    return render_template(
        "client_form.html",
        client=None,
        action="new",
        statuses=CLIENT_STATUSES,
    )


@app.route("/clients/<int:client_id>")
@login_required
def client_detail(client_id):
    client = Client.query.get_or_404(client_id)

    if session["role"] != "admin" and client.user_id != session["user_id"]:
        flash("Accès refusé.", "error")
        return redirect(url_for("clients"))

    appointments = Appointment.query.filter_by(client_id=client_id).order_by(
        Appointment.date.asc(), Appointment.time.asc()
    ).all()

    documents = Document.query.filter_by(client_id=client_id).order_by(
        Document.uploaded_at.desc()
    ).all()

    return render_template(
        "client_detail.html",
        client=client,
        appointments=appointments,
        documents=documents
    )


@app.route("/clients/<int:client_id>/edit", methods=["GET", "POST"])
@login_required
def edit_client(client_id):
    client = Client.query.get_or_404(client_id)

    if session["role"] != "admin" and client.user_id != session["user_id"]:
        flash("Accès refusé.", "error")
        return redirect(url_for("clients"))

    if request.method == "POST":
        client.name = request.form.get("name")
        client.email = request.form.get("email")
        client.phone = request.form.get("phone")
        client.address = request.form.get("address")
        client.notes = request.form.get("notes")
        client.commercial = request.form.get("commercial")
        client.status = request.form.get("status")

        db.session.commit()

        flash("Client mis à jour.", "success")
        return redirect(url_for("client_detail", client_id=client.id))

    return render_template(
        "client_form.html",
        client=client,
        action="edit",
        statuses=CLIENT_STATUSES,
    )


@app.route("/clients/<int:client_id>/delete", methods=["POST"])
@login_required
def delete_client(client_id):
    client = Client.query.get_or_404(client_id)

    if session["role"] != "admin" and client.user_id != session["user_id"]:
        flash("Accès refusé.", "error")
        return redirect(url_for("clients"))

    for rdv in Appointment.query.filter_by(client_id=client.id).all():
        db.session.delete(rdv)

    for doc in Document.query.filter_by(client_id=client.id).all():
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], doc.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        db.session.delete(doc)

    db.session.delete(client)
    db.session.commit()

    flash("Client supprimé.", "info")
    return redirect(url_for("clients"))
# -----------------------------------------------------
#                EXPORT PDF FICHE CLIENT
# -----------------------------------------------------

@app.route("/clients/<int:client_id>/export_pdf")
@login_required
def export_client_pdf(client_id):
    client = Client.query.get_or_404(client_id)

    if session["role"] != "admin" and client.user_id != session["user_id"]:
        flash("Accès refusé.", "error")
        return redirect(url_for("clients"))

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 50

    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, y, f"Fiche client : {client.name}")
    y -= 40

    p.setFont("Helvetica", 12)
    lignes = [
        f"Commercial : {client.commercial}",
        f"Statut : {client.status}",
        f"Email : {client.email or '-'}",
        f"Téléphone : {client.phone or '-'}",
        f"Adresse : {client.address or '-'}",
        "",
        "Notes :",
        client.notes or "-",
    ]

    for line in lignes:
        p.drawString(50, y, line)
        y -= 20

    p.showPage()
    p.save()

    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"fiche_{client.name}.pdf",
        mimetype="application/pdf",
    )
# ============================================================
#                    RENDEZ-VOUS — LISTE
# ============================================================

@app.route("/appointments")
@login_required
def list_appointments():
    user_id = session["user_id"]
    role = session["role"]
    date_str = request.args.get("date")

    base = Appointment.query if role == "admin" else Appointment.query.filter_by(user_id=user_id)

    if date_str:
        try:
            selected_date = datetime.strptime(date_str, "%Y-%m-%d").date()
            appointments = base.filter_by(date=selected_date).order_by(
                Appointment.time.asc()
            ).all()
        except:
            appointments = base.order_by(Appointment.date.asc(), Appointment.time.asc()).all()
    else:
        appointments = base.order_by(Appointment.date.asc(), Appointment.time.asc()).all()

    return render_template("appointments.html", appointments=appointments)
# ============================================================
#            RENDEZ-VOUS — CALENDRIER FULLCALENDAR
# ============================================================

@app.route("/appointments/calendar")
@login_required
def appointments_calendar():
    return render_template("appointments_calendar.html")


@app.route("/appointments/events_json")
@login_required
def appointments_events_json():
    user_id = session["user_id"]
    role = session["role"]

    events = Appointment.query.all() if role == "admin" else Appointment.query.filter_by(user_id=user_id).all()

    data = []

    colors = [
        "#2196f3", "#f44336", "#4caf50", "#ff9800",
        "#9c27b0", "#009688", "#3f51b5", "#795548"
    ]

    user_colors = {}
    next_color = 0

    for rdv in events:
        com = rdv.user.username

        if com not in user_colors:
            user_colors[com] = colors[next_color % len(colors)]
            next_color += 1

        start_dt = datetime.combine(rdv.date, rdv.time)

        data.append({
            "id": rdv.id,
            "title": rdv.title,
            "start": start_dt.isoformat(),
            "backgroundColor": user_colors[com],
            "borderColor": user_colors[com],
            "extendedProps": {
                "client": rdv.client_name,
                "notes": rdv.notes or "",
                "commercial": com
            }
        })

    return jsonify(data)
# ============================================================
#                  RENDEZ-VOUS — CREATION / EDIT
# ============================================================

@app.route("/appointments/new", methods=["GET", "POST"])
@login_required
def new_appointment():
    client_id = request.args.get("client_id")
    client = Client.query.get(client_id) if client_id else None

    if request.method == "POST":
        date_val = datetime.strptime(request.form.get("date"), "%Y-%m-%d").date()
        time_val = datetime.strptime(request.form.get("time"), "%H:%M").time()

        rdv = Appointment(
            title=request.form.get("title"),
            notes=request.form.get("notes"),
            date=date_val,
            time=time_val,
            client_id=client.id if client else None,
            client_name=client.name if client else request.form.get("client_name"),
            user_id=session["user_id"],
        )

        db.session.add(rdv)
        db.session.commit()

        flash("Rendez-vous ajouté.", "success")

        if client:
            return redirect(url_for("client_detail", client_id=client.id))
        return redirect(url_for("list_appointments"))

    return render_template("appointment_form.html", rdv=None, client=client, action="new")


@app.route("/appointments/<int:appointment_id>/edit", methods=["GET", "POST"])
@login_required
def edit_appointment(appointment_id):
    rdv = Appointment.query.get_or_404(appointment_id)
    client = rdv.client

    if session["role"] != "admin" and rdv.user_id != session["user_id"]:
        flash("Accès refusé.", "error")
        return redirect(url_for("list_appointments"))

    if request.method == "POST":
        rdv.title = request.form.get("title")
        rdv.notes = request.form.get("notes")
        rdv.date = datetime.strptime(request.form.get("date"), "%Y-%m-%d").date()
        rdv.time = datetime.strptime(request.form.get("time"), "%H:%M").time()

        if client:
            rdv.client_name = client.name
        else:
            rdv.client_name = request.form.get("client_name")

        db.session.commit()
        flash("RDV modifié.", "success")

        if client:
            return redirect(url_for("client_detail", client_id=client.id))
        return redirect(url_for("list_appointments"))

    return render_template("appointment_form.html", rdv=rdv, client=client, action="edit")


@app.route("/appointments/<int:appointment_id>/delete", methods=["POST"])
@login_required
def delete_appointment(appointment_id):
    rdv = Appointment.query.get_or_404(appointment_id)

    if session["role"] != "admin" and rdv.user_id != session["user_id"]:
        flash("Accès refusé.", "error")
        return redirect(url_for("list_appointments"))

    client = rdv.client

    db.session.delete(rdv)
    db.session.commit()

    flash("RDV supprimé.", "info")

    if client:
        return redirect(url_for("client_detail", client_id=client.id))
    return redirect(url_for("list_appointments"))
# ============================================================
#                     DOCUMENTS PDF
# ============================================================

@app.route("/documents")
@login_required
def documents():
    role = session["role"]
    user_id = session["user_id"]

    docs = (
        Document.query.order_by(Document.uploaded_at.desc()).all()
        if role == "admin"
        else Document.query.filter_by(user_id=user_id).order_by(Document.uploaded_at.desc()).all()
    )

    folders = {}
    for d in docs:
        folder_name = d.client.name if d.client else "Sans client"
        folders.setdefault(folder_name, []).append(d)

    return render_template("documents.html", folders=folders)
@app.route("/documents/upload", methods=["POST"])
@login_required
def upload_document():
    file = request.files.get("file")
    user_id = session["user_id"]

    client_id = request.form.get("client_id")
    client = Client.query.get(client_id)

    if not client:
        flash("Upload impossible : client manquant.", "error")
        return redirect(url_for("documents"))

    if not file or file.filename == "":
        flash("Aucun fichier envoyé.", "error")
        return redirect(url_for("client_detail", client_id=client.id))

    if not allowed_file(file.filename):
        flash("Seuls les fichiers PDF sont autorisés.", "error")
        return redirect(url_for("client_detail", client_id=client.id))

    safe_name = f"{int(datetime.utcnow().timestamp())}_{file.filename.replace(' ', '_')}"
    file.save(os.path.join(app.config["UPLOAD_FOLDER"], safe_name))

    doc = Document(
        filename=safe_name,
        original_name=file.filename,
        client_id=client.id,
        user_id=user_id,
    )

    db.session.add(doc)
    db.session.commit()

    flash("Document importé.", "success")
    return redirect(url_for("client_detail", client_id=client.id))
@app.route("/documents/<int:doc_id>/download")
@login_required
def download_document(doc_id):
    doc = Document.query.get_or_404(doc_id)

    if session["role"] != "admin" and doc.user_id != session["user_id"]:
        flash("Accès interdit.", "error")
        return redirect(url_for("documents"))

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        doc.filename,
        as_attachment=True,
        download_name=doc.original_name,
    )


@app.route("/documents/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete_document(doc_id):
    doc = Document.query.get_or_404(doc_id)

    if session["role"] != "admin" and doc.user_id != session["user_id"]:
        flash("Accès interdit.", "error")
        return redirect(url_for("documents"))

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], doc.filename)
    if os.path.exists(file_path):
        os.remove(file_path)

    db.session.delete(doc)
    db.session.commit()

    flash("Document supprimé.", "info")
    return redirect(url_for("documents"))
# ============================================================
#                     CHIFFRE D’AFFAIRES
# ============================================================

@app.route("/chiffre_affaire", methods=["GET", "POST"])
@login_required
def chiffre_affaire():
    role = session["role"]
    username = session["username"]

    if request.method == "POST" and role != "admin":
        flash("Vous n'avez pas l’autorisation d’ajouter des entrées.", "error")
        return redirect(url_for("chiffre_affaire"))

    if request.method == "POST":
        try:
            montant = float(request.form.get("montant"))
            date_val = datetime.strptime(request.form.get("date"), "%Y-%m-%d").date()
            commercial = request.form.get("commercial") or "Inconnu"
        except:
            flash("Valeurs invalides.", "error")
            return redirect(url_for("chiffre_affaire"))

        entry = Revenue(commercial=commercial, montant=montant, date=date_val)
        db.session.add(entry)
        db.session.commit()

        flash("Entrée ajoutée.", "success")
        return redirect(url_for("chiffre_affaire"))

    if role == "admin":
        revenus = Revenue.query.order_by(Revenue.date.desc()).all()
    else:
        revenus = Revenue.query.filter_by(commercial=username).order_by(
            Revenue.date.desc()
        ).all()

    ca_global = sum(r.montant for r in revenus)

    ca_par_com = {}
    if role == "admin":
        for r in Revenue.query.all():
            ca_par_com[r.commercial] = ca_par_com.get(r.commercial, 0) + r.montant

    return render_template(
        "chiffre_affaire.html",
        revenus=revenus,
        ca_global=ca_global,
        ca_par_com=ca_par_com,
        today=date.today().strftime("%Y-%m-%d"),
    )
# ============================================================
#                        CHAT WIDGET
# ============================================================

@app.route("/chat/messages_json")
@login_required
def chat_messages_json():
    msgs = Message.query.order_by(Message.timestamp.asc()).all()
    user_id = session["user_id"]

    data = []
    for m in msgs:
        data.append({
            "id": m.id,
            "username": m.user.username,
            "content": m.content,
            "time": m.timestamp.strftime("%H:%M"),
            "me": (m.user_id == user_id),
        })

    return jsonify(data)


@app.route("/chat/send_widget", methods=["POST"])
@login_required
def chat_send_widget():
    data = request.get_json() or {}
    content = (data.get("message") or "").strip()

    if not content:
        return jsonify({"error": "empty"}), 400

    msg = Message(
        user_id=session["user_id"],
        content=content
    )

    db.session.add(msg)
    db.session.commit()

    return jsonify({"success": True})
# ============================================================
#                 INITIALISATION BDD + AUTO ADMIN
# ============================================================

with app.app_context():
    db.create_all()

    inspector = inspect(db.engine)

    # Colonnes manquantes en cas de mise à jour
    cols_client = [c["name"] for c in inspector.get_columns("client")]
    if "status" not in cols_client:
        with db.engine.begin() as conn:
            conn.execute(text(
                "ALTER TABLE client ADD COLUMN status VARCHAR(50) DEFAULT 'en cours'"
            ))

    cols_msg = [c["name"] for c in inspector.get_columns("message")]
    if "filename" not in cols_msg:
        with db.engine.begin() as conn:
            conn.execute(text("ALTER TABLE message ADD COLUMN filename VARCHAR(255)"))
    if "original_name" not in cols_msg:
        with db.engine.begin() as conn:
            conn.execute(text("ALTER TABLE message ADD COLUMN original_name VARCHAR(255)"))

    cols_user = [c["name"] for c in inspector.get_columns("user")]
    if "color" not in cols_user:
        with db.engine.begin() as conn:
            conn.execute(text("ALTER TABLE user ADD COLUMN color VARCHAR(20) DEFAULT '#2196F3'"))

    # Création admin auto si aucun admin
    if not User.query.filter_by(role="admin").first():
        admin = User(username="admin", role="admin")
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()
        print(">>> ADMIN CRÉÉ : admin / admin123")
# ============================================================
#                        LANCEMENT SERVER
# ============================================================

# Ne rien mettre ici : Render utilise Gunicorn
# Commande de lancement :
# gunicorn app:app --timeout 120
