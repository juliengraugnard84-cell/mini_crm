from __future__ import annotations

import os
import re
import sqlite3
import subprocess
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = BASE_DIR / "uploads"
DB_PATH = DATA_DIR / "logiciel_appels.sqlite3"
ENV_PATH = BASE_DIR / ".env"

ALLOWED_EXTENSIONS = {
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "csv",
    "txt",
    "png",
    "jpg",
    "jpeg",
    "mp3",
    "wav",
}

CALL_STATUSES = {
    "in_progress": "En cours",
    "completed": "Termine",
    "missed": "Manque",
    "no_answer": "Sans reponse",
}

CALL_DIRECTIONS = {
    "outgoing": "Sortant",
    "incoming": "Entrant",
}

CALL_PROVIDERS = {
    "manual": "Manuel",
    "freepbx": "FreePBX",
    "microsip": "MicroSIP",
}

FINAL_CALL_STATUSES = {"completed", "missed", "no_answer"}

FREEPBX_REQUIRED_ENV_VARS = (
    "FREEPBX_WSS_URL",
    "FREEPBX_SIP_DOMAIN",
)


def load_env_file(path: Path) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


load_env_file(ENV_PATH)

app = Flask(__name__)
app.config["SECRET_KEY"] = "logiciel-appels-local-dev"
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024


def ensure_storage() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        ensure_storage()
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exception) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def ensure_column(conn: sqlite3.Connection, table: str, column_sql: str) -> None:
    column_name = column_sql.split()[0].strip()
    columns = {
        row[1]
        for row in conn.execute(f"PRAGMA table_info('{table}')").fetchall()
    }
    if column_name not in columns:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_sql}")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc).lower():
                raise


def init_db() -> None:
    ensure_storage()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                role TEXT,
                email TEXT,
                extension TEXT,
                auth_user TEXT,
                outbound_prefix TEXT,
                notes TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                company TEXT,
                phone TEXT NOT NULL,
                email TEXT,
                notes TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_id INTEGER,
                dialed_number TEXT NOT NULL,
                direction TEXT NOT NULL DEFAULT 'outgoing',
                status TEXT NOT NULL DEFAULT 'in_progress',
                summary TEXT,
                started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                ended_at TEXT,
                duration_seconds INTEGER DEFAULT 0,
                FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_id INTEGER,
                title TEXT NOT NULL,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                mime_type TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE SET NULL
            );

            CREATE INDEX IF NOT EXISTS idx_agents_active_name
            ON agents (is_active, name);

            CREATE INDEX IF NOT EXISTS idx_calls_started_at
            ON calls (started_at DESC);

            CREATE INDEX IF NOT EXISTS idx_documents_contact_id
            ON documents (contact_id, created_at DESC);
            """
        )

        ensure_column(conn, "calls", "provider TEXT DEFAULT 'manual'")
        ensure_column(conn, "calls", "provider_status TEXT")
        ensure_column(conn, "calls", "external_sid TEXT")
        ensure_column(conn, "calls", "updated_at TEXT")
        ensure_column(conn, "calls", "agent_id INTEGER")

        conn.execute(
            """
            UPDATE calls
            SET
                provider = CASE
                    WHEN provider IS NULL OR provider = '' OR provider = 'twilio' THEN 'manual'
                    ELSE provider
                END,
                updated_at = COALESCE(updated_at, started_at, CURRENT_TIMESTAMP)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_calls_provider_status
            ON calls (provider, status, started_at DESC)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_calls_agent_status
            ON calls (agent_id, status, started_at DESC)
            """
        )
        conn.commit()
    finally:
        conn.close()


def utc_now() -> datetime:
    return datetime.utcnow()


def iso_now() -> str:
    return utc_now().isoformat(sep=" ", timespec="seconds")


def parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None


def format_dt(value: str | None) -> str:
    parsed = parse_dt(value)
    if not parsed:
        return "-"
    return parsed.strftime("%d/%m/%Y %H:%M")


def format_duration(seconds: int | None) -> str:
    total = max(int(seconds or 0), 0)
    minutes, sec = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{sec:02d}"
    return f"{minutes:02d}:{sec:02d}"


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def save_uploaded_file(file_storage) -> tuple[str, str]:
    original_name = secure_filename(file_storage.filename or "")
    if not original_name:
        raise ValueError("Nom de fichier invalide.")
    if not allowed_file(original_name):
        raise ValueError("Format non autorise.")

    suffix = Path(original_name).suffix.lower()
    stored_name = f"{uuid4().hex}{suffix}"
    target = UPLOAD_DIR / stored_name
    file_storage.save(target)
    return original_name, stored_name


def mask_value(value: str | None, lead: int = 18, tail: int = 0) -> str:
    if not value:
        return "-"
    if tail <= 0 or len(value) <= lead:
        return value[:lead] if len(value) > lead else value
    if len(value) <= lead + tail:
        return value
    return f"{value[:lead]}...{value[-tail:]}"


def normalize_dial_target(value: str | None) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""

    compact = raw.replace(" ", "")
    if compact.lower().startswith("sip:"):
        cleaned = re.sub(r"[^A-Za-z0-9@+*#_.:-]", "", compact)
    else:
        cleaned = re.sub(r"[^A-Za-z0-9@+*#_.-]", "", compact)

    if len(cleaned) < 2:
        return ""

    return cleaned


def parse_optional_int(value: str | int | None) -> int | None:
    raw = str(value or "").strip()
    return int(raw) if raw.isdigit() else None


def get_freepbx_settings() -> dict:
    wss_url = (os.environ.get("FREEPBX_WSS_URL") or "").strip()
    sip_domain = (os.environ.get("FREEPBX_SIP_DOMAIN") or "").strip()
    display_name = (os.environ.get("FREEPBX_DISPLAY_NAME") or "Equipe CallFlow").strip()
    default_extension = (os.environ.get("FREEPBX_DEFAULT_EXTENSION") or "").strip()
    default_auth_user = (os.environ.get("FREEPBX_DEFAULT_AUTH_USER") or "").strip()
    outbound_prefix = (os.environ.get("FREEPBX_OUTBOUND_PREFIX") or "").strip()
    sdk_import_url = (
        os.environ.get("SIPJS_SDK_IMPORT_URL")
        or "https://cdn.jsdelivr.net/npm/sip.js@0.21.2/+esm"
    ).strip()

    missing = [
        key
        for key in FREEPBX_REQUIRED_ENV_VARS
        if not {
            "FREEPBX_WSS_URL": wss_url,
            "FREEPBX_SIP_DOMAIN": sip_domain,
        }[key]
    ]

    sample_extension = default_extension or "100"
    sample_domain = sip_domain or "pbx.example.com"
    localhost_warning = any(
        host in wss_url.lower()
        for host in ("127.0.0.1", "localhost")
    ) if wss_url else False

    return {
        "enabled": not missing,
        "missing": missing,
        "wss_url": wss_url,
        "sip_domain": sip_domain,
        "display_name": display_name,
        "default_extension": default_extension,
        "default_auth_user": default_auth_user,
        "outbound_prefix": outbound_prefix,
        "sdk_import_url": sdk_import_url,
        "localhost_warning": localhost_warning,
        "sample_aor": f"sip:{sample_extension}@{sample_domain}",
        "sample_ws_path": "/ws",
        "masked_wss_url": mask_value(wss_url, lead=42),
        "masked_domain": sip_domain or "-",
    }


def expand_env_path(raw_path: str | None) -> Path | None:
    value = (raw_path or "").strip()
    if not value:
        return None
    return Path(os.path.expandvars(os.path.expanduser(value)))


def get_microsip_settings() -> dict:
    configured_path = expand_env_path(os.environ.get("MICROSIP_EXECUTABLE"))

    candidates: list[Path] = []
    for root in (
        os.environ.get("LOCALAPPDATA"),
        os.environ.get("USERPROFILE") and os.path.join(os.environ["USERPROFILE"], "AppData", "Local"),
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
    ):
        candidate_root = expand_env_path(root)
        if candidate_root:
            candidates.append(candidate_root / "MicroSIP" / "MicroSIP.exe")

    detected_path: Path | None = None
    source = ""

    if configured_path and configured_path.is_file():
        detected_path = configured_path
        source = "env"
    else:
        for candidate in candidates:
            if candidate.is_file():
                detected_path = candidate
                source = "auto"
                break

    primary_candidate = candidates[0] if candidates else None
    return {
        "enabled": detected_path is not None,
        "configured_path": str(configured_path) if configured_path else "",
        "executable_path": str(detected_path) if detected_path else "",
        "display_path": str(detected_path or configured_path or primary_candidate or ""),
        "source": source,
        "auto_candidate": str(primary_candidate) if primary_candidate else "",
    }


def run_microsip(*arguments: str) -> None:
    settings = get_microsip_settings()
    executable = settings["executable_path"]
    if not executable:
        raise FileNotFoundError("MicroSIP.exe introuvable sur ce PC.")

    command = [executable, *arguments]
    popen_kwargs = {
        "cwd": str(Path(executable).parent),
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = (
            getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        )

    subprocess.Popen(command, **popen_kwargs)


def fetch_agent(agent_id: int) -> sqlite3.Row | None:
    db = get_db()
    return db.execute(
        """
        SELECT *
        FROM agents
        WHERE id = ?
        """,
        (agent_id,),
    ).fetchone()


def fetch_agents(active_only: bool = False) -> list[sqlite3.Row]:
    db = get_db()
    sql = """
        SELECT *
        FROM agents
    """
    if active_only:
        sql += " WHERE is_active = 1"
    sql += """
        ORDER BY
            is_active DESC,
            CASE WHEN TRIM(COALESCE(extension, '')) = '' THEN 1 ELSE 0 END,
            LOWER(name) ASC,
            id DESC
    """
    return db.execute(sql).fetchall()


def fetch_agent_summaries(limit: int | None = None) -> list[sqlite3.Row]:
    db = get_db()
    sql = """
        SELECT
            agents.*,
            COUNT(calls.id) AS total_calls,
            COALESCE(SUM(CASE WHEN calls.status = 'in_progress' THEN 1 ELSE 0 END), 0) AS active_calls,
            COALESCE(SUM(calls.duration_seconds), 0) AS total_duration_seconds,
            MAX(calls.started_at) AS last_call_at
        FROM agents
        LEFT JOIN calls ON calls.agent_id = agents.id
        GROUP BY agents.id
        ORDER BY
            agents.is_active DESC,
            active_calls DESC,
            total_calls DESC,
            LOWER(agents.name) ASC
    """
    if limit:
        sql += f" LIMIT {int(limit)}"
    return db.execute(sql).fetchall()


def serialize_agent_template(agent: sqlite3.Row) -> dict:
    return {
        "id": agent["id"],
        "name": agent["name"],
        "role": agent["role"] or "",
        "email": agent["email"] or "",
        "extension": agent["extension"] or "",
        "auth_user": agent["auth_user"] or "",
        "outbound_prefix": agent["outbound_prefix"] or "",
        "display_name": agent["name"],
        "is_active": bool(agent["is_active"]),
    }


def extension_in_use(extension: str, exclude_agent_id: int | None = None) -> bool:
    cleaned = (extension or "").strip()
    if not cleaned:
        return False

    db = get_db()
    sql = """
        SELECT id
        FROM agents
        WHERE LOWER(TRIM(COALESCE(extension, ''))) = LOWER(TRIM(?))
    """
    params: list = [cleaned]
    if exclude_agent_id is not None:
        sql += " AND id != ?"
        params.append(exclude_agent_id)

    return db.execute(sql, tuple(params)).fetchone() is not None


def fetch_contacts() -> list[sqlite3.Row]:
    db = get_db()
    return db.execute(
        """
        SELECT *
        FROM contacts
        ORDER BY datetime(created_at) DESC, id DESC
        """
    ).fetchall()


def fetch_contact(contact_id: int) -> sqlite3.Row | None:
    db = get_db()
    return db.execute(
        """
        SELECT *
        FROM contacts
        WHERE id = ?
        """,
        (contact_id,),
    ).fetchone()


def fetch_calls(
    limit: int | None = None,
    agent_id: int | None = None,
) -> list[sqlite3.Row]:
    db = get_db()
    sql = """
        SELECT
            calls.*,
            contacts.name AS contact_name,
            contacts.company AS contact_company,
            agents.name AS agent_name,
            agents.extension AS agent_extension
        FROM calls
        LEFT JOIN contacts ON contacts.id = calls.contact_id
        LEFT JOIN agents ON agents.id = calls.agent_id
    """
    params: list = []
    if agent_id is not None:
        sql += " WHERE calls.agent_id = ?"
        params.append(agent_id)
    sql += """
        ORDER BY
            CASE WHEN calls.status = 'in_progress' THEN 0 ELSE 1 END,
            datetime(calls.started_at) DESC,
            calls.id DESC
    """
    if limit:
        sql += f" LIMIT {int(limit)}"
    return db.execute(sql, tuple(params)).fetchall()


def fetch_contact_calls(contact_id: int) -> list[sqlite3.Row]:
    db = get_db()
    return db.execute(
        """
        SELECT
            calls.*,
            agents.name AS agent_name,
            agents.extension AS agent_extension
        FROM calls
        LEFT JOIN agents ON agents.id = calls.agent_id
        WHERE calls.contact_id = ?
        ORDER BY
            CASE WHEN calls.status = 'in_progress' THEN 0 ELSE 1 END,
            datetime(calls.started_at) DESC,
            calls.id DESC
        """,
        (contact_id,),
    ).fetchall()


def fetch_documents(contact_id: int | None = None) -> list[sqlite3.Row]:
    db = get_db()
    if contact_id is None:
        return db.execute(
            """
            SELECT
                documents.*,
                contacts.name AS contact_name
            FROM documents
            LEFT JOIN contacts ON contacts.id = documents.contact_id
            ORDER BY datetime(documents.created_at) DESC, documents.id DESC
            """
        ).fetchall()

    return db.execute(
        """
        SELECT *
        FROM documents
        WHERE contact_id = ?
        ORDER BY datetime(created_at) DESC, id DESC
        """,
        (contact_id,),
    ).fetchall()


def create_call_row(
    *,
    contact_id: int | None,
    agent_id: int | None,
    dialed_number: str,
    direction: str = "outgoing",
    provider: str = "manual",
) -> int:
    db = get_db()
    started_at = iso_now()
    cursor = db.execute(
        """
        INSERT INTO calls (
            contact_id,
            agent_id,
            dialed_number,
            direction,
            status,
            summary,
            started_at,
            duration_seconds,
            provider,
            provider_status,
            updated_at
        )
        VALUES (?, ?, ?, ?, 'in_progress', NULL, ?, 0, ?, ?, ?)
        """,
        (
            contact_id,
            agent_id,
            dialed_number,
            direction,
            started_at,
            provider,
            {
                "freepbx": "initiated",
                "microsip": "launch_requested",
            }.get(provider, "manual"),
            started_at,
        ),
    )
    db.commit()
    return int(cursor.lastrowid)


def update_call_row(call_id: int, **updates) -> None:
    db = get_db()
    fields = []
    values = []

    allowed = {
        "status",
        "summary",
        "ended_at",
        "duration_seconds",
        "provider_status",
        "external_sid",
    }

    for key, value in updates.items():
        if key not in allowed:
            continue
        fields.append(f"{key} = ?")
        values.append(value)

    if not fields:
        return

    fields.append("updated_at = ?")
    values.append(iso_now())
    values.append(call_id)

    db.execute(
        f"UPDATE calls SET {', '.join(fields)} WHERE id = ?",
        tuple(values),
    )
    db.commit()


@app.context_processor
def inject_helpers():
    return {
        "format_dt": format_dt,
        "format_duration": format_duration,
        "call_statuses": CALL_STATUSES,
        "call_directions": CALL_DIRECTIONS,
        "call_providers": CALL_PROVIDERS,
        "freepbx_ready": get_freepbx_settings()["enabled"],
        "microsip_ready": get_microsip_settings()["enabled"],
    }


@app.route("/")
def dashboard():
    init_db()
    db = get_db()
    stats = {
        "contacts": db.execute("SELECT COUNT(*) FROM contacts").fetchone()[0],
        "calls": db.execute("SELECT COUNT(*) FROM calls").fetchone()[0],
        "active_calls": db.execute(
            "SELECT COUNT(*) FROM calls WHERE status = 'in_progress'"
        ).fetchone()[0],
        "documents": db.execute("SELECT COUNT(*) FROM documents").fetchone()[0],
        "agents": db.execute(
            "SELECT COUNT(*) FROM agents WHERE is_active = 1"
        ).fetchone()[0],
    }

    recent_calls = fetch_calls(limit=8)
    recent_documents = fetch_documents()[:6]
    contacts = fetch_contacts()[:8]
    team_agents = fetch_agent_summaries(limit=6)

    return render_template(
        "dashboard.html",
        page_title="Dashboard",
        stats=stats,
        recent_calls=recent_calls,
        recent_documents=recent_documents,
        contacts=contacts,
        team_agents=team_agents,
        freepbx=get_freepbx_settings(),
    )


@app.route("/agents", methods=["GET", "POST"])
def agents():
    init_db()
    db = get_db()

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        role = (request.form.get("role") or "").strip()
        email = (request.form.get("email") or "").strip()
        extension = (request.form.get("extension") or "").strip()
        auth_user = (request.form.get("auth_user") or "").strip()
        outbound_prefix = (request.form.get("outbound_prefix") or "").strip()
        notes = (request.form.get("notes") or "").strip()
        is_active = 1 if request.form.get("is_active") == "on" else 0

        if not name:
            flash("Le nom de l'agent est obligatoire.", "danger")
            return redirect(url_for("agents"))

        if extension_in_use(extension):
            flash("Cette extension est deja utilisee par un autre agent.", "danger")
            return redirect(url_for("agents"))

        db.execute(
            """
            INSERT INTO agents (
                name,
                role,
                email,
                extension,
                auth_user,
                outbound_prefix,
                notes,
                is_active
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                role or None,
                email or None,
                extension or None,
                auth_user or None,
                outbound_prefix or None,
                notes or None,
                is_active,
            ),
        )
        db.commit()
        flash("Agent ajoute a l'equipe.", "success")
        return redirect(url_for("agents"))

    return render_template(
        "agents.html",
        page_title="Equipe",
        agents=fetch_agent_summaries(),
    )


@app.route("/agents/<int:agent_id>/edit", methods=["POST"])
def edit_agent(agent_id: int):
    init_db()
    current = fetch_agent(agent_id)
    if not current:
        flash("Agent introuvable.", "danger")
        return redirect(url_for("agents"))

    name = (request.form.get("name") or "").strip()
    role = (request.form.get("role") or "").strip()
    email = (request.form.get("email") or "").strip()
    extension = (request.form.get("extension") or "").strip()
    auth_user = (request.form.get("auth_user") or "").strip()
    outbound_prefix = (request.form.get("outbound_prefix") or "").strip()
    notes = (request.form.get("notes") or "").strip()
    is_active = 1 if request.form.get("is_active") == "on" else 0

    if not name:
        flash("Le nom de l'agent est obligatoire.", "danger")
        return redirect(url_for("agents"))

    if extension_in_use(extension, exclude_agent_id=agent_id):
        flash("Cette extension est deja utilisee par un autre agent.", "danger")
        return redirect(url_for("agents"))

    db = get_db()
    db.execute(
        """
        UPDATE agents
        SET
            name = ?,
            role = ?,
            email = ?,
            extension = ?,
            auth_user = ?,
            outbound_prefix = ?,
            notes = ?,
            is_active = ?
        WHERE id = ?
        """,
        (
            name,
            role or None,
            email or None,
            extension or None,
            auth_user or None,
            outbound_prefix or None,
            notes or None,
            is_active,
            agent_id,
        ),
    )
    db.commit()
    flash("Agent mis a jour.", "success")
    return redirect(url_for("agents"))


@app.route("/contacts", methods=["GET", "POST"])
def contacts():
    init_db()
    db = get_db()

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        company = (request.form.get("company") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        email = (request.form.get("email") or "").strip()
        notes = (request.form.get("notes") or "").strip()

        if not name or not phone:
            flash("Le nom et le numero sont obligatoires.", "danger")
            return redirect(url_for("contacts"))

        db.execute(
            """
            INSERT INTO contacts (name, company, phone, email, notes)
            VALUES (?, ?, ?, ?, ?)
            """,
            (name, company or None, phone, email or None, notes or None),
        )
        db.commit()
        flash("Contact ajoute.", "success")
        return redirect(url_for("contacts"))

    query = (request.args.get("q") or "").strip()
    if query:
        rows = db.execute(
            """
            SELECT *
            FROM contacts
            WHERE
                name LIKE ?
                OR COALESCE(company, '') LIKE ?
                OR phone LIKE ?
                OR COALESCE(email, '') LIKE ?
            ORDER BY datetime(created_at) DESC, id DESC
            """,
            (f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%"),
        ).fetchall()
    else:
        rows = fetch_contacts()

    return render_template(
        "contacts.html",
        page_title="Contacts",
        contacts=rows,
        query=query,
        microsip=get_microsip_settings(),
    )


@app.route("/contacts/<int:contact_id>")
def contact_detail(contact_id: int):
    init_db()
    contact = fetch_contact(contact_id)
    if not contact:
        flash("Contact introuvable.", "danger")
        return redirect(url_for("contacts"))

    return render_template(
        "contact_detail.html",
        page_title=contact["name"],
        contact=contact,
        calls=fetch_contact_calls(contact_id),
        documents=fetch_documents(contact_id),
        microsip=get_microsip_settings(),
    )


@app.route("/contacts/<int:contact_id>/edit", methods=["POST"])
def edit_contact(contact_id: int):
    init_db()
    contact = fetch_contact(contact_id)
    if not contact:
        flash("Contact introuvable.", "danger")
        return redirect(url_for("contacts"))

    name = (request.form.get("name") or "").strip()
    company = (request.form.get("company") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    email = (request.form.get("email") or "").strip()
    notes = (request.form.get("notes") or "").strip()

    if not name or not phone:
        flash("Le nom et le numero sont obligatoires.", "danger")
        return redirect(url_for("contact_detail", contact_id=contact_id))

    db = get_db()
    db.execute(
        """
        UPDATE contacts
        SET name = ?, company = ?, phone = ?, email = ?, notes = ?
        WHERE id = ?
        """,
        (name, company or None, phone, email or None, notes or None, contact_id),
    )
    db.commit()
    flash("Contact mis a jour.", "success")
    return redirect(url_for("contact_detail", contact_id=contact_id))


@app.route("/calls", methods=["GET", "POST"])
def calls():
    init_db()

    if request.method == "POST":
        contact_id = parse_optional_int(request.form.get("contact_id"))
        agent_id = parse_optional_int(request.form.get("agent_id"))
        dialed_number = normalize_dial_target(request.form.get("dialed_number"))
        direction = (request.form.get("direction") or "outgoing").strip()

        if contact_id and not dialed_number:
            contact = fetch_contact(contact_id)
            if contact:
                dialed_number = normalize_dial_target(contact["phone"])

        if not dialed_number:
            flash("Ajoute un numero ou une extension a appeler.", "danger")
            return redirect(url_for("calls"))

        if direction not in CALL_DIRECTIONS:
            direction = "outgoing"

        if agent_id and not fetch_agent(agent_id):
            agent_id = None

        create_call_row(
            contact_id=contact_id,
            agent_id=agent_id,
            dialed_number=dialed_number,
            direction=direction,
            provider="manual",
        )
        flash("Appel ajoute au journal.", "success")
        return redirect(url_for("calls"))

    selected_agent_id = parse_optional_int(request.args.get("agent"))
    return render_template(
        "calls.html",
        page_title="Appels",
        calls=fetch_calls(agent_id=selected_agent_id),
        contacts=fetch_contacts(),
        agents=fetch_agents(),
        selected_agent_id=selected_agent_id,
    )


@app.route("/calls/<int:call_id>/end", methods=["POST"])
def end_call(call_id: int):
    init_db()
    db = get_db()
    row = db.execute("SELECT * FROM calls WHERE id = ?", (call_id,)).fetchone()
    if not row:
        flash("Appel introuvable.", "danger")
        return redirect(url_for("calls"))

    status = (request.form.get("status") or "completed").strip()
    summary = (request.form.get("summary") or "").strip()

    if status not in CALL_STATUSES or status == "in_progress":
        status = "completed"

    started_at = parse_dt(row["started_at"]) or utc_now()
    ended_at = utc_now()
    duration_seconds = int((ended_at - started_at).total_seconds())

    update_call_row(
        call_id,
        status=status,
        summary=summary or None,
        ended_at=ended_at.isoformat(sep=" ", timespec="seconds"),
        duration_seconds=duration_seconds,
        provider_status="manual_closed",
    )
    flash("Appel cloture.", "success")

    next_url = request.form.get("next")
    if next_url == "contact" and row["contact_id"]:
        return redirect(url_for("contact_detail", contact_id=row["contact_id"]))
    return redirect(url_for("calls"))


@app.route("/dialer")
def dialer():
    init_db()
    team_agents = fetch_agents(active_only=True)
    return render_template(
        "dialer.html",
        page_title="Composeur",
        contacts=fetch_contacts(),
        agents=team_agents,
        team_agents_json=[serialize_agent_template(agent) for agent in team_agents],
        freepbx=get_freepbx_settings(),
        microsip=get_microsip_settings(),
    )


@app.route("/freepbx/setup")
def freepbx_setup():
    init_db()
    team_agents = fetch_agents(active_only=True)
    return render_template(
        "freepbx_setup.html",
        page_title="FreePBX",
        freepbx=get_freepbx_settings(),
        agents=team_agents,
        team_agents_json=[serialize_agent_template(agent) for agent in team_agents],
    )


@app.route("/readiness")
def readiness():
    init_db()
    team_agents = fetch_agents(active_only=True)
    ready_agents = [
        agent
        for agent in team_agents
        if (agent["extension"] or "").strip()
    ]
    return render_template(
        "readiness.html",
        page_title="Tests Poste",
        freepbx=get_freepbx_settings(),
        agents=team_agents,
        team_stats={
            "active_agents": len(team_agents),
            "ready_agents": len(ready_agents),
        },
    )


@app.route("/documents", methods=["GET", "POST"])
def documents():
    init_db()
    db = get_db()

    if request.method == "POST":
        uploaded = request.files.get("file")
        title = (request.form.get("title") or "").strip()
        contact_id = parse_optional_int(request.form.get("contact_id"))

        if not uploaded or not uploaded.filename:
            flash("Selectionne un fichier.", "danger")
            return redirect(url_for("documents"))

        try:
            original_name, stored_name = save_uploaded_file(uploaded)
        except ValueError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("documents"))

        db.execute(
            """
            INSERT INTO documents (contact_id, title, original_name, stored_name, mime_type)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                contact_id,
                title or Path(original_name).stem,
                original_name,
                stored_name,
                uploaded.mimetype,
            ),
        )
        db.commit()
        flash("Fichier ajoute.", "success")
        return redirect(url_for("documents"))

    return render_template(
        "documents.html",
        page_title="Fichiers",
        documents=fetch_documents(),
        contacts=fetch_contacts(),
    )


@app.route("/contacts/<int:contact_id>/documents", methods=["POST"])
def contact_upload_document(contact_id: int):
    init_db()
    contact = fetch_contact(contact_id)
    if not contact:
        flash("Contact introuvable.", "danger")
        return redirect(url_for("contacts"))

    uploaded = request.files.get("file")
    title = (request.form.get("title") or "").strip()

    if not uploaded or not uploaded.filename:
        flash("Selectionne un fichier.", "danger")
        return redirect(url_for("contact_detail", contact_id=contact_id))

    try:
        original_name, stored_name = save_uploaded_file(uploaded)
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("contact_detail", contact_id=contact_id))

    db = get_db()
    db.execute(
        """
        INSERT INTO documents (contact_id, title, original_name, stored_name, mime_type)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            contact_id,
            title or Path(original_name).stem,
            original_name,
            stored_name,
            uploaded.mimetype,
        ),
    )
    db.commit()
    flash("Document ajoute au contact.", "success")
    return redirect(url_for("contact_detail", contact_id=contact_id))


@app.route("/documents/<int:document_id>/download")
def download_document(document_id: int):
    init_db()
    db = get_db()
    document = db.execute(
        "SELECT * FROM documents WHERE id = ?",
        (document_id,),
    ).fetchone()
    if not document:
        flash("Document introuvable.", "danger")
        return redirect(url_for("documents"))

    target = UPLOAD_DIR / document["stored_name"]
    if not target.exists():
        flash("Le fichier n'existe plus sur le disque.", "danger")
        return redirect(url_for("documents"))

    return send_file(target, as_attachment=True, download_name=document["original_name"])


@app.route("/documents/<int:document_id>/delete", methods=["POST"])
def delete_document(document_id: int):
    init_db()
    db = get_db()
    document = db.execute(
        "SELECT * FROM documents WHERE id = ?",
        (document_id,),
    ).fetchone()
    if not document:
        flash("Document introuvable.", "danger")
        return redirect(url_for("documents"))

    target = UPLOAD_DIR / document["stored_name"]
    db.execute("DELETE FROM documents WHERE id = ?", (document_id,))
    db.commit()

    if target.exists():
        target.unlink()

    flash("Document supprime.", "success")
    if document["contact_id"]:
        return redirect(url_for("contact_detail", contact_id=document["contact_id"]))
    return redirect(url_for("documents"))


@app.route("/api/calls/start", methods=["POST"])
def api_calls_start():
    init_db()
    payload = request.get_json(silent=True) or request.form

    contact_id = parse_optional_int(payload.get("contact_id"))
    agent_id = parse_optional_int(payload.get("agent_id"))
    dialed_number = normalize_dial_target(payload.get("dialed_number"))
    direction = str(payload.get("direction") or "outgoing").strip()
    provider = str(payload.get("provider") or "manual").strip().lower()

    if not dialed_number:
        return jsonify({"ok": False, "error": "Numero ou extension invalide."}), 400

    if direction not in CALL_DIRECTIONS:
        direction = "outgoing"
    if provider not in CALL_PROVIDERS:
        provider = "manual"
    if agent_id and not fetch_agent(agent_id):
        agent_id = None

    call_id = create_call_row(
        contact_id=contact_id,
        agent_id=agent_id,
        dialed_number=dialed_number,
        direction=direction,
        provider=provider,
    )
    return jsonify({"ok": True, "call_id": call_id})


@app.route("/api/calls/<int:call_id>/sync", methods=["POST"])
def api_calls_sync(call_id: int):
    init_db()
    db = get_db()
    existing = db.execute("SELECT * FROM calls WHERE id = ?", (call_id,)).fetchone()
    if not existing:
        return jsonify({"ok": False, "error": "Appel introuvable."}), 404

    payload = request.get_json(silent=True) or {}
    status = str(payload.get("status") or "").strip()
    provider_status = str(payload.get("provider_status") or "").strip()
    external_sid = str(payload.get("external_sid") or "").strip()
    summary = str(payload.get("summary") or "").strip()

    updates: dict = {}
    if status in CALL_STATUSES:
        updates["status"] = status
        if status in FINAL_CALL_STATUSES:
            updates["ended_at"] = iso_now()
    if provider_status:
        updates["provider_status"] = provider_status[:120]
    if external_sid:
        updates["external_sid"] = external_sid[:120]
    if "summary" in payload:
        updates["summary"] = summary[:1000] or None
    if payload.get("ended") and "ended_at" not in updates:
        updates["ended_at"] = iso_now()

    duration_value = payload.get("duration_seconds")
    if duration_value not in (None, ""):
        try:
            updates["duration_seconds"] = max(int(duration_value), 0)
        except (TypeError, ValueError):
            pass

    update_call_row(call_id, **updates)
    return jsonify({"ok": True})


@app.route("/api/freepbx/config")
def api_freepbx_config():
    init_db()
    settings = get_freepbx_settings()
    return jsonify(
        {
            "ok": True,
            "enabled": settings["enabled"],
            "missing": settings["missing"],
            "localhost_warning": settings["localhost_warning"],
            "wss_url": settings["wss_url"],
            "sip_domain": settings["sip_domain"],
            "display_name": settings["display_name"],
            "default_extension": settings["default_extension"],
            "default_auth_user": settings["default_auth_user"],
            "outbound_prefix": settings["outbound_prefix"],
            "sdk_import_url": settings["sdk_import_url"],
            "sample_aor": settings["sample_aor"],
            "sample_ws_path": settings["sample_ws_path"],
        }
    )


@app.route("/api/microsip/config")
def api_microsip_config():
    init_db()
    settings = get_microsip_settings()
    return jsonify(
        {
            "ok": True,
            "enabled": settings["enabled"],
            "configured_path": settings["configured_path"],
            "executable_path": settings["executable_path"],
            "display_path": settings["display_path"],
            "source": settings["source"],
            "directory_url": url_for("api_microsip_directory", _external=True),
        }
    )


@app.route("/api/microsip/directory")
def api_microsip_directory():
    init_db()
    items = []
    for contact in fetch_contacts():
        phone = (contact["phone"] or "").strip()
        if not phone:
            continue
        items.append(
            {
                "number": phone,
                "name": contact["name"] or "",
                "firstname": "",
                "lastname": "",
                "phone": phone,
                "mobile": "",
                "email": contact["email"] or "",
                "address": "",
                "city": "",
                "state": "",
                "zip": "",
                "comment": contact["notes"] or "",
                "presence": 0,
                "starred": 0,
                "info": contact["company"] or "",
            }
        )

    return jsonify(
        {
            "refresh": 0,
            "silent": 0,
            "items": items,
        }
    )


@app.route("/api/microsip/dial", methods=["POST"])
def api_microsip_dial():
    init_db()
    settings = get_microsip_settings()
    if not settings["enabled"]:
        return jsonify(
            {
                "ok": False,
                "error": "MicroSIP.exe est introuvable sur ce PC.",
            }
        ), 503

    payload = request.get_json(silent=True) or request.form
    contact_id = parse_optional_int(payload.get("contact_id"))
    agent_id = parse_optional_int(payload.get("agent_id"))
    dialed_number = normalize_dial_target(payload.get("dialed_number"))

    if contact_id and not dialed_number:
        contact = fetch_contact(contact_id)
        if contact:
            dialed_number = normalize_dial_target(contact["phone"])

    if not dialed_number:
        return jsonify({"ok": False, "error": "Numero ou extension invalide."}), 400

    if agent_id and not fetch_agent(agent_id):
        agent_id = None

    call_id = create_call_row(
        contact_id=contact_id,
        agent_id=agent_id,
        dialed_number=dialed_number,
        direction="outgoing",
        provider="microsip",
    )

    try:
        run_microsip(dialed_number)
    except OSError as exc:
        update_call_row(
            call_id,
            status="no_answer",
            ended_at=iso_now(),
            provider_status=f"microsip_error: {exc}",
        )
        return jsonify(
            {
                "ok": False,
                "error": f"Impossible de lancer MicroSIP : {exc}",
            }
        ), 500

    update_call_row(call_id, provider_status="dial_command_sent")
    return jsonify(
        {
            "ok": True,
            "call_id": call_id,
            "dialed_number": dialed_number,
            "provider": "microsip",
        }
    )


@app.route("/api/microsip/hangup", methods=["POST"])
def api_microsip_hangup():
    init_db()
    settings = get_microsip_settings()
    if not settings["enabled"]:
        return jsonify(
            {
                "ok": False,
                "error": "MicroSIP.exe est introuvable sur ce PC.",
            }
        ), 503

    try:
        run_microsip("/hangupall")
    except OSError as exc:
        return jsonify(
            {
                "ok": False,
                "error": f"Impossible de demander le raccrochage : {exc}",
            }
        ), 500

    return jsonify({"ok": True})


@app.route("/api/agents")
def api_agents():
    init_db()
    return jsonify(
        {
            "ok": True,
            "agents": [
                serialize_agent_template(agent)
                for agent in fetch_agents(active_only=True)
            ],
        }
    )


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("LOGICIEL_APPELS_PORT", "5055"))
    debug = os.environ.get("LOGICIEL_APPELS_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=port, debug=debug)
