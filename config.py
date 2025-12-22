import os


class Config:
    # ======================================================
    # FLASK
    # ======================================================
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev_secret_key_change_me")

    # ======================================================
    # ENVIRONNEMENT
    # ======================================================
    # Render définit automatiquement la variable RENDER
    IS_RENDER = os.environ.get("RENDER") is not None

    # LOCAL_MODE :
    # - si explicitement défini → respecté
    # - sinon : local = True, render = False
    _env_local_mode = os.environ.get("LOCAL_MODE")
    if _env_local_mode is not None:
        LOCAL_MODE = str(_env_local_mode).lower() in ("1", "true", "yes")
    else:
        LOCAL_MODE = not IS_RENDER

    # ======================================================
    # BASE DIR
    # ======================================================
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    # ======================================================
    # DATABASE (SQLite — SANS DISK RENDER)
    # ======================================================
    # ➜ SQLite local, stable, pas de /data, pas de crash
    # ➜ recréé au redeploy (assumé)
    DB_PATH = os.environ.get(
        "DB_PATH",
        os.path.join(BASE_DIR, "crm.sqlite3")
    )

    # ======================================================
    # POSTGRES (OPTIONNEL — NON UTILISÉ ACTUELLEMENT)
    # ======================================================
    DATABASE_URL = os.environ.get("DATABASE_URL")

    # ======================================================
    # UPLOADS / LIMITES
    # ======================================================
    MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "10"))

    # ======================================================
    # AWS / S3
    # ======================================================
    AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")
    AWS_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")

    AWS_REGION = (
        os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or "eu-west-3"
    )

    AWS_BUCKET = os.environ.get("AWS_BUCKET")

    # ======================================================
    # SÉCURITÉ SESSION (PROD SAFE)
    # ======================================================
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    if os.environ.get("FLASK_ENV") == "production":
        SESSION_COOKIE_SECURE = True
