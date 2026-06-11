import os


class Config:
    # =========================
    # Flask
    # =========================
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev_key")

    # =========================
    # Environnement
    # =========================
    ENV = os.environ.get("ENV", "development")
    PRODUCTION = ENV == "production"

    # =========================
    # Mode local / prod
    # =========================
    # LOCAL_MODE = True  -> coupe S3 (DEV)
    # LOCAL_MODE = False -> active S3 (PROD)
    LOCAL_MODE = os.environ.get("LOCAL_MODE", "0").lower() in ("1", "true")

    # =========================
    # Base directory
    # =========================
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    # =========================
    # Instance directory (DEV / SQLite)
    # =========================
    INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
    os.makedirs(INSTANCE_DIR, exist_ok=True)

    # =========================
    # DATABASE
    # =========================
    DATABASE_URL = os.environ.get("DATABASE_URL")

    DB_PATH = os.environ.get(
        "DB_PATH",
        os.path.join(INSTANCE_DIR, "crm.db")
    )

    # =========================
    # AWS / S3
    # =========================
    AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")
    AWS_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
    AWS_REGION = os.environ.get("AWS_REGION", "eu-west-3")
    AWS_BUCKET = os.environ.get("AWS_BUCKET")

    # =========================
    # Email notifications
    # =========================
    SMTP_HOST = (
        os.environ.get("SMTP_HOST")
        or os.environ.get("SMTP_SERVER")
        or os.environ.get("MAIL_SERVER")
        or os.environ.get("MAIL_HOST")
    )
    SMTP_PORT = int(
        os.environ.get("SMTP_PORT")
        or os.environ.get("MAIL_PORT")
        or 587
    )
    SMTP_USERNAME = (
        os.environ.get("SMTP_USERNAME")
        or os.environ.get("SMTP_USER")
        or os.environ.get("MAIL_USERNAME")
        or os.environ.get("MAIL_USER")
    )
    SMTP_PASSWORD = (
        os.environ.get("SMTP_PASSWORD")
        or os.environ.get("SMTP_PASS")
        or os.environ.get("MAIL_PASSWORD")
        or os.environ.get("MAIL_PASS")
    )
    SMTP_USE_TLS = (
        os.environ.get("SMTP_USE_TLS")
        or os.environ.get("MAIL_USE_TLS")
        or "1"
    ).lower() in ("1", "true", "yes", "on")
    SMTP_USE_SSL = (
        os.environ.get("SMTP_USE_SSL")
        or os.environ.get("MAIL_USE_SSL")
        or "0"
    ).lower() in ("1", "true", "yes", "on")
    SMTP_FROM_EMAIL = (
        os.environ.get("SMTP_FROM_EMAIL")
        or os.environ.get("MAIL_DEFAULT_SENDER")
        or os.environ.get("MAIL_FROM")
        or SMTP_USERNAME
        or "no-reply@synergyconsulting.fr"
    )
    NOTIFICATION_EMAIL = os.environ.get(
        "NOTIFICATION_EMAIL",
        "j.graugnard@synergyconsulting.fr",
    )
    APP_BASE_URL = os.environ.get("APP_BASE_URL", "").rstrip("/")

    # =========================
    # Upload
    # =========================
    MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", 10))
