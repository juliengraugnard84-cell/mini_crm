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
    LOCAL_MODE = os.environ.get("LOCAL_MODE", "0") in ("1", "true", "True")

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
    # Upload
    # =========================
    MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", 10))
