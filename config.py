import os

class Config:
    # =========================
    # Flask
    # =========================
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev_key")

    # =========================
    # Mode local / prod
    # =========================
    LOCAL_MODE = os.environ.get("LOCAL_MODE", "0") in ("1", "true", "True")

    # =========================
    # Base directory
    # =========================
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    # =========================
    # DATABASE (SQLite simple)
    # =========================
    # 👉 PAS DE DISK RENDER
    # 👉 Base stockée dans le dossier projet
    DB_PATH = os.environ.get(
        "DB_PATH",
        os.path.join(BASE_DIR, "crm.sqlite3")
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
    MAX_UPLOAD_MB = 10
