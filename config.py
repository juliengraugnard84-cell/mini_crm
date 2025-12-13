import os
from urllib.parse import urlparse

class Config:
    # -------------------------------------------------
    # FLASK
    # -------------------------------------------------
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev_key")

    IS_RENDER = os.environ.get("RENDER") is not None

    _env_local_mode = os.environ.get("LOCAL_MODE")
    if _env_local_mode is not None:
        LOCAL_MODE = _env_local_mode.lower() == "true"
    else:
        LOCAL_MODE = not IS_RENDER

    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    # -------------------------------------------------
    # DATABASE
    # -------------------------------------------------

    DATABASE_URL = os.environ.get("DATABASE_URL")

    if DATABASE_URL:
        # PostgreSQL (Render)
        DB_TYPE = "postgres"
        SQLALCHEMY_DATABASE_URI = DATABASE_URL

        # Render fournit parfois postgres:// → on force postgresql://
        if SQLALCHEMY_DATABASE_URI.startswith("postgres://"):
            SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace(
                "postgres://", "postgresql://", 1
            )

    else:
        # SQLite (local uniquement)
        DB_TYPE = "sqlite"
        INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
        os.makedirs(INSTANCE_DIR, exist_ok=True)
        DB_PATH = os.path.join(INSTANCE_DIR, "crm.db")

    # -------------------------------------------------
    # AWS S3
    # -------------------------------------------------

    AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")
    AWS_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")

    AWS_REGION = (
        os.environ.get("AWS_S3_REGION")
        or os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or "eu-west-3"
    )

    AWS_BUCKET = (
        os.environ.get("AWS_S3_BUCKET")
        or os.environ.get("AWS_BUCKET")
    )
