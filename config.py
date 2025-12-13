import os

class Config:
    # Clé secrète Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev_key")

    # Détection Render
    IS_RENDER = os.environ.get("RENDER") is not None

    # Mode local
    _env_local_mode = os.environ.get("LOCAL_MODE")
    if _env_local_mode is not None:
        LOCAL_MODE = _env_local_mode.lower() == "true"
    else:
        LOCAL_MODE = not IS_RENDER

    # Base dir
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    # SQLite (local uniquement)
    INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    SQLITE_DB_PATH = os.path.join(INSTANCE_DIR, "crm.db")

    # PostgreSQL (Render)
    DATABASE_URL = os.environ.get("DATABASE_URL")

    # AWS
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
