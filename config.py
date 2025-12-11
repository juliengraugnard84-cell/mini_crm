import os

class Config:
    # Clé secrète Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev_key")

    # Mode local ou production
    LOCAL_MODE = os.environ.get("LOCAL_MODE", "false").lower() == "true"

    # Répertoire base
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    # Répertoire instance pour SQLite
    INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
    os.makedirs(INSTANCE_DIR, exist_ok=True)

    # Base SQLite
    DB_PATH = os.path.join(INSTANCE_DIR, "crm.db")

    # AWS — VARIABLES EXACTES UTILISÉES SUR RENDER
    AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")
    AWS_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
    AWS_REGION     = os.environ.get("AWS_S3_REGION")
    AWS_BUCKET     = os.environ.get("AWS_S3_BUCKET")
