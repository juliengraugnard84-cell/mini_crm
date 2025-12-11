import os

class Config:
    # Clé secrète Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev_key")

    # Render définit "RENDER" lorsqu'on tourne sur leur infra
    IS_RENDER = os.environ.get("RENDER") is not None

    # Mode local ou non
    # - Si LOCAL_MODE est défini, on le respecte.
    # - Sinon : on considère que Render = production (LOCAL_MODE = False)
    _env_local_mode = os.environ.get("LOCAL_MODE")
    if _env_local_mode is not None:
        LOCAL_MODE = _env_local_mode.lower() == "true"
    else:
        LOCAL_MODE = not IS_RENDER

    # Répertoire base
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    # Répertoire instance pour SQLite
    INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
    os.makedirs(INSTANCE_DIR, exist_ok=True)

    # Base SQLite
    DB_PATH = os.path.join(INSTANCE_DIR, "crm.db")

    # AWS — identifiants
    AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")
    AWS_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")

    # Région : on accepte plusieurs noms possibles
    AWS_REGION = (
        os.environ.get("AWS_S3_REGION")
        or os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or "eu-west-3"  # mets ici ta région par défaut
    )

    # Bucket : on accepte plusieurs noms possibles
    AWS_BUCKET = (
        os.environ.get("AWS_S3_BUCKET")
        or os.environ.get("AWS_BUCKET")
    )
