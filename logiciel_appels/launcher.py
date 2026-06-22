from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
APP_URL = os.environ.get("LOGICIEL_APPELS_URL", "http://127.0.0.1:5055/")


def server_is_up() -> bool:
    try:
        with urllib.request.urlopen(APP_URL, timeout=0.7) as response:
            return 200 <= response.status < 500
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        return False


def find_pythonw() -> str:
    candidates = [
        ROOT_DIR / "venv" / "Scripts" / "pythonw.exe",
        ROOT_DIR / "venv" / "Scripts" / "python.exe",
        Path(sys.executable),
    ]

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    return "python"


def start_server() -> None:
    python_exe = find_pythonw()
    env = os.environ.copy()
    env.setdefault("LOGICIEL_APPELS_DEBUG", "0")

    creationflags = 0
    if os.name == "nt":
        creationflags = (
            getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        )

    subprocess.Popen(
        [python_exe, str(BASE_DIR / "app.py")],
        cwd=str(ROOT_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
        env=env,
    )


def ensure_server() -> None:
    if server_is_up():
        return

    start_server()

    for _ in range(30):
        time.sleep(0.35)
        if server_is_up():
            return


def main() -> None:
    ensure_server()
    webbrowser.open(APP_URL)


if __name__ == "__main__":
    main()
