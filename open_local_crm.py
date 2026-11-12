"""Desktop launcher: start the CRM once, wait until ready, then open the browser."""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import time
from urllib.request import urlopen
import webbrowser

ROOT = Path(__file__).resolve().parent
STATE = ROOT / 'instance' / 'local_crm'


def is_ready(url):
    try:
        with urlopen(url + '/local/etat', timeout=2) as response:
            return json.load(response).get('mode') == 'local'
    except Exception:
        return False


def main():
    STATE.mkdir(parents=True, exist_ok=True)
    settings = STATE / 'settings.json'
    config = json.loads(settings.read_text(encoding='utf-8')) if settings.exists() else {}
    url = 'http://127.0.0.1:' + str(config.get('web_port', 5055))
    if not is_ready(url):
        with (STATE / 'server.log').open('ab') as log:
            subprocess.Popen([str(ROOT / 'venv' / 'Scripts' / 'pythonw.exe'),
                              str(ROOT / 'local_crm.py'), '--no-browser'],
                             cwd=ROOT, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                             creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        for _ in range(90):
            if is_ready(url):
                break
            time.sleep(1)
        else:
            raise RuntimeError('Le CRM ne demarre pas. Consulter instance\\local_crm\\server.log.')
    webbrowser.open(url)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        ctypes.windll.user32.MessageBoxW(None, str(error), 'Mini CRM local', 0x10)
