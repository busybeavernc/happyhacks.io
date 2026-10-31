"""Running the deploy from /admin: "Update live site" runs `sudo happyhacks-deploy`, exactly what you'd type over SSH.

The app's user may run only that one command as root (a sudoers rule install.sh writes:
/etc/sudoers.d/happyhacks-deploy). The command runs in its own session, so it keeps going when the app restarts in
the middle of its own update; its output goes to a log file the admin page reads back as it grows.
Same design as zipzip's autofill/selfupdate.py.
"""
import json
import os
import re
import subprocess
import time

EXIT_MARK = '__HAPPYHACKS_EXIT__'
COMMAND = ['sudo', '-n', '/usr/local/sbin/happyhacks-deploy']
BRANCH = 'main'
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class UpdateError(Exception):
    pass


def _state_dir():
    d = os.environ.get('UPDATES_DIR') or os.path.join(os.path.expanduser('~'), 'logs', 'happyhacks-updates')
    os.makedirs(d, exist_ok=True)
    return d


def _paths():
    d = _state_dir()
    return os.path.join(d, 'live.log'), os.path.join(d, 'live.json')


def _command():
    override = os.environ.get('UPDATE_COMMAND')   # tests and unusual servers
    return ['sh', '-c', override] if override else COMMAND


def _git(*args, timeout=25):
    r = subprocess.run(['git', '-C', ROOT, *args], capture_output=True, text=True, timeout=timeout)
    if r.returncode:
        msg = (r.stderr or r.stdout).strip()
        raise UpdateError(msg.splitlines()[-1] if msg else 'git failed')
    return r.stdout.strip()


def version(fetch=True):
    """{exists, branch, commit, subject, date, behind: [{commit, subject}], error}"""
    out = {'exists': os.path.isdir(os.path.join(ROOT, '.git')), 'branch': BRANCH}
    if not out['exists']:
        return out
    try:
        out['commit'], out['subject'], out['date'] = _git('log', '-1', '--format=%h%x09%s%x09%cI').split('\t')
        if fetch:
            _git('fetch', '-q', 'origin', BRANCH, timeout=40)
        rows = _git('log', '--format=%h%x09%s', f'HEAD..origin/{BRANCH}')
        out['behind'] = [dict(zip(('commit', 'subject'), r.split('\t', 1))) for r in rows.splitlines() if r][:30]
    except (UpdateError, subprocess.SubprocessError, ValueError) as e:
        out['error'] = str(e)[:300]
    return out


def _alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, ValueError, TypeError):
        return False


def status(offset=0):
    """{running, started, by, exit, log, offset}: the log from `offset` on (bytes)."""
    log, state = _paths()
    try:
        with open(state, encoding='utf-8') as fh:
            st = json.load(fh)
    except (OSError, ValueError):
        st = {}
    text, size, tail = '', 0, ''
    try:
        size = os.path.getsize(log)
        with open(log, 'rb') as fh:
            fh.seek(max(0, min(int(offset or 0), size)))
            text = fh.read(200_000).decode('utf-8', 'replace')
            fh.seek(max(0, size - 400))
            tail = fh.read().decode('utf-8', 'replace')
    except OSError:
        pass
    m = re.search(EXIT_MARK + r' (\d+)', tail)
    code = int(m.group(1)) if m else None
    running = bool(st.get('pid')) and code is None and _alive(st.get('pid'))
    if code is None and st.get('pid') and not running:
        code = -1   # it stopped without saying how (server restarted, or the command was killed)
    clean = re.sub(EXIT_MARK + r' \d+\n?', '', re.sub(r'\x1b\[[0-9;]*m', '', text))
    return {'started': st.get('started'), 'by': st.get('by'), 'running': running, 'exit': code, 'log': clean, 'offset': size}


def start(by_name):
    if not version(fetch=False).get('exists'):
        raise UpdateError('The app folder is not a Git clone, so it cannot be updated from here.')
    if status()['running']:
        raise UpdateError('An update is already running. Its progress is shown below.')
    log, state = _paths()
    cmd = _command()
    with open(log, 'wb') as fh:
        fh.write(f'$ {cmd[2] if cmd[0] == "sh" else " ".join(cmd)}\n'.encode())
    shell = f'{" ".join(_q(c) for c in cmd)} >> {_q(log)} 2>&1; echo "{EXIT_MARK} $?" >> {_q(log)}'
    # setsid + background: its own session (survives the app restarting during the update) and not our child
    r = subprocess.run(['sh', '-c', f'setsid sh -c {_q(shell)} </dev/null >/dev/null 2>&1 & echo $!'],
                       capture_output=True, text=True, timeout=10)
    pid = int((r.stdout or '0').strip() or 0)
    with open(state, 'w', encoding='utf-8') as fh:
        json.dump({'pid': pid, 'started': time.time(), 'by': by_name}, fh)
    return pid


def _q(s):
    return "'" + str(s).replace("'", "'\\''") + "'"
