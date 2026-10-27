"""Atomic JSON files with a .bak copy and 0600 permissions (the token table holds real names and keys)."""
import json
import os
import sys
import threading

_save_lock = threading.Lock()


def load(path, default):
    """A truncated file (interrupted write) falls back to .bak instead of silently returning an empty dict."""
    for cand in (path, path + ".bak"):
        try:
            with open(cand, encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            continue
        except Exception as e:  # noqa: BLE001
            print("kasiru: cannot read %s: %s - trying backup" % (cand, e), file=sys.stderr)
    return default


def save(path, obj):
    with _save_lock:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = "%s.%d.%d.tmp" % (path, os.getpid(), threading.get_ident())
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=1)
        if os.path.exists(path):
            try:
                os.replace(path, path + ".bak")
            except OSError:
                pass
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
