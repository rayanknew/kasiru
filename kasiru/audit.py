"""The audit log: one JSON line per request, never the text. Fields: timestamp, client, project, stage, data class,
requested tier, route taken (with skips and errors), backend, model, tokens, cost, replacements by kind,
secret lines kept local, leaks (always 0 for a sent request - a leak blocks sending), milliseconds."""
import json
import os
import threading

_lock = threading.Lock()


class Audit:
    def __init__(self, path):
        self.path = path

    def write(self, rec):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with _lock, open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
