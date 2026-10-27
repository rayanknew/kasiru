"""Configuration and paths.

Kasiru keeps three kinds of files apart:

* config   ``$KASIRU_CONF_DIR``  (default ``~/.config/kasiru``): ``kasiru.json``, ``env`` (API keys),
           ``entities.json`` (the owner's dictionary of people / organisations / terms).
* state    ``$KASIRU_STATE_DIR`` (default ``~/.local/state/kasiru``): ``tokens.json`` (token <-> real value,
           the most sensitive file on disk), ``quota.json``, ``ner_cache.json``.
* audit    ``audit_file`` in the config (default ``<state>/audit.jsonl``): one JSON line per request,
           never the text itself.
"""
import json
import os

CONF_DIR = os.path.expanduser(os.environ.get("KASIRU_CONF_DIR", "~/.config/kasiru"))
STATE_DIR = os.path.expanduser(os.environ.get("KASIRU_STATE_DIR", "~/.local/state/kasiru"))

DATA_CLASSES = ("secret", "personal", "public")
DEFAULT_TIERS = ("local", "cheap", "good", "best", "long")

DEFAULTS = {
    "listen": "127.0.0.1:8081",
    "default_class": "personal",
    "audit_file": None,            # None -> <state>/audit.jsonl
    "ollama_url": None,            # set to proxy /api/* to an Ollama instance (legacy clients)
    "max_body_mb": 64,
    "privacy": {
        "ner": "auto",             # auto | natasha | ollama | off
        "ner_model": None,         # Ollama model for the LLM detector (fallback when natasha is unavailable)
        "ner_classes": ["personal"],
        "protect_all": True,       # every detector hit becomes an active entity; exceptions via "ignore"
        "token_labels": {},        # {"person": "персона", ...} — labels used inside [label-N] tokens
        "secret_markers": ["[secret]", "[чувствительно]", "[конфиденциально]"],
        "phone_regions": ["US", "GB", "DE", "UA", "RU", "TR"],
        "generic_words": [],       # extra lower-case words the detector must never treat as names
    },
    "clients": {},                 # {"name": {"key": "...", "key_env": "ENV", "class": "secret", "default_class": "...", "admin": false}}
    "backends": {},
    "tiers": {},
}


def _merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = _merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
    return out


def load_env(path):
    """KEY=VALUE lines; the process environment wins over the file."""
    env = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip().strip("\"'")
    except FileNotFoundError:
        pass
    env.update({k: v for k, v in os.environ.items() if k in env or k.startswith("KASIRU_") or k.endswith("_API_KEY")})
    return env


class Config:
    def __init__(self, path=None, conf_dir=None, state_dir=None):
        self.conf_dir = conf_dir or CONF_DIR
        self.state_dir = state_dir or STATE_DIR
        self.path = path or os.path.join(self.conf_dir, "kasiru.json")
        with open(self.path, encoding="utf-8") as f:
            raw = json.load(f)
        self.data = _merge(DEFAULTS, raw)
        self.env = load_env(os.path.join(self.conf_dir, "env"))
        os.makedirs(self.state_dir, exist_ok=True)
        try:
            os.chmod(self.state_dir, 0o700)
        except OSError:
            pass
        self.validate()

    # ---- accessors ----
    def __getitem__(self, k):
        return self.data[k]

    def get(self, k, default=None):
        return self.data.get(k, default)

    @property
    def backends(self):
        return self.data["backends"]

    @property
    def tiers(self):
        return self.data["tiers"]

    @property
    def privacy(self):
        return self.data["privacy"]

    @property
    def audit_file(self):
        return os.path.expanduser(self.data.get("audit_file") or os.path.join(self.state_dir, "audit.jsonl"))

    @property
    def entities_file(self):
        return os.path.join(self.conf_dir, "entities.json")

    def validate(self):
        d = self.data
        if not d["backends"]:
            raise ValueError("config: no backends")
        if "local" not in d["tiers"] or not d["tiers"]["local"]:
            raise ValueError("config: tiers.local must list at least one local backend (the last resort)")
        for tier, cands in d["tiers"].items():
            for c in cands:
                if ":" not in c or c.split(":", 1)[0] not in d["backends"]:
                    raise ValueError("config: tier %r references unknown backend in %r" % (tier, c))
        lb = d["tiers"]["local"][0].split(":", 1)[0]
        if not self.is_local(lb):
            raise ValueError("config: tiers.local[0] (%s) is not a local backend" % lb)
        for name, b in d["backends"].items():
            b.setdefault("classes", ["public"] if not self.is_local(name) else list(DATA_CLASSES))
            for c in b["classes"]:
                if c not in DATA_CLASSES:
                    raise ValueError("config: backend %s: unknown data class %r" % (name, c))
            if not self.is_local(name) and "secret" in b["classes"]:
                raise ValueError("config: backend %s is not local and may not accept class secret" % name)
        for name, c in d["clients"].items():
            if not (c.get("key") or (c.get("key_env") and self.env.get(c["key_env"]))):
                raise ValueError("config: client %s has neither key nor a resolvable key_env" % name)

    def is_local(self, backend):
        b = self.backends.get(backend) or {}
        return b.get("kind") == "ollama" or bool(b.get("local"))

    def client_key(self, name):
        c = self.data["clients"][name]
        return c.get("key") or self.env.get(c.get("key_env", ""))

    def client_by_key(self, key):
        """-> (name, client dict) for a bearer key, or (None, None)."""
        for name in self.data["clients"]:
            if key and self.client_key(name) == key:
                return name, self.data["clients"][name]
        return None, None
