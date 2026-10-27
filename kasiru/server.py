"""HTTP front: an OpenAI-compatible endpoint plus a few service paths. Standard library only.

Authentication: when ``clients`` is configured, every request needs ``Authorization: Bearer <key>``; the matching client
name becomes ``X-Client`` (a client-supplied header is ignored). When ``clients`` is empty the gateway trusts the network
(bind to 127.0.0.1 and put a reverse proxy with keys in front, or use it on a single machine).
Administrative paths (``/v1/kasiru/entities``, ``/v1/kasiru/reload``) are allowed from localhost without a key, or for a
client with ``"admin": true``.
"""
import json
import traceback
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import backends as B
from .audit import Audit
from .config import Config
from .pipeline import Pipeline
from .privacy import Privacy
from .router import Router


class App:
    def __init__(self, config_path=None, log=print):
        self.log = log
        self.config_path = config_path
        self.reload()

    def reload(self):
        cfg = Config(self.config_path)
        if getattr(self, "privacy", None) is not None:
            self.privacy.reload_entities()
        else:
            po = dict(cfg.privacy)
            po["ollama_url"] = cfg.get("ollama_url") or po.get("ollama_url")
            self.privacy = Privacy(cfg.conf_dir, cfg.state_dir, po, self.log)
            self.log("entity detector: %s" % self.privacy.ner_label)
        self.cfg = cfg
        self.router = Router(cfg, self.log)
        self.audit = Audit(cfg.audit_file)
        self.pipeline = Pipeline(cfg, self.router, self.privacy, self.audit, self.log)
        self.log("config loaded: backends %s; tiers %s; clients %s" % (", ".join(cfg.backends), ", ".join(cfg.tiers), ", ".join(cfg["clients"]) or "(none - open)"))

    def stats(self):
        s = self.router.stats()
        s["entities"] = {k: len(v) for k, v in self.privacy.entities.items() if isinstance(v, list)}
        s["pending"] = self.privacy.entities.get("pending")
        s["tokens"] = self.privacy.tokens["counters"]
        return s

    def health(self):
        loc = {}
        for name, b in self.cfg.backends.items():
            if self.cfg.is_local(name):
                url = ((b.get("url") or self.cfg.get("ollama_url") or "http://127.0.0.1:11434").rstrip("/") + "/api/version") if b.get("kind") == "ollama" else b["url"].rstrip("/") + "/models"
                try:
                    urllib.request.urlopen(url, timeout=3)
                    loc[name] = True
                except Exception:  # noqa: BLE001
                    loc[name] = False
        lb = self.router.local_default()[0]
        ok = bool(loc.get(lb))
        return ok, {"ok": ok, "local": loc, "entities": len(self.privacy.entities["persons"]) + len(self.privacy.entities["orgs"]), "ner": self.privacy.ner_label}


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        ADMIN_PATHS = ("/v1/kasiru/entities", "/v1/kasiru/reload")
        OPEN_PATHS = ("/health",)
        OLLAMA_OK = ("/api/chat", "/api/generate", "/api/embed", "/api/embeddings", "/api/tags", "/api/ps", "/api/show", "/api/version", "/v1/embeddings")

        def log_message(self, fmt, *args):
            pass

        def _send(self, code, obj):
            data = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        # ---- auth ----
        def _auth(self):
            """-> (client_name, client_dict, is_admin) or sends 401/403 and returns None.

            Order: a bearer key of a keyed client; else, from loopback, X-Client naming a keyless (proxy-trusted) client
            as set by a reverse proxy; else loopback without X-Client = local administrator; else, when keyed clients
            exist, 401; otherwise the gateway trusts the network and X-Client is just a label."""
            path = self.path.split("?")[0]
            from_localhost = self.client_address[0] in ("127.0.0.1", "::1")
            if path in self.OPEN_PATHS:
                return "", {}, False
            auth = self.headers.get("Authorization") or ""
            key = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            xclient = self.headers.get("X-Client") or ""
            name, c = app.cfg.client_by_key(key)
            if name:
                admin = bool(c.get("admin"))
            elif from_localhost and xclient and app.cfg.proxy_client(xclient) is not None:
                name, c = xclient, app.cfg.proxy_client(xclient)
                admin = bool(c.get("admin"))
            elif from_localhost and not xclient:
                name, c, admin = "", {}, True
            elif app.cfg.keyed_clients():
                self._send(401, {"error": {"message": "unknown or missing API key", "type": "kasiru_auth"}})
                return None
            else:
                name, c, admin = xclient, {}, False
            if path in self.ADMIN_PATHS and not admin:
                self._send(403, {"error": {"message": "administrative path", "type": "kasiru_auth"}})
                return None
            if path.startswith("/api/") and path not in self.OLLAMA_OK and not admin:
                self._send(403, {"error": {"message": "path not allowed", "type": "kasiru_auth"}})
                return None
            return name, c, admin

        def _headers_for(self, name):
            h = {k: v for k, v in self.headers.items()}
            h["X-Client"] = name
            return h

        # ---- ollama pass-through for legacy clients ----
        def _proxy_ollama(self, body):
            path = self.path.split("?")[0]
            emb = app.cfg.get("embeddings") or {}
            if path == "/v1/embeddings" and emb.get("url"):          # embeddings always stay local
                url = emb["url"].rstrip("/") + "/embeddings"
            else:
                base = app.cfg.get("ollama_url")
                if not base:
                    return self._send(404, {"error": {"message": "unknown path", "type": "kasiru_path"}})
                url = base.rstrip("/") + self.path
            req = urllib.request.Request(url, data=body, method=self.command,
                                         headers={"Content-Type": self.headers.get("Content-Type", "application/json")})
            try:
                r = urllib.request.urlopen(req, timeout=7200)
                self.send_response(r.status)
                for k, v in r.getheaders():
                    if k.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(k, v)
                self.send_header("Connection", "close")
                self.end_headers()
                while True:
                    chunk = r.read(8192)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except urllib.error.HTTPError as e:
                self._send(e.code, {"error": e.read().decode(errors="replace")[:300]})
            except Exception as e:  # noqa: BLE001
                self._send(502, {"error": str(e)})

        def do_GET(self):
            a = self._auth()
            if a is None:
                return
            path = self.path.split("?")[0]
            if path == "/health":
                ok, body = app.health()
                return self._send(200 if ok else 503, body)
            if path == "/v1/models":
                data = [{"id": t, "object": "model", "owned_by": "kasiru"} for t in app.cfg.tiers]
                data += [{"id": c, "object": "model", "owned_by": "kasiru"} for t in app.cfg.tiers.values() for c in t]
                return self._send(200, {"object": "list", "data": list({d["id"]: d for d in data}.values())})
            if path == "/v1/kasiru/stats":
                return self._send(200, app.stats())
            if path == "/v1/kasiru/entities":
                return self._send(200, app.privacy.entities)
            return self._proxy_ollama(None)

        def do_POST(self):
            a = self._auth()
            if a is None:
                return
            name, client, _admin = a
            n = int(self.headers.get("Content-Length") or 0)
            if n > app.cfg["max_body_mb"] * 1024 * 1024:
                return self._send(413, {"error": {"message": "body too large", "type": "kasiru_request"}})
            raw = self.rfile.read(n) if n else b""
            path = self.path.split("?")[0]
            if path == "/v1/kasiru/reload":
                app.reload()
                return self._send(200, {"reloaded": True, "tokens_purged": app.privacy.purge_tokens()})
            if path.rstrip("/") == "/v1/chat/completions":
                try:
                    body = json.loads(raw or b"{}")
                except ValueError:
                    return self._send(400, {"error": {"message": "bad json", "type": "kasiru_request"}})
                headers = self._headers_for(name)
                try:
                    if body.get("stream") and app.pipeline.can_stream(body, headers, client):
                        return self._stream(body, headers, client)
                    code, resp = app.pipeline.handle(body, headers, client)
                except Exception as e:  # noqa: BLE001
                    app.log("handler error: %r\n%s" % (e, traceback.format_exc()))
                    return self._send(500, {"error": {"message": str(e), "type": "kasiru_internal"}})
                if body.get("stream") and code == 200:   # cloud route: the answer is restored first, then sent as one chunk
                    msg = resp["choices"][0]["message"]
                    chunk = {"id": resp["id"], "object": "chat.completion.chunk", "created": resp["created"], "model": resp["model"],
                             "choices": [{"index": 0, "delta": msg, "finish_reason": resp["choices"][0]["finish_reason"]}], "usage": resp["usage"]}
                    data = ("data: " + json.dumps(chunk, ensure_ascii=False) + "\n\ndata: [DONE]\n\n").encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                return self._send(code, resp)
            return self._proxy_ollama(raw)

        def _stream(self, body, headers, client):
            try:
                gen = app.pipeline.stream(body, headers, client)
                first = next(gen)
            except B.Upstream as e:
                return self._send(503, {"error": {"message": str(e), "type": "kasiru_no_backend"}})
            except StopIteration:
                return self._send(502, {"error": {"message": "empty stream", "type": "kasiru_backend"}})
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                for chunk in Pipeline._iter(first, gen):
                    self.wfile.write(("data: " + json.dumps(chunk, ensure_ascii=False) + "\n\n").encode())
                    self.wfile.flush()
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                gen.close()

    return Handler


def serve(config_path=None, log=print):
    app = App(config_path, log)
    host, port = app.cfg["listen"].split(":")
    srv = ThreadingHTTPServer((host, int(port)), make_handler(app))
    srv.daemon_threads = True
    log("kasiru listening on %s:%s, audit %s" % (host, port, app.cfg.audit_file))
    srv.serve_forever()
