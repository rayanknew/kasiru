"""End-to-end tests of the HTTP gateway against fake upstreams: routing, classes, tool calls, streaming, auth, quotas."""
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from tests.fake_upstream import FakeUpstream  # noqa: E402

D = tempfile.mkdtemp(prefix="kasiru-gw-")
os.environ["KASIRU_CONF_DIR"] = D
os.environ["KASIRU_STATE_DIR"] = D
os.environ["GEMINI_API_KEY"] = "test"
os.environ["KASIRU_KEY_AGENT"] = "agent-key"
os.environ["KASIRU_KEY_ADMIN"] = "admin-key"

from kasiru import server  # noqa: E402

LOCAL = FakeUpstream()
CLOUD = FakeUpstream()
CONF = {
    "listen": "127.0.0.1:0", "default_class": "personal", "privacy": {"ner": "off"},
    "clients": {"agent": {"key_env": "KASIRU_KEY_AGENT", "class": "secret", "default_tier": "local"},
                "scripts": {"key": "scripts-key"},
                "admin": {"key_env": "KASIRU_KEY_ADMIN", "admin": True},
                "proxied": {"class": "secret", "default_tier": "local"}},
    "embeddings": {"url": LOCAL.url},
    "backends": {
        "llama": {"kind": "openai", "url": LOCAL.url, "local": True, "classes": ["secret", "personal", "public"], "max_parallel": 1},
        "gemini": {"kind": "openai", "url": CLOUD.url, "key": "GEMINI_API_KEY", "classes": ["personal", "public"], "daily_requests": 1000, "price_in": 1.0, "price_out": 2.0},
    },
    "tiers": {"local": ["llama:m"], "good": ["gemini:g", "llama:m"], "cheap": ["gemini:g", "llama:m"]},
}
json.dump(CONF, open(os.path.join(D, "kasiru.json"), "w"))
json.dump({"persons": ["Jane Example"], "orgs": [], "pending": {"persons": [], "orgs": []}}, open(os.path.join(D, "entities.json"), "w"))

APP = server.App(log=lambda *a: None)
SRV = server.ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(APP))
SRV.daemon_threads = True
threading.Thread(target=SRV.serve_forever, daemon=True).start()
BASE = "http://127.0.0.1:%d" % SRV.server_address[1]


def call(path, body=None, key="scripts-key", headers=None, method=None, raw=False):
    h = {"Content-Type": "application/json"}
    if key:
        h["Authorization"] = "Bearer " + key
    h.update(headers or {})
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, headers=h, method=method or ("POST" if data is not None else "GET"))
    try:
        r = urllib.request.urlopen(req, timeout=20)
        payload = r.read()
        return r.status, (payload if raw else json.loads(payload or b"null"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def chat(content, key="scripts-key", **extra):
    body = {"model": extra.pop("model", "good"), "messages": [{"role": "user", "content": content}]}
    body.update(extra)
    return call("/v1/chat/completions", body, key=key, headers=extra.pop("headers", None))


class Auth(unittest.TestCase):
    def test_wrong_key(self):
        self.assertEqual(call("/v1/models", key="nope")[0], 401)
        self.assertEqual(call("/v1/models", key=None, headers={"X-Client": "scripts"})[0], 401)   # a keyed client needs its key

    def test_health_is_open(self):
        code, body = call("/health", key=None)
        self.assertIn(code, (200, 503))
        self.assertIn("local", body)

    def test_admin_paths(self):
        self.assertEqual(call("/v1/kasiru/entities", key="scripts-key")[0], 403)
        self.assertEqual(call("/v1/kasiru/entities", key="admin-key")[0], 200)
        self.assertEqual(call("/v1/kasiru/reload", body={}, key="scripts-key")[0], 403)
        self.assertEqual(call("/v1/kasiru/reload", body={}, key="admin-key")[0], 200)

    def test_client_header_cannot_be_forged(self):
        code, resp = chat("hi", headers={"X-Client": "admin"})
        self.assertEqual(code, 200)
        with open(APP.cfg.audit_file) as f:
            self.assertEqual(json.loads(f.read().splitlines()[-1])["client"], "scripts")


class ProxyTrusted(unittest.TestCase):
    def test_keyless_client_by_header_from_loopback(self):
        code, resp = call("/v1/chat/completions", {"messages": [{"role": "user", "content": "Jane Example"}]}, key=None, headers={"X-Client": "proxied"})
        self.assertEqual(code, 200)
        self.assertEqual(resp["kasiru"]["class"], "secret")
        self.assertEqual(resp["kasiru"]["backend"], "llama")

    def test_unknown_header_name_without_key_is_refused(self):
        self.assertEqual(call("/v1/models", key=None, headers={"X-Client": "nobody"})[0], 401)

    def test_loopback_without_anything_is_admin(self):
        self.assertEqual(call("/v1/kasiru/entities", key=None)[0], 200)


class Embeddings(unittest.TestCase):
    def test_embeddings_proxied_to_local_url(self):
        LOCAL.requests.clear()
        code, resp = call("/v1/embeddings", {"model": "bge", "input": "Jane Example"})
        self.assertEqual(code, 200)
        self.assertEqual(LOCAL.requests[-1]["path"], "/v1/embeddings")


class Routing(unittest.TestCase):
    def test_personal_goes_to_cloud_pseudonymised_and_restored(self):
        CLOUD.requests.clear()
        code, resp = chat("tell Jane Example hello")
        self.assertEqual(code, 200)
        self.assertEqual(resp["kasiru"]["backend"], "gemini")
        sent = json.dumps(CLOUD.requests[-1]["body"])
        self.assertNotIn("Jane Example", sent)
        self.assertIn("[person-", sent)
        self.assertIn("Jane Example", resp["choices"][0]["message"]["content"])   # restored in the echo
        self.assertEqual(resp["kasiru"]["replaced"]["person"], 1)
        self.assertGreater(resp["kasiru"]["cost"], 0)

    def test_secret_class_forces_local(self):
        LOCAL.requests.clear()
        code, resp = chat("Jane Example secret", headers={"X-Data-Class": "secret"})
        self.assertEqual(resp["kasiru"]["backend"], "llama")
        self.assertIn("Jane Example", json.dumps(LOCAL.requests[-1]["body"]))   # local sees the real text

    def test_client_forced_class_and_default_tier(self):
        code, resp = call("/v1/chat/completions", {"messages": [{"role": "user", "content": "Jane Example"}]}, key="agent-key")
        self.assertEqual(code, 200)
        self.assertEqual(resp["kasiru"]["class"], "secret")
        self.assertEqual(resp["kasiru"]["backend"], "llama")

    def test_secret_marker_keeps_whole_request_local(self):
        code, resp = chat("normal line\n[secret] pin 1234")
        self.assertEqual(resp["kasiru"]["backend"], "llama")
        self.assertEqual(resp["kasiru"]["forced_local"], "secret markers")

    def test_split_mode(self):
        CLOUD.requests.clear()
        code, resp = chat("normal line\n[secret] pin 1234", headers={"X-Secret-Mode": "split"})
        self.assertEqual(resp["kasiru"]["backend"], "gemini")
        self.assertNotIn("1234", json.dumps(CLOUD.requests[-1]["body"]))
        self.assertIn("Secret part", resp["choices"][0]["message"]["content"])
        self.assertTrue(any(r.get("secret_part") for r in resp["kasiru"]["route"]))

    def test_cloud_failure_falls_back_to_local(self):
        CLOUD.fail_with = (500, "boom")
        code, resp = chat("hello")
        self.assertEqual(code, 200)
        self.assertEqual(resp["kasiru"]["backend"], "llama")
        self.assertTrue(any("error" in r for r in resp["kasiru"]["route"]))
        APP.router.quota["cooldown"].clear()   # undo the cool-down for the following tests

    def test_explicit_backend_model(self):
        code, resp = chat("hello", model="llama:other")
        self.assertEqual(resp["model"], "llama:other")

    def test_bare_model_name_means_local(self):
        code, resp = chat("hello", model="some-local-model")
        self.assertEqual(resp["kasiru"]["backend"], "llama")


class Tools(unittest.TestCase):
    TOOLS = [{"type": "function", "function": {"name": "search", "parameters": {"type": "object", "properties": {"q": {"type": "string"}}}}}]

    def test_tool_calls_pass_through_locally(self):
        code, resp = chat("please call tool", model="local", tools=self.TOOLS)
        self.assertEqual(code, 200)
        msg = resp["choices"][0]["message"]
        self.assertEqual(resp["choices"][0]["finish_reason"], "tool_calls")
        self.assertEqual(msg["tool_calls"][0]["function"]["name"], "search")

    def test_tools_not_sent_to_cloud_for_personal(self):
        CLOUD.requests.clear()
        code, resp = chat("please call tool", model="good", tools=self.TOOLS)
        self.assertEqual(resp["kasiru"]["backend"], "llama")
        self.assertEqual(CLOUD.requests, [])

    def test_tools_allowed_to_cloud_for_public(self):
        CLOUD.requests.clear()
        code, resp = chat("please call tool", model="good", tools=self.TOOLS, headers={"X-Data-Class": "public"})
        self.assertEqual(resp["kasiru"]["backend"], "gemini")
        self.assertEqual(resp["choices"][0]["finish_reason"], "tool_calls")


class Streaming(unittest.TestCase):
    def test_local_stream_passthrough(self):
        code, raw = call("/v1/chat/completions", {"model": "local", "stream": True, "messages": [{"role": "user", "content": "one two three"}]}, raw=True)
        self.assertEqual(code, 200)
        lines = [l for l in raw.decode().split("\n") if l.startswith("data:")]
        self.assertGreaterEqual(len(lines), 4)          # several deltas + [DONE]
        self.assertEqual(lines[-1], "data: [DONE]")
        text = "".join(json.loads(l[5:])["choices"][0]["delta"].get("content") or "" for l in lines[:-1] if json.loads(l[5:]).get("choices"))
        self.assertEqual(text.strip(), "echo: one two three")

    def test_cloud_stream_is_one_restored_chunk(self):
        code, raw = call("/v1/chat/completions", {"model": "good", "stream": True, "messages": [{"role": "user", "content": "Jane Example"}]}, raw=True)
        lines = [l for l in raw.decode().split("\n") if l.startswith("data:")]
        self.assertEqual(len(lines), 2)
        self.assertIn("Jane Example", lines[0])


class Quotas(unittest.TestCase):
    def test_daily_requests_limit_skips_backend(self):
        APP.router.quota["days"].clear()
        APP.cfg.backends["gemini"]["daily_requests"] = 3
        for _ in range(3):
            chat("x")
        code, resp = chat("x")
        self.assertEqual(resp["kasiru"]["backend"], "llama")
        self.assertTrue(any(r.get("skip") == "daily request limit" for r in resp["kasiru"]["route"]))
        APP.cfg.backends["gemini"]["daily_requests"] = 1000
        APP.router.quota["days"].clear()


class Validation(unittest.TestCase):
    def test_config_rejects_cloud_secret(self):
        from kasiru.config import Config
        bad = dict(CONF, backends=dict(CONF["backends"], gemini=dict(CONF["backends"]["gemini"], classes=["secret"])))
        p = os.path.join(D, "bad.json")
        with open(p, "w") as f:
            json.dump(bad, f)
        with self.assertRaises(ValueError):
            Config(p)


def tearDownModule():
    SRV.shutdown()
    SRV.server_close()
    LOCAL.close()
    CLOUD.close()
    shutil.rmtree(D, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
