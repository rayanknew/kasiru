"""Calls to model servers. Two kinds: ``openai`` (any OpenAI-compatible chat endpoint, local or cloud) and ``ollama``
(the native /api/chat). A call returns the assistant message as the provider gave it - content, tool_calls,
finish_reason - plus token counts, so agents with tool calling work through the gateway unchanged.
"""
import json
import re
import urllib.error
import urllib.request
from collections import Counter

THINK = re.compile(r"<think>.*?</think>\s*", re.S)
PRIVATE_FIELDS = ("data_class", "stage", "project", "secret_mode")


class Upstream(Exception):
    """A backend failure with an HTTP-like code. Synthetic codes: 497 content filter, 498 degenerate output, 599 network."""

    def __init__(self, code, msg, retry_after=0):
        super().__init__(msg)
        self.code, self.retry_after = code, retry_after


class Result:
    __slots__ = ("message", "finish", "tokens_in", "tokens_out")

    def __init__(self, message, finish, tokens_in, tokens_out):
        self.message, self.finish, self.tokens_in, self.tokens_out = message, finish, tokens_in, tokens_out

    @property
    def text(self):
        c = self.message.get("content")
        if isinstance(c, list):
            return "\n".join(p.get("text", "") for p in c if isinstance(p, dict))
        return c or ""


def degenerate(text, min_len=20, max_rep=8, max_ratio=0.25):
    """Model looping: one line repeated many times or a quarter of the lines duplicated."""
    lines = [l.strip() for l in text.splitlines() if len(l.strip()) >= min_len]
    if len(lines) < 40:
        return None
    c = Counter(lines)
    top, n = c.most_common(1)[0]
    dup = sum(v - 1 for v in c.values())
    if n >= max_rep or dup / len(lines) > max_ratio:
        return "looping output: %d lines, %d duplicates, max repeat x%d" % (len(lines), dup, n)
    return None


def short_err(msg, n=160):
    """Provider error text without long strings (some APIs echo a fragment of the request)."""
    return re.sub(r'"[^"]{40,}"', '"…"', str(msg))[:n]


def cap_output(b, body):
    cap = b.get("max_output")
    if cap and int(body.get("max_tokens") or 0) > int(cap):
        body = dict(body, max_tokens=int(cap))
    return body


def check_answer(res):
    """An empty answer is a backend error (502), not a success; a provider content filter is 497 (next candidate, no cool-down)."""
    if res.message.get("tool_calls"):
        return
    if not res.text:
        raise Upstream(502, "empty answer (finish=%s, out=%s)" % (res.finish, res.tokens_out))
    if res.finish == "content_filter":
        raise Upstream(497, "provider content filter (finish=content_filter, out=%s)" % res.tokens_out)


def _retry_after(msg):
    m = re.search(r"retry in (?:(\d+)h)?(?:(\d+)m)?([\d.]+)s", msg, re.I)
    return (int(m.group(1) or 0) * 3600 + int(m.group(2) or 0) * 60 + int(float(m.group(3)))) if m else 0


def _openai_payload(b, model, body, stream):
    body = cap_output(b, body)
    payload = dict(body)
    payload["model"] = model
    payload["stream"] = stream
    if stream:
        payload["stream_options"] = {"include_usage": True}
    for k in PRIVATE_FIELDS:
        payload.pop(k, None)
    payload.update(b.get("extra") or {})
    return payload


def _openai_request(b, env, payload):
    hdrs = {"Content-Type": "application/json", "User-Agent": "kasiru/0.1"}
    hdrs.update(b.get("headers") or {})
    if b.get("key") and env.get(b["key"]):
        hdrs["Authorization"] = "Bearer " + env[b["key"]]
    return urllib.request.Request(b["url"].rstrip("/") + "/chat/completions", data=json.dumps(payload).encode(), headers=hdrs)


def _open(req, timeout):
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        msg = e.read().decode(errors="replace")
        raise Upstream(e.code, short_err(msg), _retry_after(msg))
    except Exception as e:  # noqa: BLE001
        raise Upstream(599, str(e))


def _strip_think(message):
    m = dict(message)
    if isinstance(m.get("content"), str):
        m["content"] = THINK.sub("", m["content"]).strip()
    m.pop("reasoning_content", None)
    m.pop("reasoning", None)
    return m


def call_openai(b, model, body, env):
    r = json.load(_open(_openai_request(b, env, _openai_payload(b, model, body, False)), b.get("timeout_s", 1800)))
    if isinstance(r, list):
        r = r[0]
    if "error" in r:
        raise Upstream(502, short_err(r["error"]))
    ch = r["choices"][0]
    u = r.get("usage") or {}
    res = Result(_strip_think(ch["message"]), ch.get("finish_reason"), u.get("prompt_tokens"), u.get("completion_tokens"))
    check_answer(res)
    return res


def stream_openai(b, model, body, env):
    """Generator of parsed SSE chunks (dicts). The last yielded item is ``{"_usage": {...}}`` when the provider reports it.
    Errors before the first chunk raise Upstream; errors after it propagate as-is (the client already received bytes)."""
    resp = _open(_openai_request(b, env, _openai_payload(b, model, body, True)), b.get("timeout_s", 1800))
    usage = None
    for raw in resp:
        line = raw.decode("utf-8", errors="replace").strip()
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            break
        try:
            chunk = json.loads(data)
        except ValueError:
            continue
        if chunk.get("usage"):
            usage = chunk["usage"]
        if chunk.get("choices"):
            yield chunk
    yield {"_usage": usage}


def call_ollama(b, model, body, ollama_url):
    body = cap_output(b, body)
    msgs = body.get("messages", [])
    chars = sum(len(str(m.get("content", ""))) for m in msgs)
    num_predict = int(body.get("max_tokens") or 8192)
    need = chars // 2 + num_predict + 1024
    num_ctx = next((c for c in (16384, 32768, 65536) if c >= need), 65536)   # steps: a new num_ctx reloads the model
    opts = {"temperature": body.get("temperature", 0.1), "num_predict": num_predict, "num_ctx": min(int(b.get("max_ctx", 65536)), num_ctx)}
    if body.get("repeat_penalty"):
        opts["repeat_penalty"] = body["repeat_penalty"]
    payload = {"model": model, "messages": msgs, "stream": False, "think": False, "options": opts}
    if body.get("tools"):
        payload["tools"] = body["tools"]
    req = urllib.request.Request((b.get("url") or ollama_url).rstrip("/") + "/api/chat", data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    r = json.load(_open(req, b.get("timeout_s", 7200)))
    msg = _strip_think(r.get("message") or {"role": "assistant", "content": ""})
    finish = "tool_calls" if msg.get("tool_calls") else ("length" if r.get("done_reason") == "length" else "stop")
    res = Result(msg, finish, r.get("prompt_eval_count"), r.get("eval_count"))
    check_answer(res)
    return res


def call(b, model, body, env, ollama_url=None):
    if b.get("kind") == "ollama":
        return call_ollama(b, model, body, ollama_url or "http://127.0.0.1:11434")
    return call_openai(b, model, body, env)
