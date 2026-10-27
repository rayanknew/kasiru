"""One request, seven stages: classify -> protect -> route -> call -> restore -> audit -> respond.

Each stage is a method on ``Pipeline`` so that behaviour can be read top to bottom and extended with plugins
(objects with any of ``before_protect(ctx)``, ``before_call(ctx, backend, model)``, ``after_call(ctx, result)``,
``after_restore(ctx)`` - see docs/plugins.md).
"""
import datetime as dt
import importlib
import json
import time

from . import backends as B
from .config import DATA_CLASSES


class Ctx:
    """Everything the stages share for one request."""

    def __init__(self, body, headers, client=None):
        self.body = body
        self.headers = headers
        self.client = client or {}
        self.client_name = headers.get("X-Client") or ""
        self.messages = body.get("messages") or []
        self.cloud_messages = self.messages
        self.secret_parts = []
        self.candidates = []
        self.result = None
        self.backend = self.model = None
        self.rec = {"ts": dt.datetime.now().isoformat(timespec="seconds"), "client": self.client_name,
                    "replaced": {}, "secret_lines": 0, "route": [], "ner_new": 0}
        self.t0 = time.time()


class Pipeline:
    def __init__(self, config, router, privacy, audit, log=print):
        self.cfg, self.router, self.privacy, self.audit, self.log = config, router, privacy, audit, log
        self.plugins = []
        for spec in config.get("plugins") or []:
            mod, _, cls = spec.partition(":")
            obj = getattr(importlib.import_module(mod), cls) if cls else importlib.import_module(mod)
            self.plugins.append(obj() if isinstance(obj, type) else obj)

    def _hook(self, name, *a):
        for p in self.plugins:
            fn = getattr(p, name, None)
            if fn:
                fn(*a)

    # ---------- 1. classify ----------
    def classify(self, ctx):
        h, body, c = ctx.headers, ctx.body, ctx.client
        data_class = (c.get("class") or h.get("X-Data-Class") or body.get("data_class") or c.get("default_class") or self.cfg["default_class"]).lower()
        if data_class not in DATA_CLASSES:
            data_class = "personal"
        ctx.data_class = data_class
        ctx.stage = h.get("X-Stage") or body.get("stage") or ""
        ctx.project = h.get("X-Project") or body.get("project") or ctx.client_name or ""
        ctx.secret_mode = (h.get("X-Secret-Mode") or body.get("secret_mode") or c.get("secret_mode") or "local").lower()
        ctx.model_req = body.get("model") or c.get("default_tier") or "good"
        ctx.rec.update(stage=ctx.stage, project=ctx.project, **{"class": data_class, "model_req": ctx.model_req})
        ctx.candidates = self.router.candidates(ctx.model_req, data_class)

    # ---------- 2. protect ----------
    def protect(self, ctx):
        self._hook("before_protect", ctx)
        cloud_possible = any(not self.router.is_local(bk) for bk, _ in ctx.candidates)
        if ctx.data_class == "secret" or not cloud_possible:
            return
        tn = time.time()
        use_ner = self.cfg.privacy.get("ner") != "off" and ctx.data_class in (self.cfg.privacy.get("ner_classes") or ["personal"])
        ctx.cloud_messages, rep, ctx.secret_parts = self.privacy.scrub_messages(ctx.messages, ctx.data_class, use_ner)
        ctx.rec["replaced"] = rep["replaced"]
        ctx.rec["secret_lines"] = rep["secret_lines"]
        ctx.rec["ner_new"] = rep["ner_new"]
        if rep.get("ner_error"):
            ctx.rec["ner_error"] = rep["ner_error"]
        self.log("[%s] protect %.1fs: replaced %s, new names %d, secret parts %d" % (ctx.stage, time.time() - tn, rep["replaced"], rep["ner_new"], ctx.rec["secret_lines"]))
        if ctx.secret_parts and ctx.secret_mode != "split":
            # secret markup inside -> the whole request stays local, unscrubbed
            ctx.candidates = [c for c in ctx.candidates if self.router.is_local(c[0])] or [self.router.local_default()]
            ctx.cloud_messages = ctx.messages
            ctx.secret_parts = []
            ctx.rec["forced_local"] = "secret markers"

    # ---------- 3 + 4. route and call ----------
    def _call_one(self, ctx, backend, model, body):
        b = self.cfg.backends[backend]
        sem = self.router.slot(backend)
        if sem is not None and not sem.acquire(timeout=b.get("queue_timeout_s", 600)):
            raise B.Upstream(503, "backend busy (max_parallel)")
        try:
            self._hook("before_call", ctx, backend, model)
            return B.call(b, model, body, self.cfg.env, self.cfg.get("ollama_url"))
        finally:
            if sem is not None:
                sem.release()

    def route_and_call(self, ctx):
        body = ctx.body
        queue = list(ctx.candidates)
        i = 0
        err = None
        retried = set()
        while i < len(queue):
            backend, model = queue[i]
            i += 1
            ok, why = self.router.available(backend)
            if not ok:
                ctx.rec["route"].append({"backend": backend, "skip": why})
                self.log("[%s] %s: skip (%s)" % (ctx.stage, backend, why))
                continue
            b = self.cfg.backends[backend]
            local = self.router.is_local(backend)
            use_msgs = ctx.messages if local else ctx.cloud_messages
            if not local and body.get("tools") and ctx.data_class != "public" and not b.get("allow_tools"):
                ctx.rec["route"].append({"backend": backend, "skip": "tools not allowed for this class"})
                continue
            if not local and ctx.data_class != "public":
                leaks = self.privacy.leak_check(json.dumps(use_msgs, ensure_ascii=False))   # the barrier BEFORE sending
                if leaks:
                    ctx.rec["route"].append({"backend": backend, "skip": "leak %d" % leaks})
                    ctx.rec["forced_local"] = "leak"
                    self.log("[%s] %s: skip (%d values left in clear text - local only): %s" % (ctx.stage, backend, leaks, ", ".join(self.privacy.last_leaks[:5])))
                    continue
            try:
                t1 = time.time()
                self.log("[%s] -> %s:%s (%s, %d chars)" % (ctx.stage, backend, model, ctx.data_class, sum(len(str(m.get("content", ""))) for m in use_msgs)))
                res = self._call_one(ctx, backend, model, dict(body, messages=use_msgs))
                bad = B.degenerate(res.text) if not res.message.get("tool_calls") else None
                if bad:
                    self.router.account(backend, res.tokens_in, res.tokens_out, 0)
                    raise B.Upstream(498, bad)
                cost = self.router.price(backend, model, res.tokens_in, res.tokens_out)
                self.router.account(backend, res.tokens_in, res.tokens_out, cost)
                ctx.rec["route"].append({"backend": backend, "model": model, "ms": int((time.time() - t1) * 1000), "in": res.tokens_in, "out": res.tokens_out, "finish": res.finish})
                ctx.rec.update(backend=backend, model=model, tokens_in=res.tokens_in, tokens_out=res.tokens_out, cost=round(cost, 6), finish=res.finish)
                ctx.backend, ctx.model, ctx.result = backend, model, res
                self._hook("after_call", ctx, res)
                self.log("[%s] ok %s:%s %dms in %s out %s" % (ctx.stage, backend, model, ctx.rec["route"][-1]["ms"], res.tokens_in, res.tokens_out))
                return
            except B.Upstream as e:
                err = "%s %s" % (e.code, str(e)[:200])
                ctx.rec["route"].append({"backend": backend, "model": model, "error": err})
                self.log("[%s] fail %s: %s" % (ctx.stage, backend, err[:120]))
                if e.code == 429:
                    self.router.cooldown(backend, max(e.retry_after, b.get("cooldown_s", 300)))
                elif e.code == 498 and local and (backend, model, "loop") not in retried:
                    retried.add((backend, model, "loop"))
                    queue.insert(i, (backend, model))
                    body = dict(body, temperature=max(float(body.get("temperature", 0.1)), 0.6), repeat_penalty=1.25, frequency_penalty=0.5)
                    self.log("[%s] %s: retry with anti-repeat settings" % (ctx.stage, backend))
                elif e.code == 599:
                    if (backend, model) not in retried and not local:
                        retried.add((backend, model))
                        queue.insert(i, (backend, model))
                elif e.code in (502, 503, 529) and not local and (backend, model, "transient") not in retried:
                    retried.add((backend, model, "transient"))
                    queue.insert(i, (backend, model))
                    time.sleep(7)
                elif e.code >= 500:
                    self.router.cooldown(backend, b.get("cooldown_s", 300))
                continue
        ctx.error = err or "no backend available"

    # ---------- 5. restore ----------
    def restore(self, ctx):
        res = ctx.result
        if not self.router.is_local(ctx.backend):
            ctx.rec["leaks"] = 0
            res.message = self.privacy.unscrub_message(res.message)
        if ctx.secret_parts:
            self._secret_part(ctx)
        self._hook("after_restore", ctx)

    def _secret_part(self, ctx):
        """Split mode: the secret lines go to the local model separately and are appended to the answer."""
        sysm = [m for m in ctx.messages if m.get("role") == "system"]
        secret_chars = sum(len(p) for p in ctx.secret_parts)
        loc_body = {"messages": sysm + [{"role": "user", "content": "\n".join(ctx.secret_parts)}],
                    "max_tokens": min(int(ctx.body.get("max_tokens", 4096)), max(512, secret_chars // 2))}
        lb, lm = self.router.local_default()
        try:
            ts = time.time()
            r = self._call_one(ctx, lb, lm, loc_body)
            c = ctx.result.message.get("content") or ""
            ctx.result.message["content"] = c + "\n\n### Secret part (processed locally)\n\n" + r.text
            ctx.rec["route"].append({"backend": lb, "model": lm, "in": r.tokens_in, "out": r.tokens_out, "secret_part": True, "ms": int((time.time() - ts) * 1000)})
        except B.Upstream as e:
            ctx.rec["secret_error"] = str(e)[:120]

    # ---------- 6 + 7. audit and respond ----------
    def respond(self, ctx):
        ctx.rec["ms"] = int((time.time() - ctx.t0) * 1000)
        if ctx.result is None:
            ctx.rec["error"] = ctx.error
            self.audit.write(ctx.rec)
            return 503, {"error": {"message": "all backends unavailable: " + ctx.error, "type": "kasiru_no_backend", "route": ctx.rec["route"]}}
        self.audit.write(ctx.rec)
        res = ctx.result
        resp = {"id": "kasiru-%d" % int(ctx.t0 * 1000), "object": "chat.completion", "created": int(ctx.t0), "model": "%s:%s" % (ctx.backend, ctx.model),
                "choices": [{"index": 0, "message": res.message, "finish_reason": res.finish or "stop"}],
                "usage": {"prompt_tokens": res.tokens_in or 0, "completion_tokens": res.tokens_out or 0, "total_tokens": (res.tokens_in or 0) + (res.tokens_out or 0)},
                "kasiru": {k: ctx.rec[k] for k in ("class", "backend", "model", "replaced", "secret_lines", "route", "cost", "ms", "forced_local") if k in ctx.rec}}
        return 200, resp

    def handle(self, body, headers, client=None):
        ctx = Ctx(body, headers, client)
        self.classify(ctx)
        self.protect(ctx)
        self.route_and_call(ctx)
        if ctx.result is not None:
            self.restore(ctx)
        return self.respond(ctx)

    # ---------- streaming ----------
    def can_stream(self, body, headers, client=None):
        """True pass-through streaming is possible when every candidate is local: nothing to restore, nothing to retry
        after the first bytes. Otherwise the answer is collected and sent as one chunk."""
        ctx = Ctx(body, headers, client)
        self.classify(ctx)
        return all(self.router.is_local(bk) for bk, _ in ctx.candidates)

    def stream(self, body, headers, client=None):
        """Generator of SSE chunk dicts for an all-local route; raises Upstream if no local backend answers."""
        ctx = Ctx(body, headers, client)
        self.classify(ctx)
        err = None
        for backend, model in ctx.candidates:
            ok, why = self.router.available(backend)
            if not ok:
                ctx.rec["route"].append({"backend": backend, "skip": why})
                continue
            b = self.cfg.backends[backend]
            if b.get("kind") == "ollama":
                ctx.rec["route"].append({"backend": backend, "skip": "ollama kind does not stream through kasiru; use an openai-kind local backend"})
                continue
            sem = self.router.slot(backend)
            if sem is not None and not sem.acquire(timeout=b.get("queue_timeout_s", 600)):
                ctx.rec["route"].append({"backend": backend, "error": "503 busy"})
                continue
            t1 = time.time()
            try:
                gen = B.stream_openai(b, model, body, self.cfg.env)
                first = next(gen)          # errors before the first chunk are retryable
            except B.Upstream as e:
                if sem is not None:
                    sem.release()
                err = "%s %s" % (e.code, str(e)[:200])
                ctx.rec["route"].append({"backend": backend, "model": model, "error": err})
                if e.code == 429:
                    self.router.cooldown(backend, max(e.retry_after, b.get("cooldown_s", 300)))
                continue
            except StopIteration:
                if sem is not None:
                    sem.release()
                continue
            try:
                usage = None
                for chunk in self._iter(first, gen):
                    if "_usage" in chunk:
                        usage = chunk["_usage"]
                        continue
                    yield chunk
            finally:
                if sem is not None:
                    sem.release()
                u = usage or {}
                tin, tout = u.get("prompt_tokens"), u.get("completion_tokens")
                self.router.account(backend, tin, tout, 0)
                ctx.rec["route"].append({"backend": backend, "model": model, "ms": int((time.time() - t1) * 1000), "in": tin, "out": tout, "stream": True})
                ctx.rec.update(backend=backend, model=model, tokens_in=tin, tokens_out=tout, cost=0, ms=int((time.time() - ctx.t0) * 1000))
                self.audit.write(ctx.rec)
            return
        ctx.rec["ms"] = int((time.time() - ctx.t0) * 1000)
        ctx.rec["error"] = err or "no local backend available"
        self.audit.write(ctx.rec)
        raise B.Upstream(503, ctx.rec["error"])

    @staticmethod
    def _iter(first, gen):
        yield first
        for c in gen:
            yield c
