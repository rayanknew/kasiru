"""Routing state: candidates for a tier, daily quotas, cool-downs, per-backend concurrency.

A tier is an ordered list of ``backend:model`` candidates. The local backend from ``tiers.local[0]`` is always appended,
so the system degrades into "slow" and never into "unavailable". A candidate is skipped when the data class is not allowed,
the key is missing, a daily limit (requests / tokens / cost) is spent, or the backend is cooling down after 429 / 5xx.
"""
import datetime as dt
import json
import os
import threading
import time


class Router:
    def __init__(self, config, log=print):
        self.cfg = config
        self.log = log
        self._lock = threading.RLock()
        self._sems = {}
        self.quota_path = os.path.join(config.state_dir, "quota.json")
        try:
            with open(self.quota_path, encoding="utf-8") as f:
                self.quota = json.load(f)
        except Exception:  # noqa: BLE001
            self.quota = {"days": {}, "cooldown": {}}
        self.quota.setdefault("days", {})
        self.quota.setdefault("cooldown", {})

    # ---- quotas ----
    def _day(self, backend):
        today = dt.date.today().isoformat()
        return self.quota["days"].setdefault(today, {}).setdefault(backend, {"requests": 0, "tokens": 0, "cost": 0.0})

    def available(self, backend):
        b = self.cfg.backends[backend]
        if time.time() < self.quota["cooldown"].get(backend, 0):
            return False, "cooling down after an error"
        if b.get("kind", "openai") == "openai" and b.get("key") and not self.cfg.env.get(b["key"]):
            return False, "no key %s" % b["key"]
        with self._lock:
            d = dict(self._day(backend))
        if b.get("daily_requests") and d["requests"] >= b["daily_requests"]:
            return False, "daily request limit"
        if b.get("daily_tokens") and d["tokens"] >= b["daily_tokens"]:
            return False, "daily token limit"
        if b.get("daily_cost") and d["cost"] >= b["daily_cost"]:
            return False, "daily budget $%.2f spent" % b["daily_cost"]
        return True, ""

    def account(self, backend, tin, tout, cost):
        with self._lock:
            d = self._day(backend)
            d["requests"] += 1
            d["tokens"] += (tin or 0) + (tout or 0)
            d["cost"] += cost
            for day in sorted(self.quota["days"])[:-14]:
                del self.quota["days"][day]
            self._save()

    def cooldown(self, backend, seconds):
        with self._lock:
            self.quota["cooldown"][backend] = time.time() + seconds
            self._save()

    def _save(self):
        tmp = self.quota_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.quota, f, indent=1)
        os.replace(tmp, self.quota_path)

    def price(self, backend, model, tin, tout):
        b = self.cfg.backends[backend]
        pr = (b.get("prices") or {}).get(model) or {}
        return ((tin or 0) * pr.get("in", b.get("price_in", 0)) + (tout or 0) * pr.get("out", b.get("price_out", 0))) / 1e6

    # ---- concurrency ----
    def slot(self, backend):
        """A semaphore per backend when ``max_parallel`` is configured (a single-slot local server queues instead of failing)."""
        b = self.cfg.backends[backend]
        n = b.get("max_parallel")
        if not n:
            return None
        with self._lock:
            if backend not in self._sems:
                self._sems[backend] = threading.BoundedSemaphore(int(n))
            return self._sems[backend]

    # ---- candidates ----
    def is_local(self, backend):
        return self.cfg.is_local(backend)

    def local_default(self):
        return tuple(self.cfg.tiers["local"][0].split(":", 1))

    def candidates(self, model_req, data_class):
        """-> [(backend, model)] in order of attempts."""
        tiers, backends = self.cfg.tiers, self.cfg.backends
        local_default = self.cfg.tiers["local"][0]
        if model_req in tiers:
            cands = list(tiers[model_req])
        elif ":" in model_req and model_req.split(":", 1)[0] in backends:
            cands = [model_req]
        else:
            lb = local_default.split(":", 1)[0]
            cands = [lb + ":" + model_req]        # a bare model name means a model on the default local backend
        if local_default not in cands:
            cands.append(local_default)
        out = []
        for c in cands:
            backend, model = c.split(":", 1)
            b = backends.get(backend)
            if not b or data_class not in b.get("classes", []):
                continue
            out.append((backend, model))
        return out or [self.local_default()]

    def stats(self):
        today = dt.date.today().isoformat()
        return {"today": self.quota["days"].get(today, {}),
                "cooldown": {k: int(v - time.time()) for k, v in self.quota["cooldown"].items() if v > time.time()},
                "tiers": self.cfg.tiers}
