"""Command line: ``kasiru serve | check | scrub | entities | report | init``."""
import argparse
import collections
import datetime as dt
import json
import os
import shutil
import statistics
import sys

from .config import CONF_DIR, STATE_DIR, Config


def _log(*a):
    print(dt.datetime.now().strftime("%F %T"), *a, flush=True)


def cmd_init(a):
    """Copy the example config, env and dictionary into the config directory (never overwrites)."""
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "examples")
    os.makedirs(CONF_DIR, exist_ok=True)
    for src, dst in (("kasiru.json", "kasiru.json"), ("env.example", "env"), ("entities.json", "entities.json")):
        target = os.path.join(CONF_DIR, dst)
        if os.path.exists(target):
            print("exists:", target)
            continue
        shutil.copy(os.path.join(here, src), target)
        os.chmod(target, 0o600)
        print("written:", target)
    print("edit %s, put API keys into %s, then: kasiru serve" % (os.path.join(CONF_DIR, "kasiru.json"), os.path.join(CONF_DIR, "env")))


def cmd_serve(a):
    from .server import serve
    serve(a.config, _log)


def cmd_check(a):
    cfg = Config(a.config)
    print("config ok: %d backends, tiers %s, clients %s" % (len(cfg.backends), ", ".join(cfg.tiers), ", ".join(cfg["clients"]) or "(none)"))
    for name, b in cfg.backends.items():
        key = b.get("key")
        flag = "local" if cfg.is_local(name) else ("key ok" if not key or cfg.env.get(key) else "KEY MISSING: " + key)
        print("  %-16s %-7s classes=%s %s" % (name, b.get("kind", "openai"), ",".join(b["classes"]), flag))
    from .privacy import Privacy
    p = Privacy(cfg.conf_dir, cfg.state_dir, cfg.privacy, log=lambda *x: None)
    print("detector: %s; dictionary: %d persons, %d orgs, %d terms; tokens: %s" % (
        p.ner_label, len(p.entities["persons"]), len(p.entities["orgs"]), len(p.entities["terms"]), p.tokens["counters"] or {}))


def cmd_scrub(a):
    """Show what a text looks like for the cloud. Uses a temporary state so the real token table is not touched."""
    import tempfile
    from .privacy import Privacy
    cfg = Config(a.config)
    text = open(a.file, encoding="utf-8").read() if a.file else sys.stdin.read()
    state = tempfile.mkdtemp(prefix="kasiru-scrub-")
    p = Privacy(cfg.conf_dir, state, cfg.privacy, log=lambda *x: None)
    out, rep = p.scrub(text, a.data_class, use_ner=not a.no_ner)
    print(out)
    print("---", json.dumps({k: rep[k] for k in ("replaced", "secret_lines", "secret_blocks", "ner_new")}, ensure_ascii=False), file=sys.stderr)
    shutil.rmtree(state, ignore_errors=True)


def cmd_entities(a):
    """Review the dictionary: pending hits wait for the owner's decision."""
    cfg = Config(a.config)
    path = cfg.entities_file
    e = json.load(open(path, encoding="utf-8")) if os.path.exists(path) else {}
    for k in ("persons", "orgs", "ignore", "auto"):
        e.setdefault(k, [])
    e.setdefault("pending", {"persons": [], "orgs": []})
    e.setdefault("terms", {})

    def save():
        from .privacy.store import save as _save
        _save(path, e)

    def numbered():
        return [(x, "persons") for x in e["pending"]["persons"]] + [(x, "orgs") for x in e["pending"]["orgs"]]

    def parse(spec):
        out = set()
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-")
                out.update(range(int(lo), int(hi) + 1))
            elif part:
                out.add(int(part))
        return out

    cmd = a.action
    if cmd == "summary":
        print("active: %d persons, %d orgs (%d auto); pending: %d / %d; ignore: %d" % (
            len(e["persons"]), len(e["orgs"]), len(e["auto"]), len(e["pending"]["persons"]), len(e["pending"]["orgs"]), len(e["ignore"])))
    elif cmd == "pending":
        for i, (x, k) in enumerate(numbered(), 1):
            print("%4d  %-7s %s" % (i, "person" if k == "persons" else "org", x))
    elif cmd == "auto":
        for i, x in enumerate(e["auto"], 1):
            print("%4d  %s" % (i, x))
    elif cmd in ("keep", "ignore", "drop"):
        rows = numbered()
        chosen = [rows[i - 1] for i in sorted(parse(a.spec)) if 0 < i <= len(rows)]
        for x, k in chosen:
            e["pending"][k].remove(x)
            if cmd == "keep" and x not in e[k]:
                e[k].append(x)
            if cmd == "ignore" and x not in e["ignore"]:
                e["ignore"].append(x)
        save()
        print("%s: %d entries" % (cmd, len(chosen)))
    elif cmd == "demote":
        chosen = [e["auto"][i - 1] for i in sorted(parse(a.spec)) if 0 < i <= len(e["auto"])]
        for x in chosen:
            e["auto"].remove(x)
            for k in ("persons", "orgs"):
                if x in e[k]:
                    e[k].remove(x)
            if x not in e["ignore"]:
                e["ignore"].append(x)
        save()
        print("demote -> ignore: %d" % len(chosen))
    elif cmd == "add":
        kind = {"person": "persons", "org": "orgs"}[a.spec]
        if a.name not in e[kind]:
            e[kind].append(a.name)
        save()
        print("added:", a.name)
    print("after changes: curl -s -X POST http://%s/v1/kasiru/reload" % cfg["listen"])


def cmd_report(a):
    cfg = Config(a.config)
    since = (dt.datetime.now() - dt.timedelta(days=a.days)).isoformat(timespec="seconds")
    rows = []
    try:
        for line in open(cfg.audit_file, encoding="utf-8"):
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("ts", "") >= since:
                rows.append(r)
    except FileNotFoundError:
        pass
    if not rows:
        print("no records for the period")
        return

    def key(r):
        return {"backend": str(r.get("backend")), "project": r.get("project") or "-", "client": r.get("client") or "-", "class": r.get("class"), "day": r["ts"][:10]}[a.by]

    agg = collections.defaultdict(lambda: {"n": 0, "in": 0, "out": 0, "cost": 0.0, "ms": [], "fail": 0, "leaks": 0, "replaced": 0, "secret_lines": 0})
    for r in rows:
        g = agg[key(r)]
        g["n"] += 1
        g["in"] += r.get("tokens_in") or 0
        g["out"] += r.get("tokens_out") or 0
        g["cost"] += r.get("cost") or 0
        g["ms"].append(r.get("ms") or 0)
        g["fail"] += 1 if r.get("error") else 0
        g["leaks"] += r.get("leaks") or 0
        g["replaced"] += sum((r.get("replaced") or {}).values())
        g["secret_lines"] += r.get("secret_lines") or 0
    print("audit, last %d days: %d requests since %s" % (a.days, len(rows), since[:16]))
    print("%-32s %6s %9s %9s %8s %7s %6s %6s %7s" % (a.by, "req", "in", "out", "$", "median", "fail", "leaks", "repl"))
    for k, g in sorted(agg.items(), key=lambda kv: -kv[1]["n"]):
        print("%-32s %6d %9d %9d %8.4f %6ds %6d %6d %7d" % (k[:32], g["n"], g["in"], g["out"], g["cost"], statistics.median(g["ms"]) / 1000, g["fail"], g["leaks"], g["replaced"]))
    local = sum(1 for r in rows if r.get("backend") and cfg.is_local(r["backend"]))
    cls = collections.Counter(r.get("class") for r in rows)
    print("\nclasses: %s | local: %d%% | secret lines kept local: %d | leaks: %d | cost: $%.4f" % (
        dict(cls), 100 * local // max(len(rows), 1), sum(r.get("secret_lines") or 0 for r in rows), sum(r.get("leaks") or 0 for r in rows), sum(r.get("cost") or 0 for r in rows)))
    skips = collections.Counter()
    for r in rows:
        for x in r.get("route", []):
            if x.get("skip"):
                skips[(x["backend"], x["skip"])] += 1
            if x.get("error"):
                skips[(x["backend"], "error " + " ".join(x["error"].split())[:40])] += 1
    if skips:
        print("\ncandidate skips / errors:")
        for (b, why), n in skips.most_common(8):
            print("  %-12s %-50s %d" % (b, why, n))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="kasiru", description="privacy-first gateway for LLM APIs")
    ap.add_argument("--config", help="path to kasiru.json (default: $KASIRU_CONF_DIR/kasiru.json)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="write example config into %s" % CONF_DIR).set_defaults(fn=cmd_init)
    sub.add_parser("serve", help="run the gateway").set_defaults(fn=cmd_serve)
    sub.add_parser("check", help="validate config, keys and the detector").set_defaults(fn=cmd_check)
    s = sub.add_parser("scrub", help="show a text as the cloud would see it")
    s.add_argument("file", nargs="?")
    s.add_argument("--data-class", default="personal", choices=("personal", "public"))
    s.add_argument("--no-ner", action="store_true")
    s.set_defaults(fn=cmd_scrub)
    e = sub.add_parser("entities", help="review the dictionary")
    e.add_argument("action", nargs="?", default="summary", choices=("summary", "pending", "auto", "keep", "ignore", "drop", "demote", "add"))
    e.add_argument("spec", nargs="?", help="numbers like 3,7-9; for add: person|org")
    e.add_argument("name", nargs="?")
    e.set_defaults(fn=cmd_entities)
    r = sub.add_parser("report", help="aggregate the audit log")
    r.add_argument("--days", type=int, default=7)
    r.add_argument("--by", choices=("backend", "project", "client", "class", "day"), default="backend")
    r.set_defaults(fn=cmd_report)
    a = ap.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
