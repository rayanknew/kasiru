"""The privacy layer: what may leave the machine and in which form.

Data classes: ``secret`` - local models only; ``personal`` - to the cloud after reversible pseudonymisation;
``public`` - as is (only the secret markup is cut out).

Pseudonymisation is reversible and persistent: token <-> value lives in ``<state>/tokens.json``; one entity is one
token in every request, so a cloud model still sees who talks to whom, and the answer is restored verbatim.

Layers:
 1. patterns + validators      e-mail, phones, cards, IBAN, crypto wallets, access keys, seed phrases, addresses, ...
 2. the owner's dictionary     ``<conf>/entities.json``: persons, orgs, terms, ignore, pending, auto - matched by lemma
 3. local entity detector      Natasha (ru) + spaCy (uk) on CPU, or a local LLM; new names join the dictionary
 4. secret markup              lines with ``[secret]`` and ``<secret>...</secret>`` blocks never go to an external API

After the answer: ``unscrub()`` restores the values; before sending: ``leak_check()`` confirms nothing active is left in
clear text. Every filter is symmetric: what the substitution cannot find, the leak check does not count as a leak.
"""
import hashlib
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request

from . import lemma as _lemma_mod
from . import patterns as P
from .store import load as _load, save as _save

try:
    from . import ner_ru
    try:
        from . import ner_uk
    except Exception:  # noqa: BLE001
        ner_uk = None
except Exception:  # noqa: BLE001
    ner_ru = None
    ner_uk = None

_lock = threading.RLock()
SECRET_BLOCK = re.compile(r"<secret>.*?</secret>", re.S | re.I)
LEGAL = re.compile(r"\b(ТОВ|ООО|ФОП|ФЛП|ПП|АТ|ЗАТ|ПрАТ|LLC|Ltd|Inc|GmbH|S\.?A\.?|LLP|OÜ|s\.r\.o\.)\b", re.I)
ORG_LEGAL_RX = re.compile(r"\b(ТОВ|ООО|ФОП|ФЛП|ПП|АТ|ЗАТ|ПрАТ|ТзОВ|ЧП|ИП|LLC|Ltd|Inc|GmbH)\s*(?:[«\"]([^»\"\n]{2,40})[»\"]|((?:[A-ZА-ЯЁІЇЄҐ][\w&.'-]+)(?:\s+[A-ZА-ЯЁІЇЄҐ][\w&.'-]+){0,2}))")
PERSON_FIO_RX = re.compile(r"\b([А-ЯЁІЇЄҐ][а-яёіїєґ']{2,}\s+[А-ЯЁІЇЄҐ][а-яёіїєґ']+(?:ович|евич|ьович|йович|овна|евна|ївна|івна|ична|инична)\s+[А-ЯЁІЇЄҐ][а-яёіїєґ'-]{2,})\b")
TOKEN_LIKE = re.compile(r"^\[?[^\W\d_]+[-\s]?\d*\]?$", re.U)
GENERIC = {"mom", "dad", "brother", "sister", "wife", "husband", "son", "daughter", "friend", "colleague", "director", "client",
           "mail", "bank", "company", "office", "shop", "school", "clinic", "market", "site", "phone",
           "мама", "папа", "брат", "сестра", "жена", "муж", "сын", "дочь", "автор", "пацаны", "друг", "коллега", "директор", "клиент",
           "почта", "банк", "компания", "фирма", "отдел", "офис", "магазин", "школа", "клиника", "рынок", "сайт", "телефон",
           "бог", "аллах", "коран", "библия", "инвест", "крипто", "таргет", "альфа", "скорпион", "акулы", "винда", "линукс"}


def fold(s):
    return s.lower().replace("ё", "е")


def stem(word):
    """Crude stem for word-form search without morphology: Виталий -> Витали."""
    w = word.strip()
    if len(w) <= 4 or not re.search(r"[А-Яа-яЁё]", w):
        return w
    return w[: max(4, len(w) - 2)]


def _morph_bad(x, kind="persons"):
    """Any Cyrillic word of a detector hit is known to the morphology as a non-name (verb form, participle, common noun)."""
    return any(_lemma_mod.word_bad(w, kind) for w in re.findall(r"[А-ЯЁа-яё][А-ЯЁа-яё\-]+", x))


def strong(name, kind):
    """A confident hit: a person = first and last name (2+ capitalised words); an org = legal form or 2+ words."""
    if re.search(r"[,;/()\[\]{}|]", name):
        return False
    words = [w for w in re.split(r"[\s]+", name.strip()) if w]
    caps = [w for w in words if w[:1].isupper()]
    if kind == "persons":
        return len(words) >= 2 and len(caps) >= 2 and all(len(w) > 1 for w in words)
    return bool(LEGAL.search(name)) or (len(words) >= 2 and len(caps) >= 1)


def rule_entities(text):
    """Deterministic rules, no models: LLC "Name", ООО Name, First Patronymic Last."""
    orgs = [(m.group(1) + " " + (m.group(2) or m.group(3))).strip() for m in ORG_LEGAL_RX.finditer(text)]
    persons = [m.group(1) for m in PERSON_FIO_RX.finditer(text)]
    return {"persons": list(dict.fromkeys(persons)), "orgs": list(dict.fromkeys(orgs))}


def _prekey(term):
    return fold(stem(term.split()[0])) if term.split() else ""


def _esc(w):
    """ё and е are interchangeable in dictionary regexes."""
    return re.sub(r"[еёЕЁ]", lambda m: "[её]" if m.group(0).islower() else "[ЕЁ]", re.escape(w))


def _rx_word(p, morph_known):
    """One word of a term: known to the morphology -> exact form (inflections are found by lemma in find_terms);
    unknown (surnames, Latin) -> stem without the last letter plus up to three letters of ending."""
    if morph_known(p) or len(p) <= 4:
        return _esc(p)
    return _esc(p[:-1]) + r"[а-яёА-ЯЁa-zA-Z]{0,3}"


def term_regex(term, morph_known=lambda w: False):
    parts = [_rx_word(p, morph_known) for p in term.split()]
    return re.compile(r"(?<![\w-])" + r"[\s«»\"']+".join(parts) + r"(?![\w-])", re.I)


class Privacy:
    """One instance per process. ``conf_dir`` holds entities.json, ``state_dir`` holds tokens.json and ner_cache.json."""

    def __init__(self, conf_dir, state_dir, options=None, log=print):
        o = dict(options or {})
        self.log = log
        self.entities_path = os.path.join(conf_dir, "entities.json")
        self.tokens_path = os.path.join(state_dir, "tokens.json")
        self.cache_path = os.path.join(state_dir, "ner_cache.json")
        self.ollama_url = o.get("ollama_url") or "http://127.0.0.1:11434"
        self.ner_model = o.get("ner_model")
        self.protect_all = bool(o.get("protect_all", True))
        self.labels = dict(o.get("token_labels") or {})
        self.phone_regions = tuple(o.get("phone_regions") or ("US", "GB", "DE", "UA", "RU", "TR"))
        self.generic = GENERIC | {w.lower() for w in (o.get("generic_words") or [])}
        markers = o.get("secret_markers") or ["[secret]"]
        self.secret_line = re.compile("|".join(re.escape(m) for m in markers), re.I)
        ner = o.get("ner", "auto")
        if ner == "auto":
            ner = "natasha" if (ner_ru and ner_ru.available()) else ("ollama" if self.ner_model else "off")
        self.ner_backend = ner
        self.ner_uk = bool(ner == "natasha" and ner_uk is not None and ner_uk.available())
        self.ner_label = ner + ("+uk" if self.ner_uk else "")
        self.tokens = _load(self.tokens_path, {"map": {}, "counters": {}})
        self.ner_cache = _load(self.cache_path, {})
        self.last_leaks = []
        self.reload_entities()

    # ---------- dictionary ----------
    def _morph_known(self, w):
        try:
            a = _lemma_mod.analyze(w)
            return a["lang"] in ("ru", "uk") and a["known"] and ner_ru is not None and ner_ru.available()
        except Exception:  # noqa: BLE001
            return False

    def reload_entities(self):
        e = _load(self.entities_path, {})
        self.entities = {"persons": list(dict.fromkeys(e.get("persons", []))), "orgs": list(dict.fromkeys(e.get("orgs", []))),
                         "terms": dict(e.get("terms", {})), "pending": e.get("pending", {"persons": [], "orgs": []}),
                         "ignore": list(e.get("ignore", [])), "auto": list(e.get("auto", []))}
        self.entities["pending"].setdefault("persons", [])
        self.entities["pending"].setdefault("orgs", [])
        rx = lambda t: term_regex(t, self._morph_known)  # noqa: E731
        self._compiled = []
        for t in self.entities["persons"]:
            if len(t) < 3:
                continue
            self._compiled.append((t, "person", rx(t), _prekey(t)))
            last = t.split()[-1]
            if len(t.split()) >= 2 and len(last) >= 5:            # the surname alone is the same person
                self._compiled.append((t, "person", rx(last), _prekey(last)))
        for t in self.entities["orgs"]:
            if len(t) < 3:
                continue
            self._compiled.append((t, "org", rx(t), _prekey(t)))
            bare = LEGAL.sub("", t).strip(" «»\"")
            if bare and bare != t and len(bare) >= 4:              # the name without its legal form
                self._compiled.append((t, "org", rx(bare), _prekey(bare)))
        self._compiled += [(t, "term", rx(t), _prekey(t)) for t in self.entities["terms"] if len(t) >= 3]
        self._compiled.sort(key=lambda x: -len(x[0]))              # longest first: "Иван Петров" before "Иван"

    def save_entities(self):
        _save(self.entities_path, self.entities)

    # ---------- tokens ----------
    def _token(self, kind, canonical, value=None):
        with _lock:
            for tok, rec in self.tokens["map"].items():
                if rec["kind"] == kind and fold(rec["canonical"]) == fold(canonical):
                    return tok
            n = self.tokens["counters"].get(kind, 0) + 1
            self.tokens["counters"][kind] = n
            tok = "[%s-%d]" % (self.labels.get(kind, kind), n)
            self.tokens["map"][tok] = {"kind": kind, "canonical": canonical, "value": value or canonical, "created": time.strftime("%F")}
            _save(self.tokens_path, self.tokens)
            return tok

    def _token_items(self):
        with _lock:
            return list(self.tokens["map"].items())

    # ---------- layer 3: detector ----------
    def ner(self, text, chunk=30000):
        if self.ner_backend == "off":
            return {"persons": [], "orgs": []}
        if self.ner_backend == "natasha":
            h = hashlib.sha256(text.encode()).hexdigest()[:24]
            if h in self.ner_cache:
                return self.ner_cache[h]
            r = ner_ru.detect(text) or {"persons": [], "orgs": []}
            if ner_uk is not None and self.ner_uk:
                ru = ner_uk.detect(text) or {}
                locs = {x.lower() for x in ru.get("locs", [])}
                for k in ("persons", "orgs"):
                    r[k] = [x for x in dict.fromkeys(list(r.get(k, [])) + list(ru.get(k, []))) if x.lower() not in locs]
                r["locs"] = sorted(locs)
            r = {k: [x for x in r.get(k, []) if self._plausible(x, k)] for k in ("persons", "orgs")}
            self.ner_cache[h] = r
            _save(self.cache_path, self.ner_cache)
            return r
        if not self.ner_model:
            return {"persons": [], "orgs": []}
        found = {"persons": [], "orgs": []}
        for i in range(0, len(text), chunk):
            part = text[i:i + chunk]
            h = hashlib.sha256(part.encode()).hexdigest()[:24]
            if h in self.ner_cache:
                r = self.ner_cache[h]
            else:
                r = self._ner_call(part)
                self.ner_cache[h] = r
                _save(self.cache_path, self.ner_cache)
            for k in found:
                found[k] += [x for x in r.get(k, []) if isinstance(x, str) and 2 < len(x) < 60]
        return {k: list(dict.fromkeys(v)) for k, v in found.items()}

    def _stem_known(self, x):
        st = {fold(stem(w)) for w in x.split()}
        for lst in (self.entities["persons"], self.entities["orgs"], self.entities["ignore"], self.entities["pending"]["persons"], self.entities["pending"]["orgs"]):
            for y in lst:
                ys = {fold(stem(w)) for w in y.split()}
                if ys == st or (len(st) == 1 and len(ys) > 1 and st <= ys):
                    return True
        return False

    def _plausible(self, x, kind):
        """Junk filter for detector hits: tokens, too short, lower-case, numbers, generic words, already known."""
        if len(x) < 4 or len(x) > 60 or x.lower() in {w.lower() for w in self.entities["ignore"]}:
            return False
        if TOKEN_LIKE.match(x.strip()) and re.search(r"\d", x) or x.lower().strip("[]") in self.generic or x.lower().split()[0] in self.generic:
            return False
        if re.search(r"[,;()\[\]{}|]", x):
            return False
        if self._stem_known(x):
            return False
        if not re.search(r"[А-ЯЁA-ZІЇЄҐ]", x):
            return False
        if re.fullmatch(r"[\d\W_]+", x) or x.lstrip().startswith("#"):
            return False
        if _morph_bad(x, kind):
            return False
        return True

    def _ner_call(self, part):
        prompt = ("Find mentions in the text below that identify specific private individuals.\n"
                  "persons - names, surnames, patronymics, nicknames (each in base form as it appears in the text).\n"
                  "orgs - only small companies and organisations the author personally deals with: counterparties, own firms, clients, "
                  "contractors, schools, clinics. Do NOT include well-known brands, services, software and platforms, "
                  "product brands, cities, countries, currencies, generic words.\n"
                  "At most 25 entries per list. Answer strictly as JSON {\"persons\": [\"...\"], \"orgs\": [\"...\"]} without explanations.\n\nTEXT:\n" + part)
        body = {"model": self.ner_model, "prompt": prompt, "stream": False, "format": "json", "think": False,
                "options": {"temperature": 0, "num_predict": 3000, "num_ctx": 32768 if len(part) // 2 + 4000 > 16384 else 16384}}
        try:
            try:
                req = urllib.request.Request(self.ollama_url + "/api/generate", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
                r = json.load(urllib.request.urlopen(req, timeout=600))
            except urllib.error.HTTPError as e:
                if e.code != 501:
                    raise
                body.pop("format", None)
                req = urllib.request.Request(self.ollama_url + "/api/generate", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
                r = json.load(urllib.request.urlopen(req, timeout=600))
            raw = r.get("response") or "{}"
            m = re.search(r"\{.*\}", raw, re.S)
            raw = m.group(0) if m else raw
            try:
                out = json.loads(raw)
            except ValueError:
                out = {}
                for key in ("persons", "orgs"):
                    m = re.search(r'"%s"\s*:\s*\[(.*?)(?:\]|$)' % key, raw, re.S)
                    out[key] = re.findall(r'"([^"\n]{3,60})"', m.group(1)) if m else []
            return {k: [x for x in (str(v).strip() for v in out.get(k, []) if v) if self._plausible(x, k)][:25] for k in ("persons", "orgs")}
        except Exception as e:  # noqa: BLE001  - the detector must never fail the request; the audit records the error
            self.log("ner error: %s" % e)
            return {"persons": [], "orgs": [], "error": str(e)}

    # ---------- main pass ----------
    def scrub(self, text, data_class="personal", use_ner=True, secret_markers=True):
        """-> (text for the cloud, report). For ``public`` returns the text as is (only the secret markup is removed).
        secret_markers=False: do not extract marker lines (system prompts, where the marker is an instruction, not data)."""
        rep = {"class": data_class, "replaced": {}, "secret_lines": 0, "secret_blocks": 0, "ner_new": 0, "ner_error": None}
        blocks = SECRET_BLOCK.findall(text) if secret_markers else []
        rep["secret_blocks"] = len(blocks)
        if blocks:
            text = SECRET_BLOCK.sub("[redacted]", text)
        kept = [l for l in text.split("\n") if self.secret_line.search(l)] if secret_markers else []
        rep["secret_lines"] = len(kept)
        if kept:
            text = "\n".join(l for l in text.split("\n") if not self.secret_line.search(l))
        rep["secret"] = kept + blocks
        if data_class == "public":
            return text, rep

        def count(kind):
            rep["replaced"][kind] = rep["replaced"].get(kind, 0) + 1

        # layer 1
        for a_, b_ in reversed(P.find_seeds(text)):
            count("seed")
            text = text[:a_] + self._token("seed", text[a_:b_]) + text[b_:]
        for kind, rx in P.PATTERNS:
            text = rx.sub(lambda m, kind=kind: (count(kind), self._token(kind, m.group(0)))[1] if P.valid(kind, m.group(0)) else m.group(0), text)
        phones = P.find_phones(text, self.phone_regions)
        if phones is None:
            text = P.PHONE.sub(lambda m: (count("phone"), self._token("phone", m.group(0)))[1] if P.looks_like_phone(m.group(0)) else m.group(0), text)
        else:
            for (a_, b_), raw in reversed(phones):
                count("phone")
                text = text[:a_] + self._token("phone", raw) + text[b_:]
        # layer 3 feeds the dictionary, then layer 2 runs in one pass
        if use_ner and self.ner_backend != "off":
            r = self.ner(text)
            rr = rule_entities(text)
            locs = set(r.get("locs") or [])
            for k in ("persons", "orgs"):
                r[k] = list(dict.fromkeys(list(r.get(k, [])) + [x for x in rr[k] if self._plausible(x, k) and x.lower() not in locs]))
            rep["ner_error"] = r.get("error")
            known = {fold(x) for lst in (self.entities["persons"], self.entities["orgs"], self.entities["ignore"],
                                          self.entities["pending"]["persons"], self.entities["pending"]["orgs"]) for x in lst}
            new = 0
            for k, kind in (("persons", "persons"), ("orgs", "orgs")):
                for name in r.get(k, []):
                    if fold(name) in known or self._stem_known(name):
                        continue
                    known.add(fold(name))
                    new += 1
                    if strong(name, kind) or self.protect_all:
                        self.entities[kind].append(name)
                        self.entities.setdefault("auto", []).append(name)
                    else:                        # a weak hit waits for the owner's decision and is not replaced
                        self.entities["pending"].setdefault(kind, []).append(name)
            if new:
                rep["ner_new"] = new
                self.save_entities()
                self.reload_entities()
        # layer 2: by lemma (morphology), then by stem regex (Latin, quotes, no morphology)
        if self.ner_backend == "natasha" and ner_ru is not None:
            terms = [(t, "person") for t in self.entities["persons"]] + [(t, "org") for t in self.entities["orgs"]] + [(t, "term") for t in self.entities["terms"]]
            terms += [(t.split()[-1], "person") for t in self.entities["persons"] if len(t.split()) >= 2 and len(t.split()[-1]) >= 5]
            terms += [(LEGAL.sub("", t).strip(" «»\""), "org") for t in self.entities["orgs"] if LEGAL.search(t)]
            canon = {}
            for t in self.entities["persons"]:
                canon[t] = t
                canon[t.split()[-1]] = t
            for t in self.entities["orgs"]:
                canon[t] = t
                canon[LEGAL.sub("", t).strip(" «»\"")] = t
            hits = ner_ru.find_terms(text, [(t, k) for t, k in terms if len(t) >= 3]) or []
            for a_, b_, term, kind in reversed(hits):
                text = text[:a_] + self._token(kind, canon.get(term, term)) + text[b_:]
                rep["replaced"][kind] = rep["replaced"].get(kind, 0) + 1
        low = fold(text)
        for term, kind, rx, key in self._compiled:
            if key and key not in low:        # substring pre-filter: of ~1400 regexes only a few run
                continue
            if not rx.search(text):           # a token is created only on a match, or the token table grows per entry
                continue
            text, n = rx.subn(lambda m, k=kind, t=term: self._token(k, t), text)
            if n:
                rep["replaced"][kind] = rep["replaced"].get(kind, 0) + n
        return text, rep

    def scrub_messages(self, messages, data_class, use_ner):
        """Scrub every text part of an OpenAI-style message list. Returns (messages, report, secret_parts)."""
        agg = {"replaced": {}, "secret_lines": 0, "ner_new": 0, "ner_error": None}
        secret_parts, out = [], []

        def one(text, role):
            clean, rep = self.scrub(text, data_class, use_ner=use_ner, secret_markers=role != "system")
            for k, v in rep["replaced"].items():
                agg["replaced"][k] = agg["replaced"].get(k, 0) + v
            agg["secret_lines"] += rep["secret_lines"] + rep["secret_blocks"]
            agg["ner_new"] += rep.get("ner_new", 0)
            if rep.get("ner_error"):
                agg["ner_error"] = rep["ner_error"][:120]
            secret_parts.extend(rep["secret"])
            return clean

        for m in messages:
            c = m.get("content")
            role = m.get("role")
            if isinstance(c, str):
                m = dict(m, content=one(c, role))
            elif isinstance(c, list):
                m = dict(m, content=[dict(p, text=one(p["text"], role)) if isinstance(p, dict) and isinstance(p.get("text"), str) else p for p in c])
            if m.get("tool_calls"):
                tcs = []
                for tc in m["tool_calls"]:
                    f = dict(tc.get("function") or {})
                    if isinstance(f.get("arguments"), str):
                        f["arguments"] = one(f["arguments"], role)
                    tcs.append(dict(tc, function=f))
                m = dict(m, tool_calls=tcs)
            out.append(m)
        return out, agg, secret_parts

    def unscrub(self, text):
        for tok, rec in sorted(self._token_items(), key=lambda kv: -len(kv[0])):
            if tok.lower() in text.lower():
                text = re.sub(re.escape(tok).replace(r"\-", r"\s*[-–]\s*"), rec["value"].replace("\\", "\\\\"), text, flags=re.I)
        return text

    def unscrub_message(self, message):
        """Restore values in content (string or parts) and in tool-call arguments."""
        m = dict(message)
        c = m.get("content")
        if isinstance(c, str):
            m["content"] = self.unscrub(c)
        elif isinstance(c, list):
            m["content"] = [dict(p, text=self.unscrub(p["text"])) if isinstance(p, dict) and isinstance(p.get("text"), str) else p for p in c]
        if m.get("tool_calls"):
            tcs = []
            for tc in m["tool_calls"]:
                f = dict(tc.get("function") or {})
                if isinstance(f.get("arguments"), str):
                    f["arguments"] = self.unscrub(f["arguments"])
                tcs.append(dict(tc, function=f))
            m["tool_calls"] = tcs
        return m

    def leak_check(self, cloud_text):
        """Values that had to be hidden (active entities and identifiers) but are present in the text for the cloud."""
        active = {fold(x) for x in self.entities["persons"] + self.entities["orgs"]}
        low = fold(cloud_text)
        leaks = 0
        self.last_leaks = []
        for _tok, rec in self._token_items():
            v = rec["value"]
            if len(v) < 5:
                continue
            if rec["kind"] in ("person", "org", "term") and fold(rec["canonical"]) not in active:
                continue   # a stale token (entity removed by the owner) is not a leak
            if re.search(r"(?<!\w)" + re.escape(fold(v)) + r"(?!\w)", low):
                leaks += 1
                self.last_leaks.append("%s:%s" % (rec["kind"], rec["canonical"]))
        return leaks

    def purge_tokens(self):
        """Drop tokens of entities that are no longer active (after a dictionary clean-up)."""
        active = {fold(x) for x in self.entities["persons"] + self.entities["orgs"]}
        before = len(self.tokens["map"])

        def stale(r):
            if r["kind"] in ("person", "org", "term"):
                return fold(r["canonical"]) not in active
            if r["kind"] == "phone" and P.DATE_PREFIX.match(r["value"].strip()):
                return True
            return False

        with _lock:
            self.tokens["map"] = {t: r for t, r in self.tokens["map"].items() if not stale(r)}
        _save(self.tokens_path, self.tokens)
        return before - len(self.tokens["map"])
