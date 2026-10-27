"""Russian NER on Natasha / Slovnet (CPU, milliseconds): people and organisations; places are reported separately
so other layers can drop false "persons". Names are normalised to the nominative case. Loaded once per process (~0.5 s).
``detect()`` returns None when natasha is not installed, and the privacy layer falls back to the LLM detector or to off.

``find_terms()`` is the morphological dictionary matcher: it compares token lemmas, so "Северного Ветра" matches the
entry "Северный Ветер" and "Экзюпери" is found inside "Сент-Экзюпери".
"""
import re
import threading

from . import lemma as _lemma_mod

_lock = threading.Lock()
_nlp = None


def _load():
    global _nlp
    with _lock:
        if _nlp is None:
            from natasha import Doc, MorphVocab, NewsEmbedding, NewsMorphTagger, NewsNERTagger, Segmenter
            emb = NewsEmbedding()
            _nlp = {"seg": Segmenter(), "mv": MorphVocab(), "ner": NewsNERTagger(emb), "mt": NewsMorphTagger(emb), "Doc": Doc}
    return _nlp


def available():
    try:
        _load()
        return True
    except Exception:  # noqa: BLE001
        return False


def _clean(s):
    s = re.sub(r"[«»\"'`]", "", s).strip(" .,;:!?-–—")
    return re.sub(r"\s+", " ", s)


def detect(text, max_chars=200000):
    """-> {"persons": [...], "orgs": [...], "locs": [...]} normalised, de-duplicated; None if the library is missing."""
    try:
        n = _load()
    except Exception:  # noqa: BLE001
        return None
    out = {"persons": [], "orgs": [], "locs": []}
    seen = set()
    for i in range(0, min(len(text), max_chars), 50000):
        doc = n["Doc"](text[i:i + 50000])
        doc.segment(n["seg"])
        doc.tag_morph(n["mt"])
        doc.tag_ner(n["ner"])
        for t in doc.tokens:
            t.lemmatize(n["mv"])
        for s in doc.spans:
            try:
                s.normalize(n["mv"])
            except Exception:  # noqa: BLE001
                pass
            key = {"PER": "persons", "ORG": "orgs", "LOC": "locs"}.get(s.type)
            if not key:
                continue
            # one span may glue several names: "Олег, Женя", "Максим и Зия"
            for name in re.split(r"\s*[,;/]\s*|\s+и\s+|\s+та\s+", _clean(s.normal or s.text)):
                name = _clean(name)
                if len(name) < 3 or name.lower() in seen:
                    continue
                seen.add(name.lower())
                out[key].append(name)
    return out


def find_terms(text, terms):
    """Lemma-based search of dictionary terms. terms: [(term, kind)] -> [(start, end, term, kind)] without overlaps,
    longest terms first. Uses a lemma -> positions index instead of a pass per term."""
    try:
        n = _load()
    except Exception:  # noqa: BLE001
        return None
    from razdel import tokenize
    mv = n["mv"]
    toks = []
    for t in tokenize(text):
        if "-" in t.text.strip("-") and re.search(r"[^\W\d_]-[^\W\d_]", t.text):   # split hyphenated words
            pos = t.start
            for part in t.text.split("-"):
                if part:
                    toks.append((pos, pos + len(part), part))
                pos += len(part) + 1
        else:
            toks.append((t.start, t.stop, t.text))
    lemmas = [(w.lower() if not w[:1].isalpha() else _lemma_mod.lemma(w)) for _a, _b, w in toks]
    index = {}
    for i, l in enumerate(lemmas):
        index.setdefault(l, []).append(i)
    prepared = sorted((([_lemma_mod.lemma(w, name_first=True) for w in re.findall(r"[\w'-]+", t)], t, k) for t, k in terms if t), key=lambda x: -len(x[0]))
    hits, taken = [], [False] * len(toks)
    for tl, term, kind in prepared:
        L = len(tl)
        if L == 0 or tl[0] not in index:
            continue
        for i in index[tl[0]]:
            if i + L > len(lemmas) or lemmas[i:i + L] != tl or any(taken[i:i + L]):
                continue
            hits.append((toks[i][0], toks[i + L - 1][1], term, kind))
            for j in range(i, i + L):
                taken[j] = True
    del mv
    return sorted(hits)
