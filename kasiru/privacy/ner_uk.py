"""Ukrainian NER on spaCy (``uk_core_news_lg``, CPU), complementing Natasha where the text is Ukrainian.
Runs only when the text contains Ukrainian letters (і ї є ґ); otherwise returns empty lists without loading anything.
Entities are lemmatised with the reference lemmatizer; places are reported so other detectors' false "persons" can be dropped.
``detect()`` returns None when spaCy or the model is unavailable.
"""
import re
import threading

from . import lemma as _lemma

_lock = threading.Lock()
_nlp = None
UK_LETTERS = re.compile(r"[іїєґІЇЄҐ]")
MODEL = "uk_core_news_lg"


def _load():
    global _nlp
    with _lock:
        if _nlp is None:
            import spacy
            _nlp = spacy.load(MODEL, disable=["parser"])
    return _nlp


def available():
    try:
        _load()
        return True
    except Exception:  # noqa: BLE001
        return False


def is_ukrainian(text, min_hits=3):
    return len(UK_LETTERS.findall(text)) >= min_hits


def _clean(s):
    s = re.sub(r"[«»\"'`]", "", s).strip(" .,;:!?-–—")
    return re.sub(r"\s+", " ", s)


def detect(text, max_chars=200000):
    if not is_ukrainian(text):
        return {"persons": [], "orgs": [], "locs": []}
    try:
        nlp = _load()
    except Exception:  # noqa: BLE001
        return None
    out = {"persons": [], "orgs": [], "locs": []}
    seen = set()
    for i in range(0, min(len(text), max_chars), 50000):
        doc = nlp(text[i:i + 50000])
        for ent in doc.ents:
            key = {"PER": "persons", "ORG": "orgs", "LOC": "locs"}.get(ent.label_)
            if not key:
                continue
            # lemmatise only Ukrainian entities: a Ukrainian lemmatizer on a Russian name produces junk
            lemma = " ".join(_lemma.lemma(t.text, name_first=True) for t in ent) if UK_LETTERS.search(ent.text) else ""
            cand = lemma if lemma and lemma.lower() != lemma else ent.text
            if lemma and lemma.lower() == lemma:   # the lemma lost its capitals; restore them from the text
                cand = " ".join(w.capitalize() if o[:1].isupper() else w for w, o in zip(lemma.split(), ent.text.split())) if len(lemma.split()) == len(ent.text.split()) else ent.text
            if key == "locs":
                for v in (_clean(cand), _clean(ent.text)):
                    if len(v) >= 3 and v.lower() not in seen:
                        seen.add(v.lower())
                        out["locs"].append(v)
                continue
            for name in re.split(r"\s*[,;/]\s*|\s+і\s+|\s+та\s+|\s+и\s+", _clean(cand)):
                name = _clean(name)
                if len(name) < 3 or name.lower() in seen:
                    continue
                seen.add(name.lower())
                out[key].append(name)
    return out
