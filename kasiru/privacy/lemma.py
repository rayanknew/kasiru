"""Reference lemmatizer: one word -> lemma, language, name-likeness.

The single normalisation point for detectors (``ner_ru``, ``ner_uk``), dictionary matching (``find_terms``)
and the junk filter (``word_bad``). The language is decided per word, not per text, so a Ukrainian
lemmatizer never mangles a Russian name inside a mixed message.

* uk - contains і ї є ґ            -> pymorphy2 with ``pymorphy2-dicts-uk`` (part of speech only, no name tags)
* ru - Cyrillic                    -> pymorphy2 (ru); for capitalised words prefer a Name/Surn/Patr parse
* en - Latin                       -> names do not inflect: lower-case, strip possessive 's and diacritics
* another language = another adapter here; detectors and matching stay unchanged.

Without pymorphy2 the module degrades to lower-casing (exact-form matching); nothing breaks.
"""
import re
import threading
import unicodedata

UK = re.compile(r"[іїєґІЇЄҐ]")
CYR = re.compile(r"[А-Яа-яЁё]")
LAT = re.compile(r"[A-Za-z]")
NAME_TAGS = ("Name", "Surn", "Patr")
PLACE_ORG_TAGS = ("Geox", "Orgn", "Trad")
BAD_POS = {"VERB", "INFN", "PRTF", "PRTS", "GRND", "ADVB", "PRED", "CONJ", "PREP", "PRCL", "NPRO", "NUMR", "INTJ", "COMP"}

_lock = threading.Lock()
_morph = {}
_cache = {}
_CACHE_MAX = 200000


def lang_of(word):
    if UK.search(word):
        return "uk"
    if CYR.search(word):
        return "ru"
    if LAT.search(word):
        return "en"
    return "x"


def _analyzer(lang):
    with _lock:
        if lang not in _morph:
            try:
                import inspect
                if not hasattr(inspect, "getargspec"):   # pymorphy2 on Python >= 3.11
                    inspect.getargspec = lambda f: tuple(inspect.getfullargspec(f))[:4]
                import pymorphy2
                _morph[lang] = pymorphy2.MorphAnalyzer(lang=lang)
            except Exception:  # noqa: BLE001
                _morph[lang] = False
        return _morph[lang]


def _en(word):
    w = unicodedata.normalize("NFKD", word)
    w = "".join(c for c in w if not unicodedata.combining(c)).lower()
    return re.sub(r"['’]s$", "", w)


def analyze(word, name_first=False):
    """-> {"lemma", "lang", "is_name" (True / False / None), "pos", "known", "score", "place_org", ...}."""
    lang = lang_of(word)
    base = {"lang": lang, "is_name": None, "name_kind": None, "anim": False, "plural": False, "pos": None, "known": False, "score": 0.0, "place_org": False}
    if lang == "en":
        return dict(base, lemma=_en(word), known=True)
    if lang == "x":
        return dict(base, lemma=word.lower())
    m = _analyzer(lang)
    if not m:
        return dict(base, lemma=word.lower().replace("ё", "е"))
    try:
        parses = m.parse(word)
    except Exception:  # noqa: BLE001
        return dict(base, lemma=word.lower().replace("ё", "е"))
    best = parses[0]
    name_parses = sorted((p for p in parses if any(t in str(p.tag) for t in NAME_TAGS)),
                         key=lambda p: (p.normal_form.lower() != word.lower(), -p.score))
    capital = word[:1].isupper()
    if name_parses and (name_first or capital):
        best = name_parses[0]
    is_name = bool(name_parses) and (capital or name_first or name_parses[0].score >= 0.5) if lang == "ru" else None
    tags = " ".join(str(p.tag) for p in name_parses)
    return {"lemma": best.normal_form.replace("ё", "е"), "lang": lang, "pos": best.tag.POS, "known": bool(best.is_known), "score": float(best.score),
            "is_name": is_name, "anim": "anim" in str(best.tag), "plural": "plur" in str(best.tag),
            "name_kind": ("first" if "Name" in tags else "patr" if "Patr" in tags else "surname" if "Surn" in tags else None),
            "place_org": any(p.is_known and any(t in str(p.tag) for t in PLACE_ORG_TAGS) for p in parses)}


def lemma(word, name_first=False):
    key = (word, name_first)
    r = _cache.get(key)
    if r is None:
        r = analyze(word, name_first)["lemma"]
        if len(_cache) > _CACHE_MAX:
            _cache.clear()
        _cache[key] = r
    return r


def word_bad(word, kind="persons"):
    """The morphology knows this word as a non-name: verb form, adverb, function word; for persons also an adjective
    or a common noun without a name tag. Latin and unknown words are not judged."""
    a = analyze(word)
    if a["lang"] not in ("ru", "uk"):
        return False
    if a["is_name"] or a["place_org"] or not a["known"]:
        return False
    if a["pos"] in BAD_POS:
        return True
    if kind != "persons" or a["lang"] != "ru":
        return False
    return a["pos"] in ("ADJF", "ADJS", "NOUN") and a["score"] >= 0.5
