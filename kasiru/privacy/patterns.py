"""Layer 1: identifiers found by pattern and confirmed by a validator.

Regular expressions only propose; the checksum / library decides: card numbers by Luhn, IBAN by its check digits,
phone numbers by ``phonenumbers`` for the configured regions, Bitcoin addresses by ``python-stdnum``,
BIP39 seed phrases by the wordlist. Everything in this module is stateless.
"""
import re

try:
    import phonenumbers
except Exception:  # noqa: BLE001
    phonenumbers = None
try:
    from stdnum import bitcoin as _bitcoin, iban as _iban, luhn as _luhn
except Exception:  # noqa: BLE001
    _luhn = _iban = _bitcoin = None
try:
    from mnemonic import Mnemonic as _Mn
    _BIP39 = set(_Mn("english").wordlist)
except Exception:  # noqa: BLE001
    _BIP39 = None

PATTERNS = [
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("tg", re.compile(r"(?:https?://)?t\.me/[A-Za-z0-9_+/-]+")),
    ("url", re.compile(r"https?://\S*(?:token|key|auth|session|password|pwd|secret)=\S*", re.I)),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    ("card", re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b")),
    # access tokens of any kind never leave the machine
    ("key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    ("key", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|sk-or-v1-[a-f0-9]{20,}|gsk_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}"
                       r"|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|\d{8,10}:[A-Za-z0-9_-]{35}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
                       r"|(?:api[_-]?key|token|secret|password|пароль|ключ)\s*[:=]\s*[\"']?[A-Za-z0-9_\-./+=]{8,}[\"']?)", re.I)),
    # crypto wallets: EVM, Bitcoin, Tron, TON, Monero, Litecoin, Dogecoin, XRP, Cardano, Cosmos, Solana / Polkadot
    ("crypto", re.compile(r"(?<![A-Za-z0-9/])(?:0x[a-fA-F0-9]{40}|bc1[a-z0-9]{25,62}|ltc1[a-z0-9]{25,62}|addr1[a-z0-9]{50,}|cosmos1[a-z0-9]{38}"
                          r"|(?:EQ|UQ|kQ|0Q)[A-Za-z0-9_-]{46}|-?\d:[a-f0-9]{64}|[48][1-9A-HJ-NP-Za-km-z]{94}"
                          r"|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|[LM][a-km-zA-HJ-NP-Z1-9]{26,33}|D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}|r[1-9A-HJ-NP-Za-km-z]{24,34}"
                          r"|T[A-Za-z1-9]{33}|[1-9A-HJ-NP-Za-km-z]{32,48})(?![A-Za-z0-9/])")),
    ("hex", re.compile(r"\b[a-fA-F0-9]{40,128}\b")),   # private keys, transaction hashes, session tokens
    ("code", re.compile(r"(?:ЄДРПОУ|ЕДРПОУ|ЕГРПОУ|ИНН|ІПН|ОГРН|РНОКПП|EDRPOU|VAT|EIN|SSN)\s*:?\s*[\d-]{8,12}", re.I)),
    ("user", re.compile(r"(?<![\w/.])@[A-Za-z][A-Za-z0-9_]{3,}")),
    # postal addresses: street type (ru/uk/en/tr) + name + house number (+ building, flat / office); cities are left alone
    ("address", re.compile(r"(?<!\w)(?:ул\.?|улица|вул\.?|вулиця|просп\.?|проспект|пр-т|пер\.?|переулок|пров\.?|провулок|бул\.?|бульвар|наб\.?|набережная|шоссе|шосе|пл\.|площадь|майдан"
                           r"|street|st\.|avenue|ave\.|road|rd\.|lane|blvd\.?|sokak|sk\.|caddesi|cad\.|mahallesi|mah\.)"
                           r"\s+[^\n,;:]{2,40}?,?\s*(?:д\.|дом|буд\.|будинок|house|no\.?|№)?\s*\d{1,4}[а-яa-z]?(?:\s*(?:/|корп\.?|к\.|стр\.)\s*\d{1,3})?"
                           r"(?:\s*,?\s*(?:кв\.|квартира|офис|оф\.|apt\.?|office|daire|d\.)\s*\d{1,4})?", re.I)),
    ("address", re.compile(r"(?<![\w\d])[A-ZÇĞİÖŞÜ][\w'’.-]{1,30}(?:\s+[A-ZÇĞİÖŞÜ][\w'’.-]{1,30}){0,2}\s+(?:Caddesi|Cad\.|Sokak|Sokağı|Sk\.|Mahallesi|Mah\.|Bulvarı|Street|St\.|Avenue|Ave\.|Road|Rd\.|Lane)"
                           r"\s*,?\s*(?:No\.?:?|№)?\s*\d{1,4}[A-Za-z]?(?:\s*(?:/|Daire|D\.|Kat|Apt\.?|apt\.?|Office)\s*\d{1,3})?")),
]

SEED_RUN = re.compile(r"\b(?:[a-z]{3,8}[ ,]+){11,23}[a-z]{3,8}\b")
PHONE = re.compile(r"(?<![\d\w])\+?\d[\d\s()-]{8,}\d(?![\d\w])")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:\s*[-–/]\s*\d{4}-\d{2}-\d{2})?$")
DATE_PREFIX = re.compile(r"\d{4}-\d{2}-\d{2}")


def find_seeds(text):
    """BIP39 seed phrases: 12-24 consecutive wordlist words -> [(start, end)]."""
    if not _BIP39:
        return []
    out = []
    for m in SEED_RUN.finditer(text):
        words = re.findall(r"[a-z]+", m.group(0))
        if len(words) in (12, 15, 18, 21, 24) and all(w in _BIP39 for w in words):
            out.append((m.start(), m.end()))
    return out


def looks_like_phone(s):
    """Fallback when ``phonenumbers`` is missing: ten or more digits, not a date, not a plain digit run."""
    s = s.strip()
    if DATE_PREFIX.match(s):
        return False
    return s.startswith("+") or (not DATE.match(s) and sum(c.isdigit() for c in s) >= 10 and not re.fullmatch(r"[\d\s]+", s))


def find_phones(text, regions):
    """Phone numbers via ``phonenumbers`` (international and local for *regions*) -> [((start, end), raw)]; None if unavailable."""
    if not phonenumbers:
        return None
    found = {}
    for region in regions:
        try:
            for m in phonenumbers.PhoneNumberMatcher(text, region, leniency=phonenumbers.Leniency.VALID):
                raw = m.raw_string.strip()
                if not DATE.match(raw) and not DATE_PREFIX.match(raw):
                    found[(m.start, m.end)] = m.raw_string
        except Exception:  # noqa: BLE001
            continue
    return sorted(found.items())


def valid(kind, raw):
    """Validators: card by Luhn, IBAN by checksum, crypto by shape / checksum, hex needs both digits and letters,
    'password: ...' only when the value looks like a real secret."""
    try:
        if kind == "card" and _luhn:
            return _luhn.is_valid(re.sub(r"\D", "", raw))
        if kind == "iban" and _iban:
            return _iban.is_valid(raw)
        if kind == "crypto":
            if re.fullmatch(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62}", raw):
                return _bitcoin.is_valid(raw) if _bitcoin else True
            if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,48}", raw):   # bare base58: require digits and both cases
                return bool(re.search(r"\d", raw) and re.search(r"[a-z]", raw) and re.search(r"[A-Z]", raw))
            return True
        if kind == "hex":
            return bool(re.search(r"\d", raw) and re.search(r"[a-fA-F]", raw))
        if kind == "key" and raw.lower().startswith(("api", "token", "secret", "password", "пароль", "ключ")):
            v = re.split(r"\s*[:=]\s*", raw, 1)[1].strip("\"'")
            return bool(re.search(r"\d", v) or len(v) >= 16)
    except Exception:  # noqa: BLE001
        return False
    return True
