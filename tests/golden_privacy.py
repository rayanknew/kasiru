"""Golden set of the privacy layer on synthetic texts with known entities. Needs the ``ru`` and ``ids`` extras
(Natasha, phonenumbers, python-stdnum); the ``uk`` extra adds the Ukrainian case. Exit code 1 when an invariant breaks.
  python3 tests/golden_privacy.py
Runs on a temporary state; real dictionaries are untouched. All data is fictional.
"""
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from kasiru.privacy import Privacy, stem  # noqa: E402
from kasiru.privacy import lemma as L  # noqa: E402

d = tempfile.mkdtemp(prefix="kasiru-golden-")
json.dump({"persons": ["Игорь Семёнович Лавренко", "Экзюпери"], "orgs": ["ООО Северный Ветер"], "ignore": ["Google", "OLX"],
           "pending": {"persons": [], "orgs": []}}, open(os.path.join(d, "entities.json"), "w"), ensure_ascii=False)
P = Privacy(d, d, {"ner": "auto", "protect_all": False, "phone_regions": ["UA", "RU", "TR", "US"]}, log=lambda *a: None)
print("detector:", P.ner_label)
if P.ner_backend != "natasha":
    print("natasha is not installed - the golden set needs the [ru] extra")
    sys.exit(2)

CASES = [
    # (text, must disappear from the cloud text, must stay)
    ("Почта vasya.pupkin@example.org, телефон +380 67 123 45 67, карта 4111 1111 1111 1111, IBAN UA213223130000026007233566001.",
     ["vasya.pupkin@example.org", "+380 67 123 45 67", "4111 1111 1111 1111", "UA213223130000026007233566001"], []),
    ("Семенович Лавренко и Игорь Семенович — ё/е равнозначны при поиске словоформ.",
     ["Семенович Лавренко", "Игорь Семенович"], ["равнозначны"]),
    ("Встреча 2024-05-04, следующая 2025-12-19 – 2025-12-21, бюджет 1500000 грн, код заказа 20240504.",
     [], ["2024-05-04", "2025-12-19", "1500000"]),
    ("Договор с ООО «Северный Ветер» подписал Игорь Семёнович Лавренко; Лавренко обещал перезвонить, Северного Ветра это устроило.",
     ["Северный Ветер", "Лавренко", "Северного Ветра"], ["Договор", "подписал"]),
    ("Писал Артемию Костюченко из Kharkiv Robotics LLC, потом Марьяне Голубевой; обе компании — Kharkiv Robotics и ФОП Голубева М.",
     ["Артемию Костюченко", "Марьяне Голубевой", "Kharkiv Robotics"], ["Писал", "потом"]),
    ("Путин и Трамп обсуждали Кипр, Дубай и Киев; Google и OLX ни при чём. Дима сказал, что мама против.",
     [], ["Кипр", "Дубай", "Киев", "Google", "OLX", "Дима", "мама", "Путин", "Трамп"]),
    ("Обычная строка.\n[secret] долг 12000 долларов перед Стасом\nЕщё строка <secret>пин 4321</secret> конец.",
     ["12000 долларов", "Стасом", "4321"], ["Обычная строка", "Ещё строка", "конец"]),
    ("Ник @ivan_petrov_88 и ссылка https://t.me/secret_chat_xyz и https://site.example/?token=abc123def.",
     ["@ivan_petrov_88", "t.me/secret_chat_xyz", "token=abc123def"], ["ссылка"]),
    ("Локальный номер 067 123 45 67 и городской (044) 123-45-67; номер заказа 1234 5678 9012 3450 не карта, а 5555 5555 5555 4444 — карта.",
     ["067 123 45 67", "(044) 123-45-67", "5555 5555 5555 4444"], ["1234 5678 9012 3450"]),
    ("Кошелёк 0x742d35Cc6634C0532925a3b844Bc454e4438f44e и bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq; невалидный IBAN UA000000000000000000000000001 оставить.",
     ["0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"], ["UA000000000000000000000000001"]),
    ("Мастера (Олег, Женя, Руслан Бойко) и брат (Максим, Зия) приехали; Руслана Бойко ждали дольше всех.",
     ["Руслан Бойко", "Руслана Бойко"], ["Мастера", "брат"]),
    ("Код ЄДРПОУ 44074574 и ИНН 1234567890 компании ТОВ «Юнікс Трейд» — директор Пётр Васильевич Орлик.",
     ["44074574", "1234567890", "Юнікс Трейд", "Пётр Васильевич Орлик"], ["директор"]),
    ("Согласившийся подрядчик, Приехавший в офис Менеджер и Начальник отдела эскалировали вопрос к Богдану Ткачуку; Самовольно уехал.",
     ["Богдану Ткачуку"], ["Согласившийся", "Приехавший", "Менеджер", "Начальник", "Самовольно", "подрядчик"]),
    ("Ключи: sk-or-v1-0123456789abcdef0123456789abcdef, AIzaSyD-ExampleKeyExampleKeyExampleKey1, ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij, бот 123456789:AAHfakeTokenFakeTokenFakeTokenFakeT1, "
     "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c, пароль: Qwe12345!, приватник 1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd, обычное слово Приложение.",
     ["sk-or-v1-0123456789abcdef0123456789abcdef", "AIzaSyD-ExampleKeyExampleKeyExampleKey1", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "123456789:AAHfakeTokenFakeTokenFakeTokenFakeT1",
      "eyJhbGciOiJIUzI1NiJ9", "Qwe12345", "1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd"], ["Ключи", "обычное слово Приложение"]),
    ("Адреса: ул. Сагайдачного 12, кв. 5; вул. Хрещатик, буд. 22; Bağdat Caddesi No: 45 Daire 3; Baker Street 221 — адрес; город Киев остаётся.",
     ["Сагайдачного 12", "Хрещатик, буд. 22", "Bağdat Caddesi No: 45", "Baker Street 221"], ["Киев", "Адреса"]),
    ("Была дана команда, просьба отправить данных партнёров; Игорь Лавренко отправил. Ryan's team и Müller обсуждали.",
     ["Игорь Лавренко"], ["дана команда", "просьба", "данных", "отправил"]),
    ("Поездки 2025-08-07/11 и 2023-03-10/16, встреча 2025-08-05/07; телефон +90 532 123 45 67.",
     ["+90 532 123 45 67"], ["2025-08-07/11", "2023-03-10/16", "2025-08-05/07"]),
    ("Читал Сент-Экзюпери и Лавренко-младшего; Игорь Семёнович Лавренко был рядом.",
     ["Экзюпери", "Лавренко"], ["Сент-", "младшего"]),
]
if P.ner_uk:
    CASES.append(("Вчора Олексій Ковальчук із ТОВ «Київбуд» зустрівся з Мариною Гнатюк у Львові; Андрій казав, що Google ні до чого.",
                  ["Олексій Ковальчук", "Київбуд", "Мариною Гнатюк"], ["Львові", "Google", "зустрівся"]))

fails = hits = total = 0
for text, must_go, must_stay in CASES:
    out, rep = P.scrub(text, "personal", use_ner=True)
    for x in must_go:
        total += 1
        if x.lower() in out.lower():
            print("  FAIL not hidden:", repr(x))
            fails += 1
        else:
            hits += 1
    for x in must_stay:
        if x.lower() not in out.lower() and not any(x.lower() in k.lower() for k in rep["secret"]):
            print("  FAIL hidden by mistake / lost:", repr(x))
            fails += 1
    back = P.unscrub(out)
    if re.search(r"\[(?:person|org|term|email|phone|user|code|tg|card|iban)-\d+\]", back, re.I):
        print("  FAIL a token is left in the restored text")
        fails += 1
    if P.leak_check(out):
        print("  FAIL symmetry: scrub left a value the leak check sees:", P.last_leaks)
        fails += 1

for w, lang, lem, bad in [("Дана", "ru", "дана", False), ("дана", "ru", "дать", True), ("просьба", "ru", "просьба", True), ("Партнерша", "ru", "партнерша", True),
                          ("Отправивший", "ru", "отправить", True), ("Лавренко", "ru", "лавренко", False), ("Ryan's", "en", "ryan", False), ("Müller", "en", "muller", False)]:
    a = L.analyze(w, name_first=False)
    if a["lang"] != lang or a["lemma"] != lem or L.word_bad(w) != bad:
        print("  FAIL lemmatizer:", w, a["lang"], a["lemma"], L.word_bad(w), "expected", lang, lem, bad)
        fails += 1

# invariants
out, rep = P.scrub("Звонил [person-3] и [org-7], номер карты 4111 1111 1111 1111", "personal")
assert "[person-" not in json.dumps(P.entities, ensure_ascii=False).lower(), "a token got into the dictionary"
back = P.unscrub("Ответ: [Person-1] и [PERSON-1] и [person - 1]")
assert "[" not in back or "person" not in back.lower(), "unscrub ignores case / spaces: " + back
auto, pend = P.entities.get("auto", []), P.entities["pending"]
print("auto-activated (confident):", auto)
print("pending (weak):", pend)
assert "Дима" not in auto and "Путин" not in auto, "single names must not auto-activate"
assert not any("," in x for x in auto + pend["persons"] + pend["orgs"]), "comma-glued entries in the dictionary"
assert all(("Кипр" not in l and "Дубай" not in l) for l in (auto, pend["persons"], pend["orgs"])), "places are not entities"
print("hidden %d of %d required; failures %d" % (hits, total, fails))
sys.exit(1 if fails else 0)
