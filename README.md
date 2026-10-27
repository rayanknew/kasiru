# Kasiru

**A privacy-first gateway between your programs and LLM APIs.**
One OpenAI-compatible endpoint; your code names a *tier* and a *data class*, Kasiru decides which model may see the text and in which form.

```
your apps ──► Kasiru ──► local model (llama.cpp / Ollama)       ← secret, or anything that could not be cleaned
   │                 ──► cloud, after reversible pseudonymisation ← personal
   │                 ──► cloud, as is                             ← public
   └── audit.jsonl: who, where, how many tokens, how many replacements, zero leaks — never the text
```

Kasiru (from Akkadian *kaṣāru*, "to bind together") was built for one person running several assistants and pipelines over private notes, chats and meeting transcripts in Russian, Ukrainian and English, with free cloud tiers and a small local model as the last resort. It is now a standalone project.

## Why another gateway

Most LLM proxies do one of two things: redact PII, or route between providers. Kasiru does both in one decision point, and adds what we could not find elsewhere:

- **The client declares the data class, the gateway enforces it.** `secret` never leaves the machine. `personal` leaves only after pseudonymisation, and only if a leak check passes. `public` goes as is. A header or a per-client default, no guessing.
- **Tiers instead of models.** `local | cheap | good | best | long` are ordered candidate lists in config, with daily quotas (requests, tokens, dollars), cool-downs after 429/5xx and a local backend always last. The system degrades into *slow*, never into *unavailable*, and free tiers are spent before paid ones.
- **Reversible, persistent pseudonyms.** One entity is one token forever (`[person-7]`), so a cloud model still sees who talks to whom, and the answer comes back with real names, inside tool-call arguments too. The token table never leaves the state directory.
- **Cyrillic as a first-class citizen.** Russian NER on CPU (Natasha), Ukrainian NER (spaCy), morphological dictionary matching ("Северного Ветра" = "Северный Ветер"), ё/е equivalence, hyphenated names, patronymics. Adding a language is one adapter.
- **Symmetric filters.** What the substitution cannot find, the leak check does not count as a leak, so a dictionary quirk cannot silently push every request to the local model.
- **Secret markup.** Lines with `[secret]` and `<secret>…</secret>` blocks never reach an external API: the whole request stays local, or in *split* mode the secret lines are processed locally and appended to the cloud answer.
- **Agents work through it.** `tools` / `tool_calls` pass through; local routes stream for real; cloud routes are restored first and streamed as one chunk.
- **Standard library only.** The core runs with no dependencies on Python 3.9+. Detectors, validators and morphology are optional extras.

## Install

```bash
pip install "kasiru[all] @ git+https://github.com/rayanknew/kasiru"   # core + identifiers + Russian + Ukrainian
# or without extras: pip install "git+https://github.com/rayanknew/kasiru"   (patterns, dictionary by stem, no NER)
python -m spacy download uk_core_news_lg   # only for the [uk] extra
kasiru init                      # writes ~/.config/kasiru/{kasiru.json,env,entities.json}
kasiru check                     # validates config, keys and the detector
kasiru serve
```

## Use

```bash
curl http://127.0.0.1:8081/v1/chat/completions \
  -H "Authorization: Bearer $KASIRU_KEY_SCRIPTS" \
  -H "X-Data-Class: personal" -H "X-Project: notes" \
  -d '{"model": "good", "messages": [{"role": "user", "content": "Summarise my call with Jane Example"}]}'
```

Any OpenAI-compatible client works: set the base URL to Kasiru and the model to a tier name. The answer carries a `kasiru` field with the class, backend, route, replacements, cost and milliseconds.

| You say | Kasiru does |
|---|---|
| `model: "good"` | tries the `good` candidates in order, skipping spent or cooling backends, local last |
| `model: "gemini:gemini-3.6-flash"` | that exact backend and model (still subject to the data class) |
| `X-Data-Class: secret` | local only, text untouched |
| `X-Data-Class: personal` (default) | pseudonymise, leak-check, cloud; restore the answer |
| `X-Data-Class: public` | cloud as is; only secret markup is removed |
| `X-Secret-Mode: split` | secret lines go local separately and are appended to the cloud answer |
| a client with `"class": "secret"` | that client can never reach a cloud, whatever it sends |

## The privacy layer

```
text ─► 1 patterns + validators ─► 2 owner's dictionary (by lemma) ─► 3 local NER ─► 4 secret markup ─► leak check ─► cloud
         e-mail, phones (libphonenumber), cards (Luhn), IBAN, crypto wallets, API keys, JWT, PEM, seed phrases, addresses
                                          persons / orgs / terms, inflections, surname alone, name without legal form
                                                                      Natasha (ru) + spaCy (uk) or a local LLM; new names join the dictionary
```

- `kasiru scrub file.txt` shows exactly what the cloud would see.
- `kasiru entities pending|keep|ignore` reviews what the detector found; with `protect_all` (default) every hit is protected until you say otherwise.
- `tests/golden_privacy.py` is the regression set: what must disappear, what must stay, round trip, symmetry.

Details: [docs/privacy.md](docs/privacy.md).

## Configuration

One JSON file: backends (kind, URL, key name, allowed classes, limits, prices), tiers (ordered candidates), clients (keys, forced or default class, default tier, admin), privacy options. Keys live in a separate `env` file with mode 0600. Full reference: [docs/configuration.md](docs/configuration.md). Running as a service: [deploy/](deploy/).

## Status and roadmap

v0.1 is what one household runs daily. Known limits and planned work:

- streaming through a cloud route is one chunk (restoration needs the whole text);
- `ollama` kind does not stream (use llama.cpp's server or any OpenAI-compatible local server for streaming);
- cool-down triggers on the first 5xx; a threshold (`allowed_fails`) is planned;
- per-client budgets with auto-stop; a `/v1/kasiru/report` endpoint;
- embeddings through the gateway (always local);
- more languages: adapters for `privacy/lemma.py` and a NER module are all it takes. Contributions welcome, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Security notes

Bind to `127.0.0.1` or a LAN address and configure `clients`; without clients the gateway trusts the network. The token table, the detector cache and the dictionary are sensitive files: they are written with mode 0600, back them up encrypted. Kasiru logs no request or response text anywhere.

Licensed under Apache-2.0. Russian readme: [README.ru.md](README.ru.md).
