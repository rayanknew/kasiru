# The privacy layer

## Data classes

| Class | Where it may go | What happens to the text |
|---|---|---|
| `secret` | local backends only | nothing |
| `personal` | cloud candidates of the tier, after the leak check | four layers, reversible |
| `public` | cloud as is | only secret markup is cut out |

The class is decided once, in `Pipeline.classify`: a client's forced `class` wins, then the `X-Data-Class` header
or `data_class` body field, then the client's `default_class`, then the global default.

## Four layers

1. **Patterns with validators** (`privacy/patterns.py`): e-mail, Telegram links, URLs carrying tokens, IBAN (checksum),
   cards (Luhn), API keys of common providers, bot tokens, JWT, PEM blocks, `password: …`, long hex strings, BIP39 seed
   phrases, crypto wallets (Bitcoin with checksum; EVM, Tron, TON, Monero, Litecoin, Dogecoin, XRP, Cardano, Cosmos,
   Solana by shape), company registration codes, `@usernames`, postal addresses (street type + name + number;
   cities are left alone). Phones go through `phonenumbers` for the configured regions, or a fallback regex.
2. **The owner's dictionary** (`entities.json`): `persons`, `orgs`, `terms`, `ignore`, `pending`, `auto`. Matching is
   by lemma when Natasha is installed (so inflected forms, a surname alone, an organisation without its legal form all
   match), and by stem regex otherwise. ё and е are interchangeable; hyphenated words are split.
3. **Local detector**: Natasha/Slovnet for Russian (PER/ORG/LOC, nominative normalisation), spaCy `uk_core_news_lg` for
   Ukrainian (only when the text contains Ukrainian letters), deterministic rules (legal form + name, First Patronymic
   Last), or a local LLM through Ollama. Places are used to drop false persons. Hits pass a junk filter driven by the
   reference lemmatizer (`privacy/lemma.py`): participles, verbs, common nouns are not names. New hits join the
   dictionary: with `protect_all` they are active at once; otherwise only confident hits (first + last name, legal
   form) are, and single names wait in `pending`.
4. **Secret markup**: a line containing any of `secret_markers` and `<secret>…</secret>` blocks are removed from the
   text for the cloud. In `local` mode (default) their presence forces the whole request local, unscrubbed. In `split`
   mode the removed parts are sent to the local model separately and appended to the cloud answer under a heading.
   Markers inside system messages are instructions, not data, and are left alone.

## Tokens

`[label-N]`, one per entity kind and canonical value, stored in `<state>/tokens.json` with the real value. The same
person gets the same token in every request, so the cloud model can reason about relations. `unscrub` restores values
in `content` (string or parts) and in `tool_calls[].function.arguments`, case-insensitively and tolerating spaces
around the hyphen. Tokens of entities the owner removed from the dictionary are purged on reload.

## The leak check

Before every cloud call the cleaned messages are searched for every active value longer than four characters, by word
boundary, folded for case and ё/е. Any hit skips that candidate; the request continues down the tier and ends on the
local backend. The audit line records `forced_local: leak` and the log names the kinds involved.

Symmetry rule: every filter that the leak check applies must be matched by the substitution, and vice versa. A
dictionary entry the regex cannot match but the leak check can see would push every request local without an error;
the golden set checks `leak_check(scrub(text)) == 0` for all cases.

## Reviewing the dictionary

```
kasiru entities              # counts
kasiru entities pending      # numbered hits waiting for a decision
kasiru entities keep 3,7-9   # activate
kasiru entities ignore 1-40  # never propose again
kasiru entities auto         # what protect_all activated by itself
kasiru entities demote 2     # auto-activated -> ignore
kasiru entities add person "Jane Example"
curl -s -X POST http://127.0.0.1:8081/v1/kasiru/reload -H "Authorization: Bearer $KASIRU_KEY_ADMIN"
```

## Adding a language

1. Extend `lemma.lang_of` and `lemma.analyze` with a morphology (or an exact-form fallback) for the language.
2. Add a detector module next to `ner_ru.py` / `ner_uk.py` returning `{"persons", "orgs", "locs"}` and wire it into
   `Privacy.ner`.
3. Add cases to `tests/golden_privacy.py`: what must disappear, what must stay.

## What the layer does not promise

Detection is statistical; a name the detector misses and the dictionary does not know will leave in clear text under
`personal`. Use `secret` for anything that must not leave, and `kasiru scrub` to inspect what the cloud would see.
