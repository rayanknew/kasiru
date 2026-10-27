# Architecture

```
┌─ clients ─────────────────────────────────────────────────────────────────┐
│ any OpenAI-compatible SDK · agents with tools · scripts · chat UIs        │
│ know: the gateway address, their key, a tier, a data class               │
└───────────────┬───────────────────────────────────────────────────────────┘
                │ POST /v1/chat/completions  (+ /health, /v1/models, /v1/kasiru/*)
┌─ server.py ───┴───────────────────────────────────────────────────────────┐
│ auth by client key · admin paths · SSE · optional /api/* pass-through     │
├─ pipeline.py ─────────────────────────────────────────────────────────────┤
│ classify → protect → route+call → restore → audit → respond               │
│      │         │          │           │                                   │
│      │   privacy/core   router.py  privacy.unscrub                        │
│      │   4 layers,      candidates, quotas, cool-downs, semaphores        │
│      │   tokens,        backends.py: openai / ollama, streaming           │
│      │   leak check                                                       │
├─ audit.py ────────────────────────────────────────────────────────────────┤
│ one JSON line per request, never the text                                 │
└───────────────────────────────────────────────────────────────────────────┘
   state: tokens.json · quota.json · ner_cache.json      config: kasiru.json · env · entities.json
```

## Principles

1. **Data class over file path.** Not "this folder never goes to the cloud" but "class `secret` never leaves".
2. **Tier over model.** Clients ask for `cheap`; which model answers is config.
3. **One decision point.** Pseudonymisation, routing, quotas, cost and the audit live in the gateway. Client code holds no provider rules.
4. **Local is always last.** The system degrades into slow, never into unavailable, and never into "send it anyway".
5. **Audit without content.** What went where, how much, how many replacements, zero leaks; never the text.
6. **Free and local before paid.** The order of candidates in a tier is the spending policy.
7. **The owner decides, the system proposes.** The detector feeds the dictionary; the review commands are the owner's.

## Module map

| Module | Lines of responsibility |
|---|---|
| `config.py` | paths, defaults, validation (a cloud backend may never accept `secret`) |
| `server.py` | HTTP, auth, streaming transport |
| `pipeline.py` | the stages and plugin hooks |
| `router.py` | candidates, quotas, cool-downs, per-backend concurrency, prices |
| `backends.py` | upstream calls, tool-call pass-through, loop detection |
| `privacy/core.py` | the four layers, tokens, leak check |
| `privacy/patterns.py` | identifiers and validators |
| `privacy/lemma.py` | the reference lemmatizer (ru / uk / en) |
| `privacy/ner_ru.py`, `ner_uk.py` | detectors and lemma-based dictionary matching |
| `audit.py` | the log |
| `cli.py` | `init`, `serve`, `check`, `scrub`, `entities`, `report` |
