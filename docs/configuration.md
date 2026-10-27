# Configuration

`$KASIRU_CONF_DIR/kasiru.json` (default `~/.config/kasiru/kasiru.json`). Keys live in `$KASIRU_CONF_DIR/env`
(`KEY=VALUE`, mode 0600); the process environment overrides the file. State (`tokens.json`, `quota.json`, `ner_cache.json`)
goes to `$KASIRU_STATE_DIR` (default `~/.local/state/kasiru`).

## Top level

| Field | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:8081` | bind address |
| `default_class` | `personal` | data class when neither the client nor the request names one |
| `audit_file` | `<state>/audit.jsonl` | one JSON line per request, no text |
| `ollama_url` | none | when set, `/api/*` and `/v1/embeddings` are proxied to this Ollama for legacy clients |
| `max_body_mb` | 64 | request size limit |
| `plugins` | `[]` | `"module:Class"` hooks, see [plugins.md](plugins.md) |

## `backends`

```json
"groq": {
  "kind": "openai",                      // openai (any OpenAI-compatible chat endpoint) | ollama (native /api/chat)
  "url": "https://api.groq.com/openai/v1",
  "key": "GROQ_API_KEY",                 // name of the variable in env; omit for keyless local servers
  "local": false,                        // true = runs on this machine: no pseudonymisation, may take secret
  "classes": ["personal", "public"],     // which data classes may be sent here; secret is allowed only for local
  "daily_requests": 900, "daily_tokens": 180000, "daily_cost": 1.0,
  "cooldown_s": 600,                     // pause after 429 (if the provider gives no retry-after) and after 5xx
  "price_in": 0.09, "price_out": 0.18,   // $ per million tokens, used for cost accounting and daily_cost
  "prices": {"model-name": {"in": 0.05, "out": 0.45}},   // per-model override
  "max_output": 8192,                    // cap the client's max_tokens
  "max_parallel": 1,                     // semaphore; a single-slot local server queues instead of failing
  "queue_timeout_s": 600,
  "timeout_s": 1800,
  "extra": {"reasoning": {"enabled": false}},   // merged into every request body for this backend
  "headers": {"HTTP-Referer": "https://example.org"},
  "allow_tools": false                   // let tools/tool_calls go to this cloud backend for personal data too
}
```

The `ollama` kind uses `url` (or the top-level `ollama_url`) and the native API with `num_ctx` chosen from the request
size in steps (16k / 32k / 64k) so a model is not reloaded on every call. It does not stream through Kasiru.

## `tiers`

Ordered candidate lists of `backend:model`. `tiers.local[0]` must be a local backend; it is appended to every tier
and used for the split-mode secret part. A request may also name `backend:model` directly or a bare model name
(then it means that model on the default local backend).

```json
"tiers": {
  "local": ["llama:qwen3.5-9b"],
  "cheap": ["groq:openai/gpt-oss-120b", "gemini:gemini-3.6-flash", "llama:qwen3.5-9b"],
  "best":  ["openrouter:deepseek/deepseek-v4-flash", "llama:qwen3.5-9b"]
}
```

A candidate is skipped when: the data class is not in its `classes`; the key is missing; a daily limit is spent;
it is cooling down; the leak check finds a protected value in the cleaned text (then the request continues to the
next candidate and ends up local); the request carries `tools` and the backend is a cloud without `allow_tools`
(for `personal`). Errors: 429 → cool-down for `retry-after` or `cooldown_s`; 502/503/529 → one retry after 7 s;
other 5xx → cool-down; network errors → one retry; a looping local answer → one retry with anti-repeat sampling.

## `clients`

```json
"clients": {
  "agent":   {"key_env": "KASIRU_KEY_AGENT", "class": "secret", "default_tier": "local"},
  "scripts": {"key": "literal-key", "default_class": "personal", "secret_mode": "split"},
  "admin":   {"key_env": "KASIRU_KEY_ADMIN", "admin": true}
}
```

| Field | Meaning |
|---|---|
| `key` / `key_env` | the bearer key, literal or from env |
| `class` | forced data class: the client cannot override it |
| `default_class` | used when the request names none |
| `default_tier` | used when the request names no model |
| `secret_mode` | `local` (default) or `split` |
| `admin` | may call `/v1/kasiru/entities` and `/v1/kasiru/reload` |

A client entry without `key` / `key_env` is *proxy-trusted*: a reverse proxy that checks keys itself sets `X-Client`
to that name, and Kasiru accepts it from loopback connections only. With `clients` empty the gateway trusts whoever
can connect. A loopback connection without any key or `X-Client` is the local administrator.

`"embeddings": {"url": "http://127.0.0.1:8084/v1"}` proxies `/v1/embeddings` to a local embeddings server; without it
the request goes to `ollama_url` like other `/api/*` paths.

## `privacy`

| Field | Default | Meaning |
|---|---|---|
| `ner` | `auto` | `natasha` (ru + uk when installed), `ollama` (local LLM detector, needs `ner_model`), `off`; `auto` picks the first available |
| `ner_model` | none | Ollama model for the LLM detector |
| `ner_classes` | `["personal"]` | data classes for which the detector runs |
| `protect_all` | true | every detector hit becomes active; otherwise weak hits (single names) wait in `pending` |
| `token_labels` | `{}` | labels inside tokens, e.g. `{"person": "персона"}` → `[персона-7]` |
| `secret_markers` | `["[secret]", "[чувствительно]", "[конфиденциально]"]` | line markers that keep a line local |
| `phone_regions` | `["US","GB","DE","UA","RU","TR"]` | regions for local-format phone detection |
| `generic_words` | `[]` | extra words the detector must never treat as names |

## Request fields

Headers `X-Data-Class`, `X-Project`, `X-Stage`, `X-Secret-Mode`; the same as body fields `data_class`, `project`,
`stage`, `secret_mode` (body fields are stripped before the request goes upstream). `stage` and `project` only label the
audit line and the report.

## Service paths

| Path | Who | What |
|---|---|---|
| `GET /health` | anyone | local backends reachable, dictionary size, detector |
| `GET /v1/models` | client | tiers and candidates |
| `POST /v1/chat/completions` | client | the gateway |
| `GET /v1/kasiru/stats` | client | today's quotas, cool-downs, dictionary and token counters |
| `GET /v1/kasiru/entities` | admin | the dictionary |
| `POST /v1/kasiru/reload` | admin | reload config and dictionary, purge stale tokens |
