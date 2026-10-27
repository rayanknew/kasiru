# Changelog

## 0.1.1 — 2026-10-27

- Keyless (proxy-trusted) clients: a reverse proxy that authenticates callers sets `X-Client`, and a client entry without a key is matched by that name from loopback.
- `embeddings.url`: `/v1/embeddings` is proxied to a local embeddings server (never to the cloud).

## 0.1.0 — 2026-10-27

First public release.

- OpenAI-compatible gateway with data classes (`secret` / `personal` / `public`) and tiers with a local last resort.
- Four-layer reversible pseudonymisation: validated identifiers, lemma-matched dictionary, Russian and Ukrainian NER, secret markup; persistent tokens; leak check before sending; split mode.
- Tool calls pass through; restoration inside tool-call arguments; real streaming on local routes.
- Client keys with forced or default class, default tier and admin flag.
- Daily quotas per backend (requests, tokens, cost), cool-downs, per-backend concurrency, per-model prices.
- Audit log without content, `kasiru report`, `kasiru scrub`, `kasiru entities`, `kasiru check`, `kasiru init`.
- Service templates for launchd and systemd.
