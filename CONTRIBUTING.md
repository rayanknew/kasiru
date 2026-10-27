# Contributing

Thank you for looking. Kasiru is small on purpose; contributions that keep it small are the most welcome.

## Ground rules

- The core stays standard-library only. Optional features go behind extras in `pyproject.toml`.
- No request or response text may ever be written to disk or logs by the gateway. A change that does so will not be merged.
- Every filter must stay symmetric: if you teach the substitution a new form, teach the leak check the same, and add a
  golden case proving `leak_check(scrub(text)) == 0`.
- Config over code: a new provider is a `backends` entry, not a Python change.

## Running tests

```bash
python3 -m unittest discover -s tests          # no optional dependencies needed
pip install -e ".[ru,ids]" && python3 tests/golden_privacy.py   # the privacy regression set
```

## Good first contributions

- a language adapter (`privacy/lemma.py` + a detector module + golden cases);
- a validator for an identifier type your country uses;
- `allowed_fails` threshold for cool-downs; per-client budgets;
- streaming restoration for cloud routes (token-boundary aware);
- a report endpoint.

## Pull requests

One topic per PR, tests included, a line in `CHANGELOG.md`. Describe the failure you saw before the fix when it is a bug.
Synthetic data only in tests and docs: never real names, numbers or keys.
