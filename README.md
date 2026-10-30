# Beckn evaluation workspace

Test-first evaluation of an open, domain-agnostic, server-to-server transaction
specification for decentralised marketplaces, using Beckn Protocol v2.0.0 as
the reference candidate. Stacks are judged by whether they pass the same
conformance scenarios, not by claims.

Independent project. Not affiliated with or endorsed by the Beckn or ONDC
owners; see [NOTICE](NOTICE).

## What is here
- `conformance/` Peppol-style certification runner and admission gate, DeDi onboarding generator
- `tests/scenarios/` HTTP-only conformance scenarios (JSON)
- `mockup/` reference Python node used to exercise the scenarios
- `packs/` domain schemas, policies and sample catalogs (data only)
- `viewer/` static transcript viewer
- `docs/` evaluation notes, audit findings and run logs

## The spec is not in this repository
The v2 specification is CC BY-NC-SA 4.0 and is not redistributed here. Clone it
yourself and point the tools at it:

```bash
git clone https://github.com/beckn/protocol-specifications-v2 vendor/protocol-specifications-v2
git -C vendor/protocol-specifications-v2 checkout a22300a
```

or set `BECKN_SPEC_DIR`. Commit `a22300a` is the one the tests were written
against (see `docs/mockup-findings.md`).

## Run the tests
```bash
pip install -r mockup/requirements.txt -r conformance/requirements.txt
python -m pytest conformance -q
(cd mockup && python -m pytest -q)
node --test viewer/test/viewer.test.js
```

The signing tests need PyNaCl (in the requirements files).

Details: `docs/conformance.md`, `docs/public-run.md`, `CLAUDE.md`.

## Licence
Original work: Apache-2.0 ([LICENSE](LICENSE)). Third-party material and
trademarks: [NOTICE](NOTICE).
