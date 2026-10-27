# CLAUDE.md

Evaluation workspace for an **open, domain-agnostic, server-to-server transaction specification** for decentralised marketplaces (Beckn Protocol as the reference candidate). Goal: judge candidate stacks by whether they pass the same conformance tests, not by claims.

Read [MEMORY.md](MEMORY.md) first: it holds the domain background and decisions so far.

## Working rules
- **Test-first.** Every stack-evaluation claim must be backed by a scenario in `tests/scenarios/`. Write or update the scenario before the code, and show the failing run before the passing one.
- **Stack-agnostic harness.** Scenarios are JSON (request, expected-response assertions) and must not assume a language. Each candidate stack gets its own adapter under `stacks/<name>/` (not created yet) exposing the same HTTP endpoints; the harness only speaks HTTP.
- **Spec is the oracle.** Assertions come from the spec's schemas and flows, not from what a given implementation happens to return. Record the spec version a scenario targets in its `spec` field.
- **No invented facts.** If a protocol detail (field name, version, endpoint) is not verified against the spec repo or a fixture, mark it `UNVERIFIED` in MEMORY.md rather than asserting it.
- Small commits; one scenario or one stack adapter per commit.

## Layout
- `tests/scenarios/` conformance scenarios (JSON), see `tests/README.md`
- `tests/fixtures/` sample payloads and signed-message vectors
- `docs/` evaluation notes and stack comparisons
- `conformance/` Peppol-style certification runner and admission gate (see `docs/conformance.md`)
- `packs/` domain schemas, policies and sample catalogs (data only; see `docs/domain-packs.md`)
- `scripts/` runners (`scripts/test.ps1`; add a stack-specific unit-test command here once a stack is chosen)

## Commands
- `pwsh scripts/test.ps1 -BaseUrl http://localhost:8080 -Participant me -Identity id.json` runs all scenarios against a running adapter (see `docs/conformance.md`; needs the mockup venv or PyNaCl).

## Evaluation criteria (apply to any stack)
1. Spec conformance: full transaction lifecycle (discover → select → init → confirm → status/track/update/cancel/rating/support), async callback model.
2. Message integrity: signing and verification of server-to-server requests, registry/key lookup.
3. Domain-agnosticism: new domains added via schema/config, not core code changes.
4. Operability: deployment footprint, observability, licence, maintenance activity.
5. Stability: release cadence and breaking-change history.
