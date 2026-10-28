# MEMORY.md

Project knowledge for the Beckn / decentralised-marketplace stack evaluation. Update as facts are verified. Items marked UNVERIFIED are from background knowledge and must be checked against the spec repo before being relied on.

## Goal
Pick or build a stack implementing an open, domain-agnostic, server-to-server transaction specification for decentralised marketplaces. Evaluation is test-driven (see [CLAUDE.md](CLAUDE.md)). The user will supply the candidate stack(s) to evaluate.

## Candidate spec: Beckn Protocol
Verified 2026-10-27 against `vendor/protocol-specifications-v2` @ `a22300a` (`api/v2.0.0/beckn.yaml` = OpenAPI 3.1.1, plus Draft RFCs in `docs/`). Details and line references: [docs/mockup-findings.md](docs/mockup-findings.md).
- Open protocol for discovery and transactions between consumer-side apps (BAP, renamed **CN / Consumer Node** in v2) and provider-side platforms (BPP, renamed **PN / Provider Node**), domain-agnostic via pluggable domain schemas (JSON-LD `Attributes` bags). Version in that repo: **2.0.0** (`info.version`, `Context.version` const `2.0.0`); all RFCs are status Draft. UNVERIFIED: governance details (RFCs authored under Networks for Humanity; FIDE/beckn.org role not checked).
- Core flow (v2.0.0): `discover` → `select` → `init` → `confirm` → `status` / `track` / `update` / `cancel` / `rate` / `support`. v1 `search` became `discover` and goes CN → DS (Discovery Service) not CN → PN; `rating` became `rate`. Each call is async: caller POSTs `/<action>`, gets a synchronous `200 Ack` (or `202 AckNoCallback`, `400/401/403/429/500` Nack), and the real response arrives on `/on_<action>`. `update`/`cancel` support `context.try` preview + commit with `context.requestDigest`.
- Message envelope: `{context, message}`. Context fields are **camelCase**: `action`, `version`, `bapId`, `bapUri`, `bppId`, `bppUri`, `transactionId` (uuid), `messageId` (uuid), `networkId`, `timestamp` (RFC 3339), `ttl` (ISO 8601 duration), `try`, `requestDigest`, `schemaContext`, `key`, `senderId`, `receiverId`. Ack body: `{message:{status: ACK|NACK, messageId, error?}}`. Transactions use a `Contract` object (commitments, consideration, participants, performance, settlements), not v1 `order`.
- Trust: every request carries `Authorization: Signature keyId="{ns}/{registry}/{record}|ed25519",algorithm="ed25519",created,expires,headers="(created) (expires) digest",signature=...`; signing string is 3 lines with digest `BLAKE2b-512=<base64>`. Solicited callbacks add a 4th line `request-signature` (the CN's request signature); every synchronous response carries a signed `Signature` header chained the same way. Keys are resolved via a dedi-protocol registry (implicit keyIds: `https://fabric.nfh.global/registry/dedi/lookup/{keyId}`); no Beckn Gateway in v2.
- Reference implementation: Beckn-ONIX (Go, adapter/plugin architecture) under the beckn GitHub org. `vendor/starter-kit` configures `onix-generic-bap/bpp` with plugins `dediregistry`, `schemav2validator`, `signvalidator`, `signer`, so ONIX is the v2 reference adapter. UNVERIFIED: current release status and maintenance activity.

## Alternatives to compare if asked
Open Commerce / ONDC profile (Beckn-based, India), Shopify/UCP-style or ACP agent-commerce protocols, OpenAPI-defined bespoke specs. UNVERIFIED; do not rely on without research. Note: `vendor/ONDC-Official` material is Beckn v1-era (snake_case context, `BLAKE-512=` digest prefix, `subscriber|ukid|alg` keyIds), not wire-compatible with v2.0.0.

## Decisions
- 2026-10-27: Workspace initialised; harness is language-agnostic HTTP scenarios; no stack chosen yet.
- 2026-10-27: Target spec version **Beckn 2.0.0** (protocol-specifications-v2). Scenario 001 + `tests/fixtures/search.json` moved to the v2 `/discover` envelope. A Python reference mockup (registry, BAP, BPP, signing, schema validation) lives in `mockup/` with its own pytest suite (`mockup\.venv\Scripts\python -m pytest -q`); it is an oracle/test double, not a candidate stack.

## Open questions
- Which stack(s) does the user want evaluated?
- Local-only evaluation, or against a public sandbox/registry? (Spec hard-codes `fabric.nfh.global` for implicit keyIds; local testing needs a registry override.)
- Harness signing is done (`conformance/signing.py`); a real network still needs the harness identity registered, and a local registry override for `fabric.nfh.global`.
- Spec contradictions to raise upstream or pin a stance on (callback replay rules, digest prefix, Context required fields): see docs/mockup-findings.md.

## Domain packs (added 2026-10-27)
- `packs/` holds workspace-owned, experimental schemas (Produce, EnergySource, Listing and their *Terms types), laid out one dir per schema/version, with mandatory fields and vocabularies in `packs/policies/`; contexts under `packs.beckn-eval.invalid`. UNVERIFIED against upstream beckn/schemas and beckn/DEG (energy placeholders to be replaced by DEG). See docs/domain-packs.md.
- BPP serves a multi-catalog `CatalogStore` (mockup/beckn_mock/catalogstore.py); only `textSearch` discovery is implemented.

- DeDi onboarding generator/validator: conformance/dedi.py (docs/dedi-onboarding.md). Signing follows the spec text but is not cross-checked against another implementation; upstream example signatures are placeholders.

- Test figures as of 2026-10-27 (Windows, local): mockup + conformance together 533 passed / 1 skipped / 10 xfailed (after the lot ledger; 481 before it); viewer 12 passed. Linux not re-run since the line-ending hash fix. The 10 xfails are strict spec-gap checks, not mockup bugs.
