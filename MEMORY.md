# MEMORY.md

Project knowledge for the Beckn / decentralised-marketplace stack evaluation. Update as facts are verified. Items marked UNVERIFIED are from background knowledge and must be checked against the spec repo before being relied on.

## Goal
Pick or build a stack implementing an open, domain-agnostic, server-to-server transaction specification for decentralised marketplaces. Evaluation is test-driven (see [CLAUDE.md](CLAUDE.md)). The user will supply the candidate stack(s) to evaluate.

## Candidate spec: Beckn Protocol
- Open protocol for discovery and transactions between consumer-side apps (BAP) and provider-side platforms (BPP), domain-agnostic via pluggable domain schemas. Stewarded by the FIDE foundation / beckn.org. UNVERIFIED: current version (1.x vs 2.0) and governance details.
- Core flow (v1.x): `search` → `select` → `init` → `confirm` → `status` / `track` / `update` / `cancel` / `rating` / `support`. Each call is async: caller POSTs to the counterpart and receives an ACK, the real response arrives on an `on_<action>` callback. UNVERIFIED for 2.0.
- Message envelope: `context` (domain, action, versions, transaction_id, message_id, bap/bpp ids and URIs, timestamp, ttl) plus `message`. UNVERIFIED exact fields.
- Trust: requests signed (Authorization header, Ed25519 / BLAKE2b digest style), public keys discovered via a registry. UNVERIFIED.
- Reference implementation: Beckn-ONIX (Go, adapter/plugin architecture) under the beckn GitHub org. UNVERIFIED current status.

## Alternatives to compare if asked
Open Commerce / ONDC profile (Beckn-based, India), Shopify/UCP-style or ACP agent-commerce protocols, OpenAPI-defined bespoke specs. UNVERIFIED; do not rely on without research.

## Decisions
- 2026-10-27: Workspace initialised; harness is language-agnostic HTTP scenarios; no stack chosen yet.

## Open questions
- Which spec version to target?
- Which stack(s) does the user want evaluated?
- Local-only evaluation, or against a public sandbox/registry?
