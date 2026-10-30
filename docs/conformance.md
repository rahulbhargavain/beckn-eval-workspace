# Conformance and admission (Peppol-style)

Flow: participant -> runs scenarios for its role against its test endpoint -> report
(`conformance/runner.py`) -> registry calls `runner.admit(report, spec, role)` before
registering keys/endpoints.

- **Scenario fields:** `id`, `level` (`mandatory`|`recommended`), `roles` (`BAP`/`BPP`), `spec`, `request`, `expect`, optional `pending`.
- **Verdicts:** `CERTIFIED` (all applicable mandatory pass), `FAILED`, `INCOMPLETE` (a mandatory scenario is pending, or none apply). Recommended failures only warn.
- **Admission checks:** digest intact, verdict CERTIFIED, spec and role match, report under 90 days old.
- **Signed scenarios:** `request.auth = "beckn-http-signature"` makes the runner template `context.bapId/bapUri/networkId/messageId` (fresh UUID) from `--identity` and sign the exact body bytes (`conformance/signing.py`, independent of the mockup). A missing identity FAILS the scenario. Identity file: `key_id`, `private_key_seed_b64`, `bap_id`, `bap_uri`, `network_id`; keep it out of git and register its public key in the target network's registry. Requires `pip install -r conformance/requirements.txt`.
- **Run:** `python -m conformance.runner --base-url http://127.0.0.1:8080 --profile conformance/profiles/bpp-core.json --participant my-bpp --out report.json`; self-tests: `mockup/.venv/Scripts/python -m pytest conformance` (the signing tests need PyNaCl). `mockup/tests/test_conformance_runner.py` proves the runner against the independent mockup BPP.

## Known gaps vs Peppol
- The digest is tamper-evidence only, not authentication. Reports must be signed by the test-bed operator (Ed25519) and the registry must pin that key. Not implemented.
- Test endpoints are exercised, but there is no proof the production endpoint behaves the same; add periodic re-certification and sampled production probes.
- Only HTTP status and JSONPath-lite are asserted. Schema validation, signature-verification negative tests, replay and SSRF scenarios still have to be added as mandatory scenarios (the mockup agent's tests are the source).
- Scenario files lacking `id` are ignored by the loader.
- Scenarios: `DISC-001` plus `NEG-001..005` (bad signature, unknown participant, replay, invalid JSON, missing `message`), selected with `request.fault`. A permissive server fails them (covered by tests). Statuses: 401 for the two auth faults is partly an assumption (spec fixes 400 only for replay, 10.1). Still missing: schema-level negatives, SSRF via bapUri, expiry/skew, impersonation (signer not matching bapId), and the other lifecycle actions.
- Callback (`on_*`) behaviour is tested only through one recommended scenario (`CB-001`, discover → `on_discover`) and only against a node that can reach this machine's loopback. See "Async callbacks" below.
- A BAP is only tested as a caller indirectly; BAP role scenarios need a test-bed that drives it.

## Status after the audit (docs/audit-conformance.md)
Fixed: F1 (profiles pin required scenario ids + content hashes; subset or altered runs are INCOMPLETE), F2 (reports signed by the operator key; `admit` takes participant, pinned profile and issuer public key, re-derives the verdict from results, rejects future `issued_at`), F3/F4 (`null` is a literal; operators `exists/type/enum/pattern`; strict jsonpath grammar with quoted keys; type-strict equality), F5 (scenario validation, unknown keys/levels/roles/faults are errors, files without `id` are errors), F6 (no redirects, no env proxies), F7/F8 (fixture containment, path and host checks), F9, F10, F11 (truncation, BOM-tolerant reads, identity files git-ignored), F12/F14 (replay resends a different `Authorization` header; `replay-new-body` keeps the messageId), F13 (DS scenarios `DISC-001`, `NEG-001..006`; PN scenarios `PNNEG-001..004` on `/select`), F15 partly (error codes asserted per fault), F17 (`status_in`, messageId echo, `Signature` response header pattern), F18/F19 (`scripts/test.ps1`).

Deliberate deviations from the audit: Nack `messageId` is asserted as a UUID only, not as an echo, because beckn.yaml requires the field on NackUnauthorized but does not say it echoes the request (the mockup returns a nil UUID before authentication). Ack `messageId` is an echo.

Response `Signature` (runner v3): every signed scenario now demands `expect.response_signature: {"chain": true}`, graded by `conformance/signing.check_response`: header parsed strictly (both the 'Signature ' and bare spellings accepted), `algorithm=ed25519`, `headers="(created) (expires) digest request-signature"`, BLAKE2b-512 digest of the response body, `request-signature` equal to the signature actually sent (including a deliberately faulted one), created/expires within a 5 s skew, Ed25519 signature checked against a key the operator supplies with `--sut-key KEYID=BASE64_PUBLIC_KEY` (or `sut_keys=`). The harness never fetches a registry URL named in a response header (pre-authentication SSRF), so without a supplied key the scenario fails with the remedy in its detail: a node cannot be CERTIFIED without proving its responses verify. Scenario hashes and both profiles were re-pinned. Hardening from the first external audit: the runner refuses credentials in `base_url` and fails any scenario whose response exceeds 1 MiB; `admit` also refuses probe runs, reports with problems and duplicate result ids.

Still open: the SUT's key is trusted by operator supply, not looked up in its registry (no revoke/rotate/expiry-of-key check); PN replay (`PNNEG-005`) is recommended+pending because it needs a catalog-valid `select`; registry-backed revoke/rotate; expiry/skew, wrong-algorithm and digest-mismatch negatives; PN lifecycle actions and `on_*` callbacks beyond `CB-001` (the receiver is local-only; a remote node cannot reach it); BAP role has no scenarios; an unauthenticated operator public-key distribution story.

## Provider lifecycle (LIFE-001) and the seed

`LIFE-001` is mandatory in `bpp-core`. It is one signed transaction: `select`, `init`, `confirm`, `status`. Each request after the first is built from the callback the node sent for the step before, so a node that ACKs and never calls back fails at the first step. It uses the local callback listener, so the same loopback limits apply (below).

What it asserts comes from the spec (`api/v2.0.0/beckn.yaml` at a22300a): every callback echoes `context.transactionId` and carries the right `context.action`; `init` and `confirm` callbacks carry a UUID `contract.id`; the `on_confirm` contract has `status.code` `ACTIVE` and a `performance` array; the `on_status` contract has the same id that `on_confirm` assigned. Not yet asserted: schema validation of the whole callback body, `cancel`, `track`, `update`, `rate`, `support`.

The catalog and the payment evidence are specific to each node, so the operator supplies a **seed** file (`--seed seed.json`). Without it `LIFE-001` FAILS and says so; it is never skipped. Seed shape (all keys optional except `select`):

```json
{
  "context": {"bppId": "bpp.example.org", "bppUri": "http://127.0.0.1:8080"},
  "select":  {"contract": {"commitments": [ ... a Commitment the node will accept, with resource id and quantity ... ]}},
  "init":    {"contract": {"participants": [ ... the buyer ... ]}},
  "confirm": {"settlementsPatch": {"status": "COMMITTED"}}
}
```

`context` is merged into every request context. `init.contract` and `confirm` values are deep-merged onto the contract the node returned. `settlementsPatch` is applied to every settlement in the contract sent with `confirm`; what counts as payment evidence is domain-specific (UNVERIFIED which settlement status the spec expects there), so the operator states it. The seed is not part of the report.

## Async callbacks (local-only receiver)

A scenario can say `expect.callback: {"action": "on_discover", "within": 5, "jsonpath": {...}}`. The runner then starts `conformance/callbacks.py`, a listener on **127.0.0.1 only**, and the scenario passes only if the node's `on_*` POST arrives in time and verifies.

- **Setup.** The identity's `bap_uri` must be `http://127.0.0.1:<port>`, and that is the URL registered for the identity (a node checks `bapUri` against the registry). The runner binds exactly that port. The node must also be willing to call it (its own SSRF policy may need that origin allow-listed). The target must be loopback too; otherwise the scenario fails with an explanation instead of silently passing.
- **What is checked.** A callback is accepted only for a `messageId` the runner just sent, and only once. Its `Authorization` must be `(created) (expires) digest request-signature`, over the received body, chained to the signature the runner sent, by a key given with `--sut-key` (never fetched). Same rules as the response `Signature` check, including no grace after `expires`. The first verdict for a message stands, so a refused callback cannot be retried into a pass.
- **Limits.** Body cap 1 MiB; only `POST /on_<action>`; `context.action` must equal the path. The Ack the listener returns is unsigned (UNVERIFIED whether a node requires a signed Ack). A remote node needs a public callback URL, which this does not provide. `CB-001` is `recommended` and pinned in no profile.
