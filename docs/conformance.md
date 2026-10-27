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
- Callback (`on_*`) behaviour is untested: the runner has no receiver endpoint to catch async callbacks yet.
- A BAP is only tested as a caller indirectly; BAP role scenarios need a test-bed that drives it.

## Status after the audit (docs/audit-conformance.md)
Fixed: F1 (profiles pin required scenario ids + content hashes; subset or altered runs are INCOMPLETE), F2 (reports signed by the operator key; `admit` takes participant, pinned profile and issuer public key, re-derives the verdict from results, rejects future `issued_at`), F3/F4 (`null` is a literal; operators `exists/type/enum/pattern`; strict jsonpath grammar with quoted keys; type-strict equality), F5 (scenario validation, unknown keys/levels/roles/faults are errors, files without `id` are errors), F6 (no redirects, no env proxies), F7/F8 (fixture containment, path and host checks), F9, F10, F11 (truncation, BOM-tolerant reads, identity files git-ignored), F12/F14 (replay resends a different `Authorization` header; `replay-new-body` keeps the messageId), F13 (DS scenarios `DISC-001`, `NEG-001..006`; PN scenarios `PNNEG-001..004` on `/select`), F15 partly (error codes asserted per fault), F17 (`status_in`, messageId echo, `Signature` response header pattern), F18/F19 (`scripts/test.ps1`).

Deliberate deviations from the audit: Nack `messageId` is asserted as a UUID only, not as an echo, because beckn.yaml requires the field on NackUnauthorized but does not say it echoes the request (the mockup returns a nil UUID before authentication). Ack `messageId` is an echo.

Response `Signature` (runner v3): every signed scenario now demands `expect.response_signature: {"chain": true}`, graded by `conformance/signing.check_response`: header parsed strictly (both the 'Signature ' and bare spellings accepted), `algorithm=ed25519`, `headers="(created) (expires) digest request-signature"`, BLAKE2b-512 digest of the response body, `request-signature` equal to the signature actually sent (including a deliberately faulted one), created/expires within a 5 s skew, Ed25519 signature checked against a key the operator supplies with `--sut-key KEYID=BASE64_PUBLIC_KEY` (or `sut_keys=`). The harness never fetches a registry URL named in a response header (pre-authentication SSRF), so without a supplied key the scenario fails with the remedy in its detail: a node cannot be CERTIFIED without proving its responses verify. Scenario hashes and both profiles were re-pinned.

Still open: the SUT's key is trusted by operator supply, not looked up in its registry (no revoke/rotate/expiry-of-key check); PN replay (`PNNEG-005`) is recommended+pending because it needs a catalog-valid `select`; registry-backed revoke/rotate; expiry/skew, wrong-algorithm and digest-mismatch negatives; PN lifecycle actions and `on_*` callbacks (no receiver, being built next); BAP role has no scenarios; an unauthenticated operator public-key distribution story.
