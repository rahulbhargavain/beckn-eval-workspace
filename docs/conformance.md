# Conformance and admission (Peppol-style)

Flow: participant -> runs scenarios for its role against its test endpoint -> report
(`conformance/runner.py`) -> registry calls `runner.admit(report, spec, role)` before
registering keys/endpoints.

- **Scenario fields:** `id`, `level` (`mandatory`|`recommended`), `roles` (`BAP`/`BPP`), `spec`, `request`, `expect`, optional `pending`.
- **Verdicts:** `CERTIFIED` (all applicable mandatory pass), `FAILED`, `INCOMPLETE` (a mandatory scenario is pending, or none apply). Recommended failures only warn.
- **Admission checks:** digest intact, verdict CERTIFIED, spec and role match, report under 90 days old.
- **Run:** `python -m conformance.runner --base-url http://127.0.0.1:8080 --profile conformance/profiles/bpp-core.json --participant my-bpp --out report.json`; self-tests: `python -m pytest conformance`.

## Known gaps vs Peppol
- The digest is tamper-evidence only, not authentication. Reports must be signed by the test-bed operator (Ed25519) and the registry must pin that key. Not implemented.
- Test endpoints are exercised, but there is no proof the production endpoint behaves the same; add periodic re-certification and sampled production probes.
- Only HTTP status and JSONPath-lite are asserted. Schema validation, signature-verification negative tests, replay and SSRF scenarios still have to be added as mandatory scenarios (the mockup agent's tests are the source).
- `spec` in profiles is a placeholder until the spec version is verified.
- Scenario files lacking `id` (e.g. the legacy 001) are ignored by the loader.
- A BAP is only tested as a caller indirectly; BAP role scenarios need a test-bed that drives it.
