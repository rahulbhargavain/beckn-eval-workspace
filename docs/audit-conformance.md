# Audit: conformance harness (2026-10-27)

Scope: `conformance/` (runner.py, signing.py, tests/, profiles/), `tests/scenarios/*.json`, `tests/fixtures/search.json`, `scripts/test.ps1`, `docs/conformance.md`, `mockup/tests/test_conformance_runner.py`. Repo at `6cda368`. Spec oracle: `vendor/protocol-specifications-v2` @ `a22300a` (read only, nothing in it was run).

Abbreviations: **Y** = `vendor/protocol-specifications-v2/api/v2.0.0/beckn.yaml`, **A** = `vendor/.../docs/Authentication_and_Trust.md`, **C** = `vendor/.../docs/Communication_Protocol.md`, **R** = `conformance/runner.py`.

Baseline: `mockup\.venv\Scripts\python -m pytest conformance -q` gives 34 passed. `mockup/tests/test_conformance_runner.py` gives 2 passed.

Reproductions were run from throwaway scripts in the session scratchpad (`exp.py`, `e7.py`, `t.ps1`). They drive `runner.run` / `runner.admit` against local mutant HTTP servers. Each finding is tagged **[verified]** (reproduced or read directly in code or spec) or **[inferred]** (reasoned, not executed).

---

## Headline false pass: a server that breaks several MUSTs is CERTIFIED [verified]

This mutant server is CERTIFIED by the repo scenarios (DISC-001, NEG-001..005) in 5 of 5 runs, and `admit()` returns `(True, "ok")`:
- It verifies the signature against one hard-coded key. It does no registry lookup at all.
- Its replay cache is keyed on the raw `Authorization` header string, not on `messageId`.
- Its Ack/Nack bodies have **no `messageId`**, although Y:4109, 4178, 4209 require it.
- Every Nack carries `error.code: "X"`, which is not in the ErrorCode enum (Y:4250-4330, "MUST be one of these values" Y:3277). It also omits `error.message`, which Y:3271-3273 requires.
- It sends **no `Signature` response header**, which is MUST under CON-004-02 and CON-004-23 (A:444, A:466) and `required: true` at Y:2080.

The variants with `error.code: null` (Finding 3) and with a body-hash replay cache also certify. The findings below break this down.

---

## 1. Runner / signing / admit correctness

### F1. Critical: certification is not bound to a scenario set; `--scenarios` is participant-controlled [verified]
- Evidence: R:193 (`--scenarios` default, overridable). R:143-169: `run` certifies "all applicable mandatory scenarios" of whatever list it is given. The profiles (`conformance/profiles/bpp-core.json:1`) list no required scenario IDs. The report (R:165-167) records neither scenario IDs/hashes nor a runner version. `admit` (R:172-184) never checks `results` against a required set.
- Repro: `runner.run([DISC-001 only], bpp-core, ...)` gives `CERTIFIED`, and `admit(...)` returns `(True, 'ok')`. `results: []` with `verdict: CERTIFIED` and a recomputed digest is also admitted (E5/E5b).
- Fix: the profile declares `required: [{id, sha256-of-scenario-file}]`. `run` marks any missing or altered required scenario INCOMPLETE. The report embeds the scenario hashes, runner version and spec commit. `admit` re-derives the verdict from `results` against the registry's own copy of the profile.

### F2. Critical: anyone can forge a report; `admit` does not check participant identity or future timestamps [verified]
- Evidence: R:138-140 is an unkeyed sha256 over the report, so anyone can recompute it. This is acknowledged in `docs/conformance.md:14`, but it is still the whole admission control. `admit(report, spec, role)` (R:172) has no participant parameter, so participant A's report admits B. R:182 only rejects old reports: `now - issued_at` is negative for a future `issued_at`, and that passes. `run(now=...)` (R:143,166) lets the caller choose `issued_at`.
- Repro: a hand-built report with `participant: "someone-else"`, `issued_at` 10 years in the future and `results: []` is admitted, and still admitted 5 years later (E5b).
- Fix: the test-bed operator signs reports with Ed25519 and the registry pins that key. `admit` takes the registering `participant` (and key_id/endpoint) and compares. Reject `issued_at > now + skew`. Bind `base_url` and the harness `key_id` into the report.

### F3. High: `null` in `expect.jsonpath` means "exists", and a JSON `null` value satisfies it [verified]
- Evidence: R:133 `if got is MISSING or (want is not None and got != want)`. A present key whose value is `null` returns `None`, not `MISSING`, so it passes. That makes `"$.message.error.code": null` (all NEG scenarios, e.g. `tests/scenarios/neg-001-bad-signature.json:21`) pass for `{"error":{"code":null}}`. It also means no scenario can assert "value is null".
- Repro: a mutant returning `{"message":{"status":"NACK","error":{"code":null}}}` certifies (E2).
- Fix: replace the `None` sentinel with explicit operators, e.g. `{"$.message.error.code": {"exists": true, "type": "string", "enum": [...]}}` or `{"pattern": "^AUT_"}`. Treat `null` as a literal.

### F4. Medium: jsonpath-lite silently skips tokens it cannot parse (fail-open) [verified]
- Evidence: R:30. `re.findall` drops anything that does not match `.name` or `[n]`.
- Repro (E9):
  - `$.message.@type` returns the whole `message` object, so a `null` "exists" check passes.
  - `$['message']` returns the root document.
  - The typo `$message.status` resolves to root `status`.
  - `$.message.status[0]` indexes into the string and gives `"A"`.
  - `beckn:id` keys are unreachable. That is fail-closed, but it blocks JSON-LD assertions on `@type`, `@context` and `prefix:name` attributes, which v2 payloads use.
  - Equality uses Python `==`, so `want: true` matches `got: 1`.
- Fix: validate the path against a full grammar such as `^\$(\.[^.\[\]]+|\[\d+\])*$` and raise on mismatch. Support quoted keys. Compare with `type(got) is type(want)` for bool/int.

### F5. Medium: a level or role typo silently downgrades or drops a mandatory scenario [verified]
- Evidence: R:149 treats any `level` other than exactly `"mandatory"` as recommended. R:145 matches roles case-sensitively. Unknown fields are accepted.
- Repro (E4):
  - `level: "Mandatory"` with a failing request gives `CERTIFIED` with only a warning.
  - `roles: ["bpp"]` drops the scenario, and the run is still `CERTIFIED`.
- Fix: validate each scenario against a JSON Schema at load time (enums for `level`, `roles`, `fault`; required `id`, `request`, `expect`). Fail loading on an unknown or misspelled value. Also stop ignoring files without `id` (R:42, `docs/conformance.md:17`), because a file whose `id` was deleted silently drops out of coverage.

### F6. Medium: redirects are followed, and the redirect target's answer is graded with the `Authorization` header forwarded [verified]
- Evidence: R:79-86 uses the default `urllib.request.urlopen`, which handles 301/302/303 by re-issuing as GET without a body. The `Authorization` header goes to the new host as well.
- Repro: the SUT answers `302 Location: <other server>`. The other server returns `200 ACK`. DISC-001 passes and the run is `CERTIFIED`. The second server received the signed `Authorization` header (E8).
- Fix: build an opener without `HTTPRedirectHandler` (or with one that raises), and treat any 3xx as a failure. Also disable environment proxies (`ProxyHandler({})`), since urllib honours `HTTP(S)_PROXY` [inferred: standard urllib behaviour, not run].

### F7. Medium: scenario `body` path traversal can exfiltrate local files, including the signing seed [verified]
- Evidence: R:52-53 `Path(fixtures_root) / body` with no containment check. An absolute path replaces the root entirely.
- Repro: `body: "../identity.json"` or an absolute path to the identity file makes the runner POST the file, `private_key_seed_b64` included, to `base_url` (E6, both cases True). This matters once scenario packs come from anyone other than the operator, or `--scenarios` points at a participant-supplied directory (see F1).
- Fix: `p = (root / body).resolve()` and require `p.is_relative_to(root.resolve())`. Reject absolute paths. Never place the identity file under the fixtures root.

### F8. Low: `base_url + path` is plain string concatenation, so the host can change [verified]
- Evidence: R:80.
- Repro: base `http://sut.example` with path `.attacker.test/discover` gives host `sut.example.attacker.test` (urlsplit and `Request.host`). The `@host` trick does not work with urllib, which fails on getaddrinfo (E7).
- Fix: require `path` to start with `/`. Build the URL with `urljoin` and assert the host is unchanged. Allow only http/https schemes for `base_url`.

### F9. Low: `admit` raises on malformed input instead of returning `(False, reason)` [verified]
- Evidence: R:176-182 index `report[...]` directly.
- Repro: `{"x":1}` with a matching digest raises `KeyError 'verdict'`. A list input raises `AttributeError` (E5c).
- Fix: check `isinstance(report, dict)` and the presence and type of each field first.

### F10. Low: inline-dict scenario bodies are mutated in place [verified]
- Evidence: R:55 `setdefault`/`update` and R:59 `pop` act on the scenario's own dict when `body` is inline.
- Repro: after one run, an inline body with `fault: missing-message` has lost `message` for good, and its `context` now carries the identity and a stale messageId.
- Fix: `body = copy.deepcopy(body)`.

### F11. Low: server-controlled text lands in the report; encoding is not pinned for CLI inputs [verified]
- Evidence: R:134 puts `got!r` (any length) into `detail`. R:197-198 `read_text()` uses no encoding, which is cp1252 on Windows. R:41 uses `utf-8`, not `utf-8-sig`. A BOM, as written by Windows PowerShell 5 `Out-File -Encoding utf8`, gives "Unexpected UTF-8 BOM".
- Secrets: no seed reached a report. `test_identity_secret_never_in_report` holds, and exception text for a credentialed base_url showed no userinfo (E10).
- Fix: truncate `got`. Use `encoding="utf-8-sig"` everywhere. Add `*identity*.json` to `.gitignore` (`.gitignore:1-4` has no such rule, although `docs/conformance.md:10` says to keep the file out of git).

### F12. Low: the "fresh signature" on replay is usually byte-identical [verified]
- Evidence: R:114 claims a fresh signature that "tests messageId dedupe, not header reuse". But `signing.py:17` uses whole-second `created`, and Ed25519 is deterministic. Identical body plus identical second gives an identical header.
- Repro: identical in 19 of 20 runs (E1b). See F14 for the consequence.

---

## 2. Do the scenarios test what they claim? (spec check)

### F13. High: all six scenarios target `/discover` under role BPP, but `/discover` is a DS endpoint in v2 [verified]
- Evidence: Y:131-132 ("The CN sends a discovery request to the DS"). C:131 ("Discovery (`discover` / `on_discover`) flows between a CN and a DS; all other lifecycle actions ... flow between a CN and a PN"). C:87. The mockup co-hosts a DS in its BPP, which `docs/mockup-findings.md:53` itself flags as spec-conflicting.
- Effect:
  - A spec-literal PN (BPP) need not serve `/discover`, so it is FAILED (false fail).
  - Every auth and replay check is exercised only on the DS path, never on a PN action. Y:235 `/select` and Y:454 `/confirm` are untested.
- Fix: add a `DS` role and profile, retarget DISC-001 to it, and re-home NEG-001..005 onto a PN action (`/select` with a minimal valid body). Alternatively, parameterise negatives per role.

### F14. High: NEG-003 (replay) does not prove `messageId` dedupe [verified]
- Evidence: `tests/scenarios/neg-003-replay.json:9` and R:110-115. The second request is the byte-identical body with (usually) the byte-identical `Authorization` header (F12).
- Repro: mutants deduping by header string, or by body hash, both certify (E1, E3).
- A:423 requires rejecting a matching `messageId`. The mockup distinguishes byte-identical replay (`AUT_REPLAY_DETECTED`) from a reused messageId with a different body (`CTX_MESSAGE_ID_DUPLICATE`) (`docs/mockup-findings.md:59`).
- The precondition (R:112) is sound against "first request fails differently". It is too narrow, though: Y:91/178 allow `202 AckNoCallback` as an authenticated acceptance for `/discover`, so a DS with no results gets FAILED "replay test is void" instead of a valid test.
- Fix:
  - Add a fault `replay-new-body`: same `messageId`, different `transactionId` or intent, fresh `created` (sleep 1 s or set `now=created+1`).
  - Assert 400 and `error.code ∈ {CTX_MESSAGE_ID_DUPLICATE, AUT_REPLAY_DETECTED}`.
  - Accept 200 or 202 as the precondition.
  - Assert in a harness self-test that the two headers differ.

### F15. Medium: NEG-001 and NEG-002 cannot tell *why* the request got 401 [verified]
- What the scenarios check: only status plus `status: NACK` plus "code exists". Any 401 cause passes, and so does `code: SCH_INVALID_JSON` or `code: "X"` (E1).
- Concrete wrong-reason passes:
  - A server that 401s on any unknown `bapId` from a static allowlist passes NEG-002 without a registry.
  - A server with a pinned harness key passes NEG-002 and DISC-001 (the E1 mutant has no registry). So CLAUDE.md criterion 2 ("registry/key lookup") is not evidenced.
- Fix:
  - Assert `error.code` per fault: NEG-001 `AUT_SIGNATURE_INVALID`; NEG-002 `∈ {AUT_SUBSCRIBER_NOT_FOUND, AUT_KEY_NOT_FOUND}`.
  - Add a registry-backed positive control: rotate or revoke the harness key in a test registry mid-run, then expect 401 `AUT_KEY_EXPIRED_OR_REVOKED`.
  - Note that NEG-002's implicit keyId (R:75) makes a spec-literal verifier call `fabric.nfh.global` (A:158, CON-004-06) during the test. Document the egress, or use an explicit keyId pointing at the test registry.

### F16. Low: spec citations and assumption labels are inaccurate [verified]
- NEG-001 cites "Authentication_and_Trust.md 7" (`neg-001-bad-signature.json:9`). §7 is the *CN callback* procedure (A:346-348). The request-side rule is §8 (A:389-399) plus CON-004-08 (A:451). The 401 is correct.
- NEG-002 calls 401 an "ASSUMPTION" (`neg-002-unknown-participant.json:9`), and so do `docs/conformance.md:18` and `conformance/tests/test_negative_faults.py:7-8`. The spec fixes it: A:208 ("If the lookup fails or returns no key, reject with `401`"), A:391 (any step of §8, including key fetch step 4, gives 401), and Y:93 ("fails Registry key verification"). Relabel as spec-backed.
- NEG-004 names `SCH_INVALID_JSON` (Y:4275) and NEG-005 says the "Schema requires it" (Y:155-157 `required: [context, message]`, correct). Neither asserts the code (F15).
- NEG-003's 400 is correct (A:423).
- DISC-001 `notes` contains mojibake `Â§4` ("Â§4") at `tests/scenarios/001-search-ack.json:9`. This is double-encoded UTF-8.
- CLAUDE.md:22 still says the runner "is a stub".

### F17. Medium: DISC-001 accepts only `200`, which is a false fail and too weak [verified]
- Evidence: `001-search-ack.json:17`. Y:91 and Y:178 define `202 AckNoCallback` for "no matching results". The fixture searches `"widget"` (`tests/fixtures/search.json:13`), so a conformant DS with an empty index is FAILED. Y:176/180 (403/429) are also legitimate but should stay failures for certification.
- It also does not assert:
  - `$.message.messageId` equal to the sent messageId (Y:4109).
  - The `Signature` header (Y:2080).
  - `Content-Type`.
- Fix: `expect.status_in: [200, 202]` with per-status body rules. Add a `"$.message.messageId": "{{request.context.messageId}}"` templated assertion. Verify the `Signature` header.

---

## 3. Other false-pass risks [verified unless noted]
- **Status-only checks are allowed.** An empty or absent `expect.jsonpath` skips body parsing (R:126). Nothing forces a Nack body. Require a body schema for every scenario: validate against the referenced Y response schema (`Ack`, `NackBadRequest`, `NackUnauthorized`).
- **Schema negatives are minimal.** NEG-005 only checks that `message` is present. A server that validates nothing except "JSON parses and has `message`" certifies (the E1 mutant does exactly that).
- **Ordering dependence** [inferred]: DISC-001 (file `001-…`) is the only positive control and runs first (R:40 sorted). A server that degrades after its first request is caught only because NEG-003 needs a 200. Each negative should carry its own positive control (same request without the fault) in the same scenario.
- "200/400 for everything" and "200 for everything" do fail. The `test_permissive_server_fails` mutation (`conformance/tests/test_negative_faults.py:229-232`) only tests a server that ACKs everything. It is too weak: add the E1 mutant (wrong codes, no messageId, no `Signature`, header-keyed replay cache, pinned key) as a self-test that must FAIL.

---

## 4. Missing mandatory coverage for the Peppol-style admission claim (ranked)
1. **Scenario-set binding and report authenticity** (F1, F2). Without these, no coverage claim holds.
2. **Synchronous `Signature` response header** with the `request-signature` chain, on every status including 400/401 (A:304, CON-004-02, CON-004-23; Y:2080). Not tested at all.
3. **Ack/Nack body schema**: `messageId` echo, `error.code` from the enum, `error.message` (Y:4109, 4178-4179, 3271-3273).
4. **PN lifecycle**: `select/init/confirm/status/track/update/cancel/rate/support` (Y:235 …), including `context.try`/`requestDigest` (Y:74-79). Today only `/discover` (DS) is covered (F13).
5. **Async callbacks**: the runner needs a receiver to check `on_*` delivery, the same `messageId` (CON-004-17), the callback signing chain (CON-004-09/10), and the Ack obligation to call back (Y:4870-4873). This is acknowledged in `docs/conformance.md:19`.
6. **Signature negatives**:
   - Missing `Authorization` (`AUT_SIGNATURE_MISSING`).
   - Expired `expires` and `created` > now+5 s (A:394, A:472, CON-004-08).
   - `algorithm` ≠ ed25519 (A:140).
   - keyId alg-suffix mismatch (A:205).
   - Valid signature over body A sent with body B (digest mismatch).
7. **`messageId` duplicate with a different body** (F14).
8. **Schema negatives**:
   - `context.action` ≠ path (Y:166 const).
   - `version` ≠ 2.0.0.
   - Missing `message.intent` (Y:2294-2295).
   - Extra property under `additionalProperties: false` (Y:2293).
9. **Registry-backed key resolution** (revoked or rotated key) (F15).
10. **BAP role**: zero scenarios, so `bap-core` is always INCOMPLETE (verified; fail-closed, but the profile is unusable). Impersonation (signer ≠ bapId) and SSRF via explicit keyId should stay *recommended*, because the spec does not mandate them (`docs/mockup-findings.md:96-97`).

---

## 5. scripts/test.ps1 (Windows/PowerShell)

### F18. High: a missing interpreter exits 0, so CI reports success with no tests run [verified]
- Evidence: `scripts/test.ps1:10` falls back to `python`. When `& $py` fails with CommandNotFoundException (non-terminating under the default `$ErrorActionPreference`), `$LASTEXITCODE` stays `$null` (line 15), and `exit $null` is exit 0.
- Repro: a copy with `$py = "no-such-python-xyz"` exits 0 under both `pwsh` 7 and Windows PowerShell 5.1 (`t.ps1`).
- The same happens if `python` resolves to the Windows Store alias stub. Without PyNaCl the run fails closed ("request error: No module named 'nacl'").
- Fix:
  - `$ErrorActionPreference = 'Stop'`.
  - `if (-not (Get-Command $py -ErrorAction SilentlyContinue)) { Write-Error ...; exit 2 }`.
  - `exit ($code ?? 2)`.
  - Wrap Push/Pop in `try { } finally { Pop-Location }`.

### F19. Low: relative paths resolve against the repo root, not the caller's CWD; `$Profile` shadows `$PROFILE` [verified by reading]
- Evidence: `-Identity` and `-Profile` are passed relative after `Push-Location $root` (`scripts/test.ps1:11-13`), so `-Identity .\me.json` run from elsewhere reads the wrong file or fails. The parameter `$Profile` (line 3) shadows the automatic `$PROFILE` variable (case-insensitive). It works, but it is confusing. There are no `-Out` or `-Scenarios` pass-throughs, so the report only goes to stdout.
- Fix: `Resolve-Path` both before `Push-Location`. Rename to `-ProfilePath`. Add `-Out`.

---

## Summary
- **Scale.** 34/34 self-tests pass, but the harness can certify non-conformant servers.
- **One mutant breaks several MUSTs and is CERTIFIED and admitted.** It has no Ack/Nack `messageId`, non-enum error codes, no `Signature` response header, a replay cache keyed on the header string, and a pinned key with no registry.
- **Root causes:**
  - `null` means "exists" and accepts JSON null (F3).
  - Error codes are never asserted (F15).
  - Replay re-sends a byte-identical body and, 19 times in 20, a byte-identical header (F12/F14).
- **Admission (Critical).**
  - Certification is not bound to any scenario set, so `--scenarios` with only DISC-001 certifies (F1).
  - Reports are forgeable via an unkeyed digest. `admit` ignores participant identity and accepts future `issued_at` forever (F2).
- **Spec fit (High).** All scenarios hit `/discover`, which v2 assigns to the DS, not the BPP/PN (Y:131, C:131). PN actions and their auth checks are untested (F13). DISC-001 wrongly rejects the spec's `202 AckNoCallback` (F17).
- **Spec labels.** NEG-002's 401 is spec-backed (A:208, A:391), not an assumption. NEG-001 cites the wrong section (F16).
- **Runner safety (Medium).**
  - Redirects are followed, with `Authorization` forwarded (F6).
  - Scenario `body` path traversal can POST the identity seed to the SUT (F7).
  - Level and role typos silently downgrade mandatory scenarios (F5).
  - jsonpath-lite skips tokens it cannot parse (F4).
- **test.ps1 (High).** It exits 0 when the interpreter is missing (F18).
- **Coverage, top priorities.** Response `Signature` header; Ack/Nack schema; PN lifecycle and callbacks; expiry/missing-signature/algorithm negatives; messageId duplicate with a new body.
