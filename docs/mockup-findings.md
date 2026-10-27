# Beckn v2.0.0 Python mockup: findings

Date: 2026-10-27. Target: **Beckn Protocol 2.0.0** as defined by `vendor/protocol-specifications-v2` (commit `a22300a`, 2026-08-17): `api/v2.0.0/beckn.yaml` (OpenAPI 3.1.1, "authoritative") plus the RFC drafts in `docs/` (NFH-006 API, NFH-007 Authentication and Trust, NFH-013 Communication Protocol). Every RFC is marked **Draft**. Unless a path says otherwise, `Y` means `api/v2.0.0/beckn.yaml`, `A` means `docs/Authentication_and_Trust.md` and `C` means `docs/Communication_Protocol.md`.

## What was built

`mockup/beckn_mock/` contains:

- a mock registry (`registry.py`);
- a BAP/CN (`bap.py`);
- a generic BPP/PN that loads its catalog from `catalog.json` and also serves `/discover` (`bpp.py`);
- shared verification code (`node.py`);
- signing helpers (`signing.py`);
- an SSRF guard (`urlguard.py`);
- JSON Schema validation driven directly from `beckn.yaml` (`spec.py`).

It covers all 10 action pairs (`discover`, `select`, `init`, `confirm`, `status`, `track`, `update`, `cancel`, `rate`, `support`). Each action gets a signed synchronous Ack, then an asynchronous `on_<action>` callback with a chained signature. The mockup also implements:

- PN-initiated callbacks;
- the two-phase `context.try` + `requestDigest` flow for `update` and `cancel`;
- verification of the `Signature` header on Acks.

### How to run

```
cd mockup
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m pytest -q -rx
```

Every server is uvicorn on `127.0.0.1` on an OS-chosen port, run in-process in a thread. Each test gets its own network, which is torn down afterwards. Set `BECKN_SPEC_DIR` to point at a different spec checkout. The spec YAML is only read with `yaml.safe_load`; nothing from `vendor/` is imported or executed.

### Results (real run)

**75 passed, 9 xfailed, 0 failed** in about 97 s. The tests were written first, and the first run failed at collection because `beckn_mock.network` did not exist yet.

Mutation checks confirmed the tests can detect failures. I disabled one control at a time:

| Control disabled | Result |
|---|---|
| Replay cache | 3 failures |
| Signature verification | 3 failures |
| URL guard | 16 failures |
| Expiry check | 1 failure |

Each of the 9 xfails (`tests/test_spec_gaps.py`, `strict=True`) records a defect in the spec artefacts themselves (items 1-9 below). They will start XPASS-failing once upstream fixes them.

## Mockup assumptions where the spec is silent

Each of these is also stated in the docstring of the test that covers it.

- **DS co-hosted by the BPP.** The BPP answers `/discover` under its own identity. This conflicts with "Each role MUST have a separate identity and public key" (Y:33), which a real deployment must honour.
- **Mock registry shapes are invented.** The dedi / GRR API is "out of scope" (Y:46). Implicit keyIds are resolved against the mock registry, not `https://fabric.nfh.global/registry` as A:158 and CON-004-06 (A:449) require. A spec-literal implementation cannot be tested offline or on a private network.
- **Signer bound to sender.** The keyId's registry subscriber must equal `context.bapId` (for requests) or `context.bppId` (for callbacks); otherwise 401 `AUT_UNAUTHORIZED_ACTION`. See item S1.
- **Business errors are rejected synchronously.** `400` NACK with `BIZ_*` codes, because callbacks cannot carry errors (item 9).
- **Dedup key and error codes.**
  - Duplicates are tracked per (sender, messageId).
  - A byte-identical replay returns `AUT_REPLAY_DETECTED`; a reused messageId with a different body returns `CTX_MESSAGE_ID_DUPLICATE`. The spec lists both codes (Y ErrorCode enum) without saying when each applies.
  - Dedup entries are kept until the signature's `expires` + 5 s skew.
- **TTL.** An expired `ttl` returns 400 `CTX_TTL_EXPIRED`. Y:3013-3017 says only "SHOULD reject" and gives no status code.
- **Callback URL guard** (beyond the spec's "bapUri MUST match subscriber_url", Y:2944):
  - only http/https;
  - no userinfo;
  - in allowlist mode, the origin must match exactly;
  - in open mode, every resolved address must be globally routable;
  - non-canonical numeric hosts are refused;
  - redirects are not followed.
- **Callbacks per messageId.** The CN accepts further *distinct* callbacks for one messageId (CON-013-15) but rejects byte-identical replays. See S4.

## Spec defects and ambiguities (each backed by an xfail unless noted)

1. **Context has no `required` list.** The prose says context MUST include `action`, `version`, `transactionId`, `messageId` and "`bapId` or `bppId`" (Y:66-73). The `Context` schema (Y:2901-3026) declares properties only, so `{"context":{}}` validates. The mockup enforces the fields in code.
2. **`/status` cannot be minimal.** `StatusAction` (Y:2558-2577), `CancelAction` and `Tracking.contract` are `allOf[Contract, required:[id]]`, and `Contract` requires `commitments` (Y:3105-3106). A "give me the state of contract X" request must therefore resend the whole contract.
3. **`/track` requests must invent tracking data.** `Tracking` requires `url` and `status` (Y:4086-4088), so the request has to supply the very url and status it is asking for. The mockup sends a placeholder.
4. **Ack `Signature` header format contradiction.** NFH-007 §5 shows `Signature: keyId="..."` with no scheme (A:314, A:568). The `AckSignature` pattern requires `^Signature keyId=` (Y:3906). The mockup emits the YAML form and its parser accepts both.
5. **Two digest prefixes.**
   - Signing uses `BLAKE2b-512=` (A:219, CON-004-04).
   - `RequestDigest.digest` must match `^BLAKE-512=` (Y:3472).
   - ONDC's reference signer uses `BLAKE-512=` in the signing string (`vendor/ONDC-Official/py-protocol-layer/webserver/main/utils/cryptic_utils.py:27`), so ONDC-signed v1 traffic will not verify under v2 rules.
6. **`Error.code` is unconstrained.** Y:3277 says it "MUST be a value from the ErrorCode enum", but the schema is `type: string` and the `ErrorCode` enum (Y:4250) is never referenced.
7. **The spec's own examples are invalid.** NFH-013 Example 1 uses `"txn-f7e3c2a1"` and `"msg-..."` as IDs, which are not UUIDs, despite CON-013-21/22. It also uses a v1 `message.order` (C:478, C:487). NFH-006 does the same (`txn-123`). Not covered by an xfail: the starter-kit's own Postman `select`/`confirm` bodies use `contract.id: "draft-contract-0001"`, which fails `format: uuid` (Y:3049-3051).
8. **No field for the rating value.** `RatingInput` is `additionalProperties:false` with only `target`, `range` (an untyped `object`) and `feedbackFormSubmission` (Y:3739-3777). The mockup puts the score inside `range`.
9. **Callbacks cannot carry an async error.** `AsyncError` (Y:2694) is defined, but every `On*Action` is `additionalProperties:false` with no `error` property, so a PN that ACKed and then failed has no schema-valid way to report it.

Other gaps not covered by xfails:

10. **`requestDigest` means two different things.** It is the hash of the *originating request* carried in callbacks (Y:3452-3475), and also the hash of the *preview response* in a `try:false` commit (Y:77, Y:804). It is the same field with two meanings. The mockup implements both.
11. **Wrong RFC number.** NFH-007 is cited as "NFH-004 Authentication and Trust" in Y:2078, Y:3853, Y:3879 and Y:3903, while the document's ID is NFH-007 (A:4) and its conformance IDs are `CON-004-*`.
12. **Leftover v1 name.** `Support.orderId` (Y:3926) survives in the contract-based v2 model.
13. **Unresolved FAQs.** Seven NFH-013 FAQs are "TBA" (C:592-620). They include the retry-after-500 messageId rule and what happens when a PN ACKs and never calls back.
14. **`ttl` has no `format: duration`** (Y:3013). Combined with item 1, a receiver gets no schema help parsing it.

## Security issues

- **S1. The signer is not bound to the claimed participant.** NFH-007 verifies that the signature matches *the keyId's* key (A:389-399). It never requires that keyId to belong to `context.bapId` / `bppId`. Any registered participant could sign a request claiming to be another BAP and have the callback routed by the victim's identity. The mockup adds that binding (`test_impersonation_of_other_participant_rejected`).
- **S2. Pre-authentication SSRF through explicit keyIds.** For explicit keyIds the verifier "MUST extract the URL portion … and issue an HTTP GET to that URL" (A:201). That URL comes from an unauthenticated header, and it is fetched before any trust decision. The text says untrusted registries MUST be rejected (A:175), but the conformance table downgrades this to **SHOULD** (CON-004-14, A:457). The two explicit-format shapes also differ: implicit uses `/dedi/lookup/{keyId}` while explicit uses `/{ns}/{reg}/{rec}`. The mockup refuses untrusted prefixes before fetching; `test_explicit_keyid_to_untrusted_url_rejected_without_fetch` proves no request leaves.
- **S3. No bound on how long a signature lives, and no defined replay window.**
  - `expires` is capped only by the key's registration expiry (A:239), which can be months away.
  - Duplicate detection applies only "within its replay detection window" (A:423), and the window is never defined.
  - The signature covers neither method, path nor host. Only the body digest and times are signed (A:226-236), so `context.action` is the only thing tying a body to an endpoint.
  - The ONDC reference signs with a default 1-hour expiry and checks no replays (`cryptic_utils.py:65`, `:84`).
- **S4. The callback replay rules contradict each other.**
  - NFH-007 §10.2: a callback for a messageId "for which a callback has already been received, MUST be rejected" (A:434).
  - NFH-013 §9 / CON-013-15: the CN "MUST NOT discard a callback solely because a prior callback with the same messageId was already received" (C:434).
  - CON-013-12 forbids rejecting unknown messageIds (C:431), while §10.2 requires it.
  - PN-initiated callbacks carry no chain at all. A captured `on_status` can be replayed until it expires unless the CN keeps a cache, and the spec never requires the CN to reject repeats (A:438).
  - The mockup's resolution is to deduplicate on (messageId, signature), as CON-013-23 recommends.
- **S5. The callback chain value is never transmitted.** The CN is told to rebuild the string "plus the value on the `request-signature` line" (A:371) and then compare that value against its stored signature (A:381-383). But the value appears nowhere in the HTTP message. The only workable reading is "verify using your own stored signature", which is what the mockup does. As written, step 7 is circular.
- **S6. Callback SSRF is barely addressed.** The only control is "bapUri MUST match subscriber_url" (Y:2944). Registry entries are self-declared, and the spec says nothing about private addresses, schemes, redirects or DNS rebinding. It requires "publicly reachable HTTPS" endpoints (C:105-106), but receivers are never told to enforce that before dispatch.
  - Catalogs returned by a DS carry their own `bppUri` (Y:2757), so a hostile DS can steer a naive CN. The mockup resolves PN addresses from the registry only (`test_bap_does_not_trust_bpp_uri_from_catalog`).
- **S7. Error responses cannot always be signed sensibly.** Every response "regardless of status code" must carry a chained `Signature` (A:304). When the request has no or a malformed `Authorization`, there is no request signature to chain. The mockup signs with an empty `request-signature`.
  - Nack schemas also require a UUID `messageId` even when the body is unparseable. The mockup returns the nil UUID.
- **S8. Revocation and pre-call checks are SHOULD-level.**
  - The `subscriber_reference` lookup before dispatch is only SHOULD (A:407, CON-004-21).
  - Revocation "MUST be checked at verification time" (cross-cutting, A:484), which forbids caching keys. That pushes a registry round-trip onto every message, with no guidance on cache TTL.
- **S9. Reference material ships private keys.** `vendor/starter-kit/generic-devkit/config/generic-bpp.yaml:49,119` and `generic-bap.yaml:50,120` contain `signingPrivateKey` values. Treat them as compromised test keys, and never register them on a real subnet.
  - The ONIX schema validator also downloads extended schemas at runtime from `raw.githubusercontent.com`, among other hosts (`generic-bpp.yaml:65`). That is a supply-chain and egress dependency on the request path.

## Python tooling gaps

- **JSON Schema `format` is not asserted by default.** It is annotation-only in 2020-12, so `uuid`, `date-time` and `uri` pass silently. You must pass `format_checker`, and `uri`/`date-time` checks need the extra packages from `jsonschema[format-nongpl]` (`rfc3986-validator`, `rfc3339-validator`). Without them, the CON-013-21/22 UUID rules go unenforced.
- **No maintained Beckn v2 Python SDK.** The only Python reference in vendor (`ONDC-Official/py-protocol-layer`) is v1 / ONDC: `BLAKE-512=` prefix, a `subscriber|ukid|alg` keyId, no response signing, no callback chain and no replay cache. Signing therefore had to be hand-written on PyNaCl, with BLAKE2b-512 from `hashlib.blake2b(digest_size=64)`.
- **OpenAPI 3.1 to validator glue is manual.** `openapi-core` and similar libraries were not needed, but the schema has to be registered as a `referencing` resource and request bodies addressed by JSON pointer (`spec.py`).
- **No ISO 8601 duration parser in the stdlib.** A minimal one was written for `ttl`. It rejects years and months, which have no fixed length.
- **httpx cannot pin the resolved IP.** The SSRF guard resolves and vets the addresses, then httpx resolves again on connect. That leaves a DNS-rebinding TOCTOU window; closing it needs a custom transport or connecting by IP with an SNI override.
- **Client construction is slow.** Each new httpx client loads the CA bundle (about 0.25 s on this machine). Per-request clients pushed the suite from 97 s to 197 s, so long-lived clients are required.
