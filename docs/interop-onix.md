# Interop with beckn-onix (signing)

Purpose: a second, independent implementation checks the signing rules that our conformance runner
enforces, so a pass does not rest on one reading of the spec. It exercises the workspace's mockup signer and ONIX's plugin functions directly (no HTTP, key lookup or identity check), not our runner's header parsing.

## What runs

`interop/onix/crosscheck.py` makes signed vectors with this workspace's signer. A Go test
(`interop/onix/onix_interop_test.go`, copied into the ONIX checkout by CI, not part of ONIX) then:

1. validates our request signature and our chained ack signature with ONIX's own `signvalidator`;
2. signs the same bodies with ONIX's own `signer`.

`crosscheck.py compare` checks ONIX's signatures with our verifier and prints AGREE or DIFFER per check.
CI: `.github/workflows/interop-onix.yml` (informational; it does not gate Pages). Pinned ONIX commit
`b0a134b8850a5785db6a97af8349668e664493dd` (Go 1.26.1). Not tried: a full ONIX deployment with a
registry; running our runner against an ONIX-fronted node.

## Result (2026-10-31, ONIX `b0a134b`, Go 1.26.1)

Eight cases, per-case verdicts in `interop/onix/baseline.json` (CI fails if they change):

| Case | What differs |
|---|---|
| base, v2-keyid, empty-body, non-ascii-body | ONIX rejects our request and chained ack signatures; we reject the signatures ONIX makes. Same cause in all four: the digest prefix. keyId shape, empty bodies and Devanagari text make no difference |
| onix-prefix (signed with `BLAKE-512=`) | ONIX accepts it, our strict reading rejects it. This confirms the reverse direction against ONIX's code rather than only from its source |
| headers-wrong, headers-missing | ONIX accepts both (signed with its prefix so only the `headers` attribute differs); our parser rejects both |
| expired | Both reject |
| diagnostic, every signing case | ONIX's signatures verify under our code if the prefix is `BLAKE-512=`: the prefix is the only difference |

The same vectors also pass through the runner's own verifier (`conformance/signing.py`) in
`conformance/tests/test_interop_crosscheck.py`: it accepts the four spec-prefix cases and rejects `onix-prefix`.

- This workspace follows `docs/Authentication_and_Trust.md` of the v2.0.0 spec: `digest: BLAKE2b-512={Base64}`.
- ONIX at the pinned commit signs and validates `digest: BLAKE-512={Base64}`.
- The prefixes belong to different fields. The signing-string digest is specified as `BLAKE2b-512=` (the `Signature`
  schema in `api/v2.0.0/beckn.yaml`, and CON-004-04, a MUST, in `docs/Authentication_and_Trust.md`). `BLAKE-512=`
  appears only in the `RequestDigest.digest` pattern (`context.requestDigest`). On this reading ONIX departs from
  CON-004-04, probably by taking the `RequestDigest` prefix for the signing string. The inconsistency between the two
  fields is real; whether ONIX's choice is intended is UNVERIFIED, so ask the maintainers (see below).
- The ack signing string appends `request-signature: {sig}` as a fourth line in both implementations.
- ONIX's parser accepts a wrong or absent `headers` attribute (tested above), which our strict parser and the `Signature` pattern reject. Whether receivers must check it is a question for the maintainers.

## Consequence for CERTIFIED

The runner stays strict (`BLAKE2b-512=` only, per CON-004-04). ONIX-style signing would be a named finding, not a pass. Until the maintainers answer, a node that interoperates with ONIX-signed traffic would fail our
signing checks, and the reverse. The report does not change the CERTIFIED verdict; the divergence is
recorded here and a prefix scenario waits for the maintainers' answer.

## Open items from review (2026-10-31)

- Done 2026-10-31: the reverse `BLAKE-512=` vector, v2-shaped keyId, empty and non-ASCII bodies, negative `headers` and expiry vectors, runner-verifier test, DIAGNOSTIC label, committed baseline, actions pinned by SHA, 15-minute timeout.
- ONIX's `ValidateAck` falls back to the 3-line string when the request signature passed in is empty; the spec requires the chain. UNVERIFIED whether its handler can pass an empty value.
- Draft question to the spec maintainers (not sent): in v2.0.0, `Authentication_and_Trust.md` section 3.1, CON-004-04 and the `Signature` schema give the signing-string digest as `BLAKE2b-512={Base64}`, while `RequestDigest.digest` uses `^BLAKE-512=`; beckn-onix at b0a134b uses `BLAKE-512=` in the signing string. Please confirm (a) the intended signing-string prefix, (b) whether `context.requestDigest` intentionally differs, (c) whether receivers must check the `headers` attribute.
