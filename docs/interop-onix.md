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

## Result (2026-10-31, run locally under WSL with Go 1.26.1)

| Check | Result |
|---|---|
| ONIX validates our request signature | DIFFER: signature verification failed |
| ONIX validates our chained ack signature | DIFFER: AckSignature verification failed |
| We verify the signature ONIX makes | DIFFER |
| We verify the chained ack signature ONIX makes | DIFFER |
| ONIX signatures verify if our digest prefix is `BLAKE-512=` | AGREE |

The last row isolates the cause: the only difference found is the digest prefix inside the signing string.

- This workspace follows `docs/Authentication_and_Trust.md` of the v2.0.0 spec: `digest: BLAKE2b-512={Base64}`.
- ONIX at the pinned commit signs and validates `digest: BLAKE-512={Base64}`.
- The prefixes belong to different fields. The signing-string digest is specified as `BLAKE2b-512=` (the `Signature`
  schema in `api/v2.0.0/beckn.yaml`, and CON-004-04, a MUST, in `docs/Authentication_and_Trust.md`). `BLAKE-512=`
  appears only in the `RequestDigest.digest` pattern (`context.requestDigest`). On this reading ONIX departs from
  CON-004-04, probably by taking the `RequestDigest` prefix for the signing string. The inconsistency between the two
  fields is real; whether ONIX's choice is intended is UNVERIFIED, so ask the maintainers (see below).
- The ack signing string appends `request-signature: {sig}` as a fourth line in both implementations.
- Other observed differences, not yet tested: ONIX's `Authorization` parser does not require the `headers`
  attribute that our strict parser (and the spec's `Signature` pattern) requires.

## Consequence for CERTIFIED

The runner stays strict (`BLAKE2b-512=` only, per CON-004-04). ONIX-style signing would be a named finding, not a pass. Until the maintainers answer, a node that interoperates with ONIX-signed traffic would fail our
signing checks, and the reverse. The report does not change the CERTIFIED verdict; the divergence is
recorded here and a prefix scenario waits for the maintainers' answer.

## Open items from review (2026-10-31)

- Add a vector signed with `BLAKE-512=` and run it through ONIX's `Validate`/`ValidateAck` (the reverse half of the cause isolation is inferred from source), plus a v2-shaped keyId, empty and non-ASCII bodies, and negative `headers` vectors; run them against `conformance/signing.py` too.
- ONIX's `ValidateAck` falls back to the 3-line string when the request signature passed in is empty; the spec requires the chain. UNVERIFIED whether its handler can pass an empty value.
- Label the diagnostic row DIAGNOSTIC, not AGREE; check results against a committed baseline on re-pin; pin actions by SHA and add a timeout.
- Draft question to the spec maintainers (not sent): in v2.0.0, `Authentication_and_Trust.md` section 3.1, CON-004-04 and the `Signature` schema give the signing-string digest as `BLAKE2b-512={Base64}`, while `RequestDigest.digest` uses `^BLAKE-512=`; beckn-onix at b0a134b uses `BLAKE-512=` in the signing string. Please confirm (a) the intended signing-string prefix, (b) whether `context.requestDigest` intentionally differs, (c) whether receivers must check the `headers` attribute.
