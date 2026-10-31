# Interop with beckn-onix (signing)

Purpose: a second, independent implementation checks the signing rules that our conformance runner
enforces, so a pass does not rest on one reading of the spec.

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
- The spec itself carries both: the `RequestDigest` pattern in `api/v2.0.0/beckn.yaml` is `^BLAKE-512=...`
  (also noted in `mockup/beckn_mock/signing.py`), while the same file's signing description and the auth
  document say `BLAKE2b-512=`. So this is a spec ambiguity that ONIX and we resolved differently, not
  evidence that either side is wrong. UNVERIFIED which reading the maintainers intend; the way to settle it
  is a question to the spec maintainers, not a change here.
- Two chain points agree in shape: the ack signing string appends `request-signature: {sig}` as a fourth
  line in both.
- Other observed differences, not yet tested: ONIX's `Authorization` parser does not require the `headers`
  attribute that our strict parser (and the spec's `Signature` pattern) requires.

## Consequence for CERTIFIED

Until the maintainers settle the prefix, a node that interoperates with ONIX-signed traffic would fail our
signing checks, and the reverse. The report does not change the CERTIFIED verdict; the divergence is
recorded here and a conformance scenario for the prefix should wait for the maintainers' answer.
