# Vendored DeDi protocol files

Copied unmodified from https://github.com/LF-Decentralized-Trust-labs/decentralized-directory-protocol
at commit 4804d83 (2026-09-23), licence Apache-2.0 (see LICENSE-Apache-2.0).

- `schemas/`: the DeDi file, manifest and digests schemas and the two Beckn registry-record schemas.
- `examples/`: the upstream illustrative files. Their `jws` and `digest` values are placeholders, so
  they are used only as shape fixtures, never as signature vectors.

The schema `$id` URLs point at the upstream `main` branch, which the spec itself says is mutable and
must be pinned before release. Re-vendor deliberately and re-run the tests when upstream pins them.
