# DeDi file-based onboarding (generator and validator)

`conformance/dedi.py` builds and checks the two signed files that put a Beckn participant on the
NFH fabric by file (spec: `publishing-dedi-files.md` in the DeDi protocol repo; schemas vendored
under `conformance/dedi_vendor`, Apache-2.0, commit 4804d83).

| File | Hosted at |
|---|---|
| Registry file | `https://<domain>/dedi/<nfo>_<network>_<env>_registry.json` (`_ref_registry` for an NFO) |
| Manifest | `https://<domain>/.well-known/dedi.index.json` |

Both are signed Ed25519 over RFC 8785 canonical JSON as a detached JWS (`EdDSA`, `b64:false`). The
registry is written and signed first, its digest is taken over the final bytes, then the manifest
is built and signed. Records are checked against the vendored Beckn Subscriber (NP) or Subscriber
Reference (NFO) schema.

## Use
```bash
python -m conformance.dedi build --config dedi.config.json --identity secrets/dedi-identity.json --out site
python -m conformance.dedi verify --dir site --domain np1.example
```
Config (NP): `role`, `domain` (bare host), `name`, `nfo_name`, `network`, `env`, `kid`, optional
`validity_days` (default 7), and `records` of `{record_name, subscriber_id, url, type, countries,
signing_public_key}`. NFO records are `{record_name, subscriber_id, type, url}`. `--reissue` re-signs
over the same directory and keeps `updated_at` when content is unchanged (spec section 9); re-issue
before `next_update` passes.

The identity file comes from `python -m conformance.keygen` and holds a private seed that is read
into memory, never printed or written. Prefer a separate key for DeDi publishing from your Beckn
message-signing key (make a second identity file); the registry record's `signing_public_key` is the
Beckn message key, while `publisher.key` is the DeDi file-signing key.

`verify` follows spec section 7.3: schema shape, signature against the embedded key, key listed in the
manifest's own keys, freshness, registry state, plus digest, domain, `source_url`, unique record names
and record-schema checks. It verifies a local tree laid out as it will be hosted; it does not fetch.

## Not done
- The signing and canonicalization follow the spec text but have not been checked against another
  implementation (the upstream examples carry placeholder signatures, so they are shape fixtures only).
- Floats are refused by the canonicalizer (none occur in these files).
- No discovery-list entry, digests file, inline registries on build, or hosted (dedi.global) path.
- No live fetching verifier, so our BAP/BPP still resolve keys through the mockup registry.
- Hosting on an HTTPS domain you control, CORS and cache headers, and entering the domain on the NFH
  onboarding portal are yours to do. Schema URLs point at the upstream `main` branch, which the spec
  says must be pinned before release.
