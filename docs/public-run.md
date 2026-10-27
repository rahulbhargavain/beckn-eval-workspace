# Running the conformance suite against a public sandbox / registry

Status: **prepared, not run.** Nothing here has contacted a public service. This is a shared network, so the run is outward-facing: read "What the suite sends" first.

## What the human provides
1. **Target node URLs**, `https` only. Which role each plays: DS (answers `/discover`), PN/BPP (answers `/select` ...). Pick the profile accordingly (`ds-core`, `bpp-core`).
2. **A harness identity registered in the target's registry.** Generate it locally (the private seed never leaves the file and is never printed):
   ```
   mockup\.venv\Scripts\python -m conformance.keygen --out secrets\identity.json --key-id "<ns>/<registry>/<record>|ed25519" --bap-id <your-subscriber-id> --bap-uri https://<your-callback-host>/beckn --network-id <network>
   ```
   Register the printed public key yourself with the registry operator (account creation and registration are yours to do). `key_id`, `bap_id` and `network_id` must be exactly what the registry holds. `secrets/` and `*identity*.json` are git-ignored.
3. **The registry used by the target** and whether it differs from `fabric.nfh.global` (implicit key ids resolve there; see MEMORY.md). If a private registry is used, the target's verifier must be configured for it; the harness cannot change that.
4. **Permission from the node operator** to send deliberately invalid traffic (see below). Public sandboxes may rate-limit or ban on abuse signals.
5. **An operator signing key** for reports (`--issuer-key`, same file shape as an identity: `key_id`, `private_key_seed_b64`) and its public key pinned wherever `admit` runs. Optional for a first look.

Do NOT use the private keys committed in `vendor/starter-kit` / DEG / open-agri configs: they are public, so using them impersonates another participant.

## What the suite sends
- `DISC-001`: one valid signed `/discover`.
- `NEG-001..006`, `PNNEG-001..004`: bad signature, signature from an unregistered participant, replayed `messageId` (x2 requests), invalid JSON, missing `message`. Each is rejected by a conformant node; against a non-conformant one they may be *accepted* (a replay or an unregistered signer treated as valid), which is a real side effect on that node.
- The unregistered-participant scenario uses an implicit key id, so a spec-literal verifier will query the registry for a name that does not exist.
- Total: about 16 HTTP requests per profile. No `on_*` callbacks are received (no receiver yet), so nothing is asked to call back into your host. `bapUri` is still sent in the request context.

## Safety rails in the runner
- Remote hosts must be `https` and listed with `--allow-host <exact host>`; otherwise nothing is sent. Loopback is always allowed.
- `--dry-run` prints the plan and exits with no network access and no signing.
- `--only <ID>` probes a subset (report is marked `probe` and can never be CERTIFIED).
- `--delay <seconds>` spaces scenarios apart.
- Redirects are not followed and environment proxies are ignored.

## Procedure
```
# 1. plan only
mockup\.venv\Scripts\python -m conformance.runner --profile conformance/profiles/ds-core.json --base-url https://<node> --participant <name> --allow-host <node> --dry-run
# 2. one valid request first
mockup\.venv\Scripts\python -m conformance.runner --profile conformance/profiles/ds-core.json --base-url https://<node> --participant <name> --allow-host <node> --identity secrets\identity.json --only DISC-001 --out report-probe.json
# 3. full run with spacing and a signed report
mockup\.venv\Scripts\python -m conformance.runner --profile conformance/profiles/ds-core.json --base-url https://<node> --participant <name> --allow-host <node> --identity secrets\identity.json --issuer-key secrets\issuer.json --delay 2 --out report-ds.json
```
Stop and ask if: step 2 returns anything but 200/202 (identity not registered, wrong `network_id`, clock skew over ~5 s), a 429 appears, or the operator asks you to stop.

## Expected first-run caveats
- `DISC-001` needs a signed request the node's verifier can resolve; an unregistered or mismatched key gives 401 and every other scenario's meaning is then void (the replay scenarios will report "precondition failed").
- Public nodes may legitimately differ from the spec's status codes; treat a FAILED as a finding to examine, not automatically as non-conformance. Record it with the exact response in `docs/`.
- Clock: the machine clock must be within a few seconds of real time.
- Reports contain the target URL and your harness `key_id`, never the seed. Do not commit them (`report*.json` is git-ignored).
