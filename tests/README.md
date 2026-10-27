# Conformance tests

Language-agnostic. A scenario is a JSON file in `scenarios/`:

```json
{
  "name": "discover returns ACK",
  "spec": "beckn-2.0.0 (protocol-specifications-v2 @ a22300a, api/v2.0.0/beckn.yaml paths./discover)",
  "request": { "method": "POST", "path": "/discover", "body": "fixtures/search.json", "auth": "beckn-http-signature" },
  "expect": { "status": 200, "jsonpath": { "$.message.status": "ACK" } }
}
```

Rules:
- `body` paths are relative to `tests/`.
- Assertions come from the spec, never from observed implementation output.
- `auth: beckn-http-signature` means the runner must sign the request (Beckn v2 requires it; unsigned requests get 401) and template `context.bapId`/`bapUri`/`messageId`.
- A scenario that cannot pass yet is kept and marked `"pending": true` with a reason, not deleted.

Run with `pwsh scripts/test.ps1 -BaseUrl <adapter url>`.
