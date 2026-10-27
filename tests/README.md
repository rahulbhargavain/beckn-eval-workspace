# Conformance tests

Language-agnostic. A scenario is a JSON file in `scenarios/`:

```json
{
  "name": "search returns ACK",
  "spec": "beckn-1.x (UNVERIFIED)",
  "request": { "method": "POST", "path": "/search", "body": "fixtures/search.json" },
  "expect": { "status": 200, "jsonpath": { "$.message.ack.status": "ACK" } }
}
```

Rules:
- `body` paths are relative to `tests/`.
- Assertions come from the spec, never from observed implementation output.
- A scenario that cannot pass yet is kept and marked `"pending": true` with a reason, not deleted.

Run with `pwsh scripts/test.ps1 -BaseUrl <adapter url>`.
