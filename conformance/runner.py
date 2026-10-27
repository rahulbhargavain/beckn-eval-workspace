"""Peppol-style conformance runner: stdlib only, spec- and stack-agnostic.

A participant is certified for (spec, role) when every applicable mandatory
scenario passes. Pending or absent mandatory coverage yields INCOMPLETE, never
CERTIFIED. The report carries a sha256 digest so the registry can detect edits;
the digest is NOT a signature. Sign the report with the issuer's key before
trusting it across organisations.
"""
import base64
import hashlib
import json
import re
import time
import urllib.error
import uuid
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCENARIOS = ROOT / "tests" / "scenarios"
DEFAULT_FIXTURES = ROOT / "tests"
SIGNED = "beckn-http-signature"
MISSING = object()
MAX_AGE_SECONDS = 90 * 24 * 3600


def jsonpath(data, path):
    """Minimal `$.a.b[0].c` lookup; returns MISSING when absent."""
    cur = data
    for key, idx in re.findall(r"\.([A-Za-z0-9_\-]+)|\[(\d+)\]", path):
        try:
            cur = cur[key] if key else cur[int(idx)]
        except (KeyError, IndexError, TypeError):
            return MISSING
    return cur


def load_scenarios(directory):
    out = []
    for f in sorted(Path(directory).glob("*.json")):
        s = json.loads(f.read_text(encoding="utf-8"))
        if "id" in s:
            out.append(s)
    return out


FAULTS = {"bad-signature", "unknown-participant", "replay", "invalid-json", "missing-message"}


def _body(req, fixtures_root, identity, fault):
    body = req.get("body")
    if isinstance(body, str):  # path relative to the fixtures root
        body = json.loads((Path(fixtures_root) / body).read_text(encoding="utf-8"))
    if body is not None and req.get("auth") == SIGNED:
        ctx = body.setdefault("context", {})
        ctx.update(bapId=identity["bap_id"], bapUri=identity["bap_uri"],
                   networkId=identity["network_id"], messageId=str(uuid.uuid4()))
    if fault == "missing-message":
        body.pop("message", None)
    if fault == "invalid-json":
        return b'{"context": {"action": '  # signed over garbage: signature is valid, payload is not
    return None if body is None else json.dumps(body, separators=(",", ":")).encode()


def _flip_signature(auth):
    m = re.search(r'signature="([^"]+)"', auth)
    raw = bytearray(base64.b64decode(m.group(1)))
    raw[0] ^= 0x01
    return auth[:m.start(1)] + base64.b64encode(bytes(raw)).decode() + auth[m.end(1):]


def _unknown_identity(identity):
    from nacl.signing import SigningKey
    name = f"unregistered-{uuid.uuid4().hex[:8]}.invalid"
    return dict(identity, key_id=f"{name}/keys/k1|ed25519", bap_id=name,
                private_key_seed_b64=base64.b64encode(bytes(SigningKey.generate())).decode())


def _send(base_url, req, data, headers, timeout):
    r = urllib.request.Request(base_url + req["path"], data=data, headers=headers,
                               method=req.get("method", "POST"))
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _call(base_url, req, timeout, fixtures_root, identity):
    signed = req.get("auth") == SIGNED
    fault = req.get("fault")
    if fault and fault not in FAULTS:
        raise ValueError(f"unknown fault {fault!r}")
    if fault and not signed:
        raise ValueError("fault scenarios must use auth beckn-http-signature")
    if signed and not identity:
        raise ValueError("scenario needs a signing identity (none supplied)")
    if fault == "unknown-participant":
        identity = _unknown_identity(identity)
    data = _body(req, fixtures_root, identity, fault)
    headers = {"Content-Type": "application/json", **req.get("headers", {})}

    def sign():
        if signed:
            from . import signing
            auth = signing.authorization(identity, data)
            headers["Authorization"] = _flip_signature(auth) if fault == "bad-signature" else auth

    sign()
    if fault == "replay":
        status, _ = _send(base_url, req, data, headers, timeout)
        if status != 200:
            raise ValueError(f"precondition failed: first request answered {status}, replay test is void")
        sign()  # fresh signature over the identical body: tests messageId dedupe, not header reuse
    return _send(base_url, req, data, headers, timeout)


def _check(s, base_url, timeout, fixtures_root, identity):
    try:
        status, raw = _call(base_url, s["request"], timeout, fixtures_root, identity)
    except Exception as e:  # unreachable, timeout, TLS failure, missing identity...
        return False, f"request error: {e}"
    exp = s["expect"]
    if status != exp["status"]:
        return False, f"status {status} != {exp['status']}"
    if exp.get("jsonpath"):
        try:
            doc = json.loads(raw)
        except ValueError:
            return False, "response is not JSON"
        for p, want in exp["jsonpath"].items():
            got = jsonpath(doc, p)
            if got is MISSING or (want is not None and got != want):
                return False, f"{p}: got {None if got is MISSING else got!r}, want {want!r}"
    return True, ""


def digest(report):
    body = {k: v for k, v in report.items() if k != "digest"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def run(scenarios, profile, base_url, participant, timeout=10, now=None,
        fixtures_root=DEFAULT_FIXTURES, identity=None):
    applicable = [s for s in scenarios if profile["role"] in s.get("roles", [profile["role"]])]
    results, warnings = [], []
    mand_fail = mand_pending = False
    for s in applicable:
        mandatory = s.get("level", "mandatory") == "mandatory"
        if s.get("pending"):
            results.append({"id": s["id"], "level": s.get("level", "mandatory"), "outcome": "pending"})
            mand_pending |= mandatory
            continue
        ok, why = _check(s, base_url, timeout, fixtures_root, identity)
        results.append({"id": s["id"], "level": s.get("level", "mandatory"),
                        "outcome": "pass" if ok else "fail", "detail": why})
        if not ok:
            if mandatory:
                mand_fail = True
            else:
                warnings.append(s["id"])
    has_mandatory = any(s.get("level", "mandatory") == "mandatory" for s in applicable)
    verdict = ("FAILED" if mand_fail else "INCOMPLETE" if mand_pending or not has_mandatory
               else "CERTIFIED")
    rep = {"participant": participant, "profile": profile["name"], "spec": profile["spec"],
           "role": profile["role"], "issued_at": int(now if now is not None else time.time()),
           "verdict": verdict, "warnings": warnings, "results": results}
    rep["digest"] = digest(rep)
    return rep


def admit(report, spec, role, now=None):
    """Registry gate: (True, 'ok') or (False, reason)."""
    if report.get("digest") != digest(report):
        return False, "digest mismatch (report altered)"
    if report["verdict"] != "CERTIFIED":
        return False, f"verdict {report['verdict']}"
    if report["spec"] != spec:
        return False, f"spec {report['spec']} != {spec}"
    if report["role"] != role:
        return False, f"role {report['role']} != {role}"
    if (now if now is not None else time.time()) - report["issued_at"] > MAX_AGE_SECONDS:
        return False, "report expired"
    return True, "ok"


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--profile", required=True, help="path to profile JSON")
    ap.add_argument("--participant", required=True)
    ap.add_argument("--scenarios", default=str(DEFAULT_SCENARIOS))
    ap.add_argument("--identity", help="JSON file: key_id, private_key_seed_b64, bap_id, bap_uri, network_id")
    ap.add_argument("--out")
    a = ap.parse_args()
    rep = run(load_scenarios(a.scenarios), json.loads(Path(a.profile).read_text()), a.base_url, a.participant,
              identity=json.loads(Path(a.identity).read_text()) if a.identity else None)
    text = json.dumps(rep, indent=2)
    Path(a.out).write_text(text) if a.out else print(text)
    raise SystemExit(0 if rep["verdict"] == "CERTIFIED" else 1)
