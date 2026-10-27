"""Peppol-style conformance runner: stdlib only, spec- and stack-agnostic.

A participant is certified for (spec, role) when every applicable mandatory
scenario passes. Pending or absent mandatory coverage yields INCOMPLETE, never
CERTIFIED. The report carries a sha256 digest so the registry can detect edits;
the digest is NOT a signature. Sign the report with the issuer's key before
trusting it across organisations.
"""
import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

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


def _call(base_url, req, timeout):
    body = req.get("body")
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json", **req.get("headers", {})}
    r = urllib.request.Request(base_url + req["path"], data=data, headers=headers,
                               method=req.get("method", "POST"))
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _check(s, base_url, timeout):
    try:
        status, raw = _call(base_url, s["request"], timeout)
    except Exception as e:  # unreachable, timeout, TLS failure...
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


def run(scenarios, profile, base_url, participant, timeout=10, now=None):
    applicable = [s for s in scenarios if profile["role"] in s.get("roles", [profile["role"]])]
    results, warnings = [], []
    mand_fail = mand_pending = False
    for s in applicable:
        mandatory = s.get("level", "mandatory") == "mandatory"
        if s.get("pending"):
            results.append({"id": s["id"], "level": s.get("level", "mandatory"), "outcome": "pending"})
            mand_pending |= mandatory
            continue
        ok, why = _check(s, base_url, timeout)
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
    ap.add_argument("--scenarios", default=str(Path(__file__).parent.parent / "tests" / "scenarios"))
    ap.add_argument("--out")
    a = ap.parse_args()
    rep = run(load_scenarios(a.scenarios), json.loads(Path(a.profile).read_text()), a.base_url, a.participant)
    text = json.dumps(rep, indent=2)
    Path(a.out).write_text(text) if a.out else print(text)
    raise SystemExit(0 if rep["verdict"] == "CERTIFIED" else 1)
