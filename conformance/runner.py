"""Peppol-style conformance runner.

A participant is CERTIFIED for (spec, role) only when every scenario the profile pins
(by id and content hash) was run unaltered and every mandatory one passed. Reports are
signed by the test-bed operator; the registry's `admit` re-derives the verdict from the
results against its own copy of the profile, so neither a self-chosen scenario set nor an
edited report is admitted. Stdlib only, except PyNaCl for signed requests and reports.
"""
import base64
import copy
import hashlib
import json
import re
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlsplit

RUNNER_VERSION = "3"
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCENARIOS = ROOT / "tests" / "scenarios"
DEFAULT_FIXTURES = ROOT / "tests"
SIGNED = "beckn-http-signature"
MISSING = object()
MAX_AGE_SECONDS = 90 * 24 * 3600
MAX_FUTURE_SKEW = 300
MAX_RESPONSE_BYTES = 1_048_576  # a hostile SUT must not be able to stream the runner out of memory

ROLES = {"BAP", "BPP", "DS"}
LEVELS = {"mandatory", "recommended"}
FAULTS = {"bad-signature", "unknown-participant", "replay", "replay-new-body", "invalid-json",
          "missing-message"}
SCENARIO_KEYS = {"id", "level", "roles", "spec", "name", "notes", "pending", "pendingReason", "request", "expect"}
REQUEST_KEYS = {"method", "path", "body", "auth", "fault", "headers"}
EXPECT_KEYS = {"status", "status_in", "jsonpath", "headers", "response_signature"}
OPERATORS = {"exists", "type", "enum", "pattern"}
TYPES = {"string", "number", "integer", "boolean", "null", "object", "array"}


class ScenarioError(ValueError):
    pass


class TargetNotAllowed(ValueError):
    pass


LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def check_target(base_url, allow_hosts=None):
    """Remote targets must be https and explicitly allow-listed (exact host); loopback is always fine."""
    parts = urlsplit(base_url)
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("http", "https") or not host:
        raise TargetNotAllowed("base_url must be an http(s) URL")
    if "@" in parts.netloc:
        raise TargetNotAllowed("base_url must not carry credentials (they would be sent on and copied into the report)")
    if host in LOOPBACK:
        return
    if parts.scheme != "https":
        raise TargetNotAllowed(f"refusing plain http to remote host {host}")
    if host not in {h.lower() for h in (allow_hosts or ())}:
        raise TargetNotAllowed(f"remote host {host} is not in the allow-list (--allow-host)")


# ---------------------------------------------------------------- assertions
_TOKEN = r"\.[A-Za-z0-9_\-]+|\[\d+\]|\['[^']+'\]"
_PATH_RE = re.compile(rf"\$(?:{_TOKEN})*")
_TOKEN_RE = re.compile(r"\.([A-Za-z0-9_\-]+)|\[(\d+)\]|\['([^']+)'\]")


def jsonpath(data, path):
    """`$.a.b[0]['@type']` lookup; MISSING when absent; ScenarioError on unparseable paths."""
    if not isinstance(path, str) or not _PATH_RE.fullmatch(path):
        raise ScenarioError(f"unsupported jsonpath {path!r}")
    cur = data
    for key, idx, quoted in _TOKEN_RE.findall(path):
        k = key or quoted
        if k:
            if not isinstance(cur, dict) or k not in cur:
                return MISSING
            cur = cur[k]
        else:
            if not isinstance(cur, list) or int(idx) >= len(cur):
                return MISSING
            cur = cur[int(idx)]
    return cur


def values_match(got, want):
    if isinstance(got, bool) or isinstance(want, bool):
        return type(got) is type(want) and got == want
    return got == want


def _type_of(v):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "number"
    return {str: "string", dict: "object", list: "array"}.get(type(v), "other")


def _is_operator(want):
    return isinstance(want, dict) and want and set(want) <= OPERATORS


def op_match(got, op):
    present = got is not MISSING
    if "exists" in op and present != op["exists"]:
        return False
    if not present:
        return "exists" in op and op["exists"] is False and len(op) == 1
    if "type" in op:
        t = _type_of(got)
        if t != op["type"] and not (op["type"] == "number" and t == "integer"):
            return False
    if "enum" in op and not any(values_match(got, e) for e in op["enum"]):
        return False
    if "pattern" in op and not (isinstance(got, str) and re.search(op["pattern"], got)):
        return False
    return True


def _short(x, n=120):
    s = repr(x)
    return s if len(s) <= n else s[:n] + "...(truncated)"


# ---------------------------------------------------------------- scenarios
def validate_scenario(s):
    def bad(msg):
        raise ScenarioError(f"scenario {s.get('id', '?') if isinstance(s, dict) else '?'}: {msg}")

    if not isinstance(s, dict):
        raise ScenarioError("scenario must be an object")
    if unknown := set(s) - SCENARIO_KEYS:
        bad(f"unknown keys {sorted(unknown)}")
    if not isinstance(s.get("id"), str) or not s["id"]:
        bad("missing id")
    if s.get("level") not in LEVELS:
        bad(f"level must be one of {sorted(LEVELS)}")
    roles = s.get("roles")
    if not isinstance(roles, list) or not roles or not set(roles) <= ROLES:
        bad(f"roles must be a non-empty subset of {sorted(ROLES)}")
    req, exp = s.get("request"), s.get("expect")
    if not isinstance(req, dict) or not isinstance(exp, dict):
        bad("request and expect are required objects")
    if unknown := set(req) - REQUEST_KEYS:
        bad(f"unknown request keys {sorted(unknown)}")
    if not isinstance(req.get("path"), str):
        bad("request.path is required")
    if req.get("auth") not in (None, SIGNED):
        bad("unknown request.auth")
    if req.get("fault") is not None:
        if req["fault"] not in FAULTS:
            bad(f"unknown fault {req['fault']!r}")
        if req.get("auth") != SIGNED:
            bad("fault scenarios must use auth " + SIGNED)
    if unknown := set(exp) - EXPECT_KEYS:
        bad(f"unknown expect keys {sorted(unknown)}")
    if ("status" in exp) == ("status_in" in exp):
        bad("expect needs exactly one of status / status_in")
    if "status" in exp and not isinstance(exp["status"], int):
        bad("expect.status must be an integer")
    if "status_in" in exp and not (isinstance(exp["status_in"], list) and exp["status_in"]
                                   and all(isinstance(x, int) for x in exp["status_in"])):
        bad("expect.status_in must be a non-empty integer list")
    for p, want in (exp.get("jsonpath") or {}).items():
        try:
            jsonpath({}, p)
        except ScenarioError as e:
            bad(str(e))
        if isinstance(want, dict) and want and not set(want) <= OPERATORS and set(want) & OPERATORS:
            bad(f"mixed operator/literal object for {p}")
        if _is_operator(want) and "type" in want and want["type"] not in TYPES:
            bad(f"unknown type {want['type']!r}")
    for h, want in (exp.get("headers") or {}).items():
        if not _is_operator(want):
            bad(f"header {h} needs an operator object")
    if "response_signature" in exp:
        if exp["response_signature"] != {"chain": True}:
            bad('response_signature must be exactly {"chain": true}')
        if req.get("auth") != SIGNED:
            bad("response_signature needs a signed request (there is no request signature to chain to)")
    return s


def load_scenarios(directory):
    out, seen = [], set()
    for f in sorted(Path(directory).glob("*.json")):
        try:
            s = validate_scenario(json.loads(f.read_text(encoding="utf-8-sig")))
        except ScenarioError as e:
            raise ScenarioError(f"{f.name}: {e}") from None
        if s["id"] in seen:
            raise ScenarioError(f"{f.name}: duplicate id {s['id']}")
        seen.add(s["id"])
        out.append(s)
    return out


def _fixture_path(root, rel):
    root = Path(root).resolve()
    p = (root / rel).resolve()
    if Path(rel).is_absolute() or not p.is_relative_to(root):
        raise ValueError("body path outside the fixtures root")
    return p


def scenario_hash(s, fixtures_root):
    h = hashlib.sha256(json.dumps(s, sort_keys=True, separators=(",", ":")).encode())
    body = s["request"].get("body")
    if isinstance(body, str):
        try:
            raw = _fixture_path(fixtures_root, body).read_bytes()
            h.update(b"\0" + raw.replace(b"\r\n", b"\n"))  # same pin on CRLF (Windows) and LF checkouts
        except (OSError, ValueError):
            h.update(b"\0unreadable")
    return h.hexdigest()


def pin_profile(profile, scenarios, fixtures_root=DEFAULT_FIXTURES):
    """Profile with `required`: {mandatory scenario id: content hash} for its role."""
    req = {s["id"]: scenario_hash(s, fixtures_root) for s in scenarios
           if profile["role"] in s["roles"] and s["level"] == "mandatory"}
    return {**profile, "required": dict(sorted(req.items()))}


# ---------------------------------------------------------------- requests
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # a 3xx is a result to grade, never a hop that receives our Authorization


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
_PATH_OK = re.compile(r"/[A-Za-z0-9_\-./]*")


def _build_doc(req, fixtures_root, identity, fault):
    body = req.get("body")
    if isinstance(body, str):
        body = json.loads(_fixture_path(fixtures_root, body).read_text(encoding="utf-8-sig"))
    else:
        body = copy.deepcopy(body)
    if isinstance(body, dict) and req.get("auth") == SIGNED:
        body.setdefault("context", {}).update(
            bapId=identity["bap_id"], bapUri=identity["bap_uri"],
            networkId=identity["network_id"], messageId=str(uuid.uuid4()))
    if fault == "missing-message" and isinstance(body, dict):
        body.pop("message", None)
    return body


def _dumps(doc):
    return None if doc is None else json.dumps(doc, separators=(",", ":")).encode()


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


def _send(url, method, data, headers, timeout):
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    def bounded(stream):
        body = stream.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError(f"response larger than {MAX_RESPONSE_BYTES} bytes")
        return body

    try:
        with _OPENER.open(r, timeout=timeout) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, bounded(resp)
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, bounded(e)


def _call(base_url, req, timeout, fixtures_root, identity):
    """Returns (status, response headers, body bytes, sent context, Authorization header of the last request)."""
    signed, fault = req.get("auth") == SIGNED, req.get("fault")
    parts = urlsplit(base_url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("base_url must be an http(s) URL")
    path = req["path"]
    if not _PATH_OK.fullmatch(path) or path.startswith("//"):
        raise ValueError(f"invalid request path {path!r}")
    url = base_url.rstrip("/") + path
    if urlsplit(url).netloc != parts.netloc:
        raise ValueError("request path changed the target host")
    if signed and not identity:
        raise ValueError("scenario needs a signing identity (none supplied)")
    if fault == "unknown-participant":
        identity = _unknown_identity(identity)
    doc = _build_doc(req, fixtures_root, identity, fault)
    data = b'{"context": {"action": ' if fault == "invalid-json" else _dumps(doc)  # signed garbage
    headers = {"Content-Type": "application/json", **req.get("headers", {})}
    method = req.get("method", "POST")
    ctx = (doc or {}).get("context", {}) if isinstance(doc, dict) else {}

    def sign(payload, now):
        if signed:
            from . import signing
            auth = signing.authorization(identity, payload, now=now)
            headers["Authorization"] = _flip_signature(auth) if fault == "bad-signature" else auth

    t0 = int(time.time())
    sign(data, t0)
    if fault in ("replay", "replay-new-body"):
        status, _, _ = _send(url, method, data, headers, timeout)
        if status not in (200, 202):
            raise ValueError(f"precondition failed: first request answered {status}, replay test is void")
        if fault == "replay-new-body":
            doc["context"]["transactionId"] = str(uuid.uuid4())
            data = _dumps(doc)
        sign(data, t0 + 1)  # different created second => different Authorization header on a byte-identical body
    status, rh, raw = _send(url, method, data, headers, timeout)
    return status, rh, raw, ctx, headers.get("Authorization")


def _expected(want, ctx):
    if isinstance(want, str):
        m = re.fullmatch(r"\{\{request\.context\.(\w+)\}\}", want)
        if m:
            return ctx.get(m.group(1), MISSING)
    return want


def _check(s, base_url, timeout, fixtures_root, identity, sut_keys=None):
    try:
        status, rh, raw, ctx, sent_auth = _call(base_url, s["request"], timeout, fixtures_root, identity)
    except Exception as e:  # unreachable, timeout, TLS failure, missing identity, precondition...
        return False, f"request error: {_short(str(e), 200)}"
    exp = s["expect"]
    allowed = exp["status_in"] if "status_in" in exp else [exp["status"]]
    if status not in allowed:
        return False, f"status {status} not in {allowed}"
    for name, op in (exp.get("headers") or {}).items():
        got = rh.get(name.lower(), MISSING)
        if not op_match(got, op):
            return False, f"header {name}: got {_short(got if got is not MISSING else None)}, want {_short(op)}"
    if exp.get("jsonpath"):
        try:
            doc = json.loads(raw)
        except ValueError:
            return False, "response is not JSON"
        for p, want in exp["jsonpath"].items():
            got = jsonpath(doc, p)
            want = _expected(want, ctx)
            if want is MISSING:
                return False, f"{p}: template refers to a field the request did not carry"
            ok = op_match(got, want) if _is_operator(want) else (got is not MISSING and values_match(got, want))
            if not ok:
                return False, f"{p}: got {_short(None if got is MISSING else got)}, want {_short(want)}"
    if exp.get("response_signature"):
        from . import signing
        try:
            signing.check_response(rh, raw, sent_auth, sut_keys)
        except signing.ResponseSignatureError as e:
            return False, f"response Signature: {e}"
    return True, ""


# ---------------------------------------------------------------- reports
def digest(report):
    body = {k: v for k, v in report.items() if k not in ("digest", "signature")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def resign(report, issuer):
    """Set issuer_key_id, recompute digest, sign it (Ed25519) with the operator key."""
    from nacl.signing import SigningKey
    report["issuer_key_id"] = issuer["key_id"]
    report["digest"] = digest(report)
    key = SigningKey(base64.b64decode(issuer["private_key_seed_b64"]))
    report["signature"] = base64.b64encode(key.sign(report["digest"].encode()).signature).decode()
    return report


def plan(scenarios, profile, base_url, only=None):
    """Dry run: what would be sent, without signing or any network access."""
    out = []
    for s in scenarios:
        validate_scenario(s)
        if profile["role"] not in s["roles"] or (only and s["id"] not in only) or s.get("pending"):
            continue
        fault = s["request"].get("fault")
        out.append({"id": s["id"], "method": s["request"].get("method", "POST"),
                    "url": base_url.rstrip("/") + s["request"]["path"], "fault": fault,
                    "requests": 2 if fault in ("replay", "replay-new-body") else 1})
    return out


def run(scenarios, profile, base_url, participant, timeout=10, now=None,
        fixtures_root=DEFAULT_FIXTURES, identity=None, issuer=None, allow_hosts=None, delay=0, only=None, sut_keys=None):
    check_target(base_url, allow_hosts)
    for s in scenarios:
        validate_scenario(s)
    applicable = [s for s in scenarios if profile["role"] in s["roles"]]
    probe = bool(only)
    if probe:
        applicable = [s for s in applicable if s["id"] in only]
    by_id = {s["id"]: s for s in scenarios}
    problems = []
    for rid, h in (profile.get("required") or {}).items():
        s = by_id.get(rid)
        if s is None:
            problems.append(f"required scenario {rid} was not run")
        elif scenario_hash(s, fixtures_root) != h:
            problems.append(f"required scenario {rid} differs from the pinned version")
    results, warnings, hashes = [], [], {}
    mand_fail = mand_pending = False
    for i, s in enumerate(applicable):
        if delay and i:
            time.sleep(delay)
        mandatory = s["level"] == "mandatory"
        hashes[s["id"]] = scenario_hash(s, fixtures_root)
        if s.get("pending"):
            results.append({"id": s["id"], "level": s["level"], "outcome": "pending"})
            mand_pending |= mandatory
            continue
        ok, why = _check(s, base_url, timeout, fixtures_root, identity, sut_keys)
        results.append({"id": s["id"], "level": s["level"], "outcome": "pass" if ok else "fail", "detail": why})
        if not ok:
            if mandatory:
                mand_fail = True
            else:
                warnings.append(s["id"])
    has_mandatory = any(s["level"] == "mandatory" for s in applicable)
    if probe:
        problems.append("probe run (--only): subset of scenarios, never certifiable")
    verdict = ("FAILED" if mand_fail else "INCOMPLETE" if mand_pending or problems or not has_mandatory
               else "CERTIFIED")
    rep = {"participant": participant, "profile": profile["name"], "spec": profile["spec"],
           "role": profile["role"], "issued_at": int(now if now is not None else time.time()),
           "runner_version": RUNNER_VERSION, "base_url": base_url,
           "harness_key_id": (identity or {}).get("key_id"), "probe": probe, "verdict": verdict,
           "warnings": warnings, "problems": problems, "scenario_hashes": hashes, "results": results}
    rep["digest"] = digest(rep)
    return resign(rep, issuer) if issuer else rep


def admit(report, spec, role, participant, profile, issuer_public_key_b64, now=None):
    """Registry gate: (True, 'ok') or (False, reason). Never raises on malformed input."""
    try:
        return _admit(report, spec, role, participant, profile, issuer_public_key_b64, now)
    except Exception as e:
        return False, f"malformed report ({type(e).__name__})"


def _admit(report, spec, role, participant, profile, pub_b64, now):
    if not isinstance(report, dict):
        return False, "report is not an object"
    if not report.get("signature"):
        return False, "unsigned report (missing signature)"
    if report.get("digest") != digest(report):
        return False, "digest mismatch (report altered)"
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey
    try:
        VerifyKey(base64.b64decode(pub_b64)).verify(report["digest"].encode(), base64.b64decode(report["signature"]))
    except (BadSignatureError, ValueError):
        return False, "invalid issuer signature"
    for field, want in (("participant", participant), ("spec", spec), ("role", role), ("profile", profile["name"])):
        if report.get(field) != want:
            return False, f"{field} {report.get(field)!r} != {want!r}"
    required = profile.get("required")
    if not isinstance(required, dict) or not required:
        return False, "profile has no pinned required scenarios"
    ids = [r["id"] for r in report["results"]]
    if len(set(ids)) != len(ids):
        return False, "duplicate result ids"
    if report.get("probe"):
        return False, "probe run (subset of scenarios)"
    if report.get("problems"):
        return False, "report carries problems"
    outcomes = {r["id"]: r["outcome"] for r in report["results"]}
    for rid, h in required.items():
        if outcomes.get(rid) != "pass":
            return False, f"required scenario {rid} did not pass"
        if report["scenario_hashes"].get(rid) != h:
            return False, f"required scenario {rid} ran a different version"
    if report["verdict"] != "CERTIFIED":
        return False, f"verdict {report['verdict']}"
    t = now if now is not None else time.time()
    if report["issued_at"] > t + MAX_FUTURE_SKEW:
        return False, "report issued in the future"
    if t - report["issued_at"] > MAX_AGE_SECONDS:
        return False, "report expired"
    return True, "ok"


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url")
    ap.add_argument("--profile", required=True, help="path to profile JSON")
    ap.add_argument("--participant")
    ap.add_argument("--scenarios", default=str(DEFAULT_SCENARIOS))
    ap.add_argument("--identity", help="JSON file: key_id, private_key_seed_b64, bap_id, bap_uri, network_id")
    ap.add_argument("--issuer-key", help="operator JSON file: key_id, private_key_seed_b64 (signs the report)")
    ap.add_argument("--allow-host", action="append", default=[], help="exact remote host allowed (https only); repeatable")
    ap.add_argument("--sut-key", action="append", default=[], metavar="KEYID=BASE64_PUBLIC_KEY",
                    help="trusted public key of the system under test, to verify its response Signature; repeatable")
    ap.add_argument("--delay", type=float, default=0, help="seconds to wait between scenarios")
    ap.add_argument("--only", action="append", help="run only this scenario id (probe, never certifiable); repeatable")
    ap.add_argument("--dry-run", action="store_true", help="print the request plan and exit without any network access")
    ap.add_argument("--pin", action="store_true", help="print the profile with required scenario hashes and exit")
    ap.add_argument("--out")
    a = ap.parse_args()
    load = lambda p: json.loads(Path(p).read_text(encoding="utf-8-sig"))  # noqa: E731
    scenarios, profile = load_scenarios(a.scenarios), load(a.profile)
    if a.pin:
        print(json.dumps(pin_profile(profile, scenarios), indent=2))
        raise SystemExit(0)
    if not (a.base_url and a.participant):
        ap.error("--base-url and --participant are required unless --pin")
    if a.dry_run:
        check_target(a.base_url, a.allow_host)
        print(json.dumps(plan(scenarios, profile, a.base_url, set(a.only or [])), indent=2))
        raise SystemExit(0)
    sut_keys = {}
    for kv in a.sut_key:
        kid, sep, pub = kv.partition("=")
        if not sep or not kid or not pub:
            ap.error("--sut-key must look like KEYID=BASE64_PUBLIC_KEY")
        sut_keys[kid] = pub
    rep = run(scenarios, profile, a.base_url, a.participant, sut_keys=sut_keys,
              identity=load(a.identity) if a.identity else None,
              issuer=load(a.issuer_key) if a.issuer_key else None,
              allow_hosts=set(a.allow_host), delay=a.delay, only=set(a.only) if a.only else None)
    text = json.dumps(rep, indent=2)
    Path(a.out).write_text(text, encoding="utf-8") if a.out else print(text)
    raise SystemExit(0 if rep["verdict"] == "CERTIFIED" else 1)
