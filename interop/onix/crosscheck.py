"""Cross-verify message signing against an independent implementation (beckn-onix, Go).

`vectors` writes signed messages made by this workspace's signer, in several shapes (see CASES below).
The Go test in `onix_interop_test.go` (copied into the ONIX checkout by CI) validates them with ONIX's own
validator and signs the same bodies with ONIX's own signer. `compare` then checks ONIX's signatures with
our verifier and reports, per case and check, whether the two implementations agree.

Scope: ONIX's plugin functions are called directly, so HTTP header extraction, key lookup and the identity
check are not exercised. The report is evidence about ONIX at a pinned commit, not a verdict for either side.
"""
import argparse
import base64
import hashlib
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "mockup"))
from beckn_mock import signing  # noqa: E402

ONIX_PREFIX = "BLAKE-512="
KEY_V1 = "interop.example.org|key-1|ed25519"
KEY_V2 = "interop.example.org/dedi/key-1|ed25519"  # {namespace}/{registry}/{record}|ed25519 (Signature schema)
BODY = '{"context":{"action":"select","version":"2.0.0"},"message":{"contract":{"commitments":[]}}}'
BODY_HI = '{"context":{"action":"select","version":"2.0.0"},"message":{"note":"कुमाऊँ सहकारी"}}'
ACK = '{"message":{"ack":{"status":"ACK"}}}'


def _header(kp, key_id, body, created, expires, prefix, request_signature=None, headers_attr="default"):
    """An Authorization header; `headers_attr` None omits the attribute, a string overrides it."""
    digest = prefix + base64.b64encode(hashlib.blake2b(body, digest_size=64).digest()).decode()
    sig = kp.sign(signing.signing_string(created, expires, digest, request_signature))
    if headers_attr == "default":
        return signing.format_header(key_id, created, expires, sig, chained=request_signature is not None)
    parts = [f'keyId="{key_id}"', 'algorithm="ed25519"', f'created="{created}"', f'expires="{expires}"']
    if headers_attr is not None:
        parts.append(f'headers="{headers_attr}"')
    parts.append(f'signature="{sig}"')
    return "Signature " + ",".join(parts)


def make_vectors(seed: bytes = bytes(range(32)), created: int = 1_900_000_000, expires: int = 1_900_000_300) -> dict:
    kp = signing.Keypair(signing.nacl.signing.SigningKey(seed))
    cases = []

    def case(name, key_id=KEY_V1, body=BODY, prefix=signing.DIGEST_PREFIX, ours_prefix=None, ack=True, sign=True,
             c=created, e=expires, headers_attr="default", onix=False, why=""):
        raw, ack_raw = body.encode("utf-8"), ACK.encode()
        hdr = _header(kp, key_id, raw, c, e, prefix, headers_attr=headers_attr)
        rs = signing.parse_authorization(hdr)["signature"] if headers_attr == "default" else hdr.split('signature="')[1].rstrip('"')
        cases.append({"name": name, "key_id": key_id, "body": body, "ack_body": ACK, "header": hdr,
                      "ack_header": _header(kp, key_id, ack_raw, c, e, prefix, request_signature=rs) if ack else None,
                      "request_signature": rs, "sign": sign, "created": c, "expires": e,
                      "ours_prefix": ours_prefix or signing.DIGEST_PREFIX, "onix_would_accept": onix, "why": why})

    case("base", why="v1-shaped keyId, ASCII body")
    case("v2-keyid", key_id=KEY_V2, why="keyId shaped as the Signature schema describes")
    case("empty-body", body="", why="zero-length body")
    case("non-ascii-body", body=BODY_HI, why="Devanagari text, UTF-8 bytes")
    case("onix-prefix", prefix=ONIX_PREFIX, onix=True, sign=False,
         why="signed with BLAKE-512=; our strict reading rejects it, ONIX is expected to accept it")
    # negatives are signed with ONIX's prefix so that ONIX can accept them and only the property under test differs
    case("headers-wrong", prefix=ONIX_PREFIX, ours_prefix=ONIX_PREFIX, ack=False, sign=False, onix=True,
         headers_attr="(created)", why="headers attribute does not list (expires) and digest")
    case("headers-missing", prefix=ONIX_PREFIX, ours_prefix=ONIX_PREFIX, ack=False, sign=False, onix=True,
         headers_attr=None, why="no headers attribute at all")
    case("expired", prefix=ONIX_PREFIX, ours_prefix=ONIX_PREFIX, ack=False, sign=False, c=created - 1000,
         e=created - 700, why="expires in the past")
    pub = kp.public_b64
    return {"seed_b64": base64.b64encode(seed).decode(), "public_b64": pub, "created": created,
            "expires": expires, "cases": cases}


def ours_accepts(v, header, body, now, request_signature=None, prefix=signing.DIGEST_PREFIX) -> bool:
    """Our strict reading of the spec: full header, headers attribute as required, window, spec digest prefix."""
    try:
        a = signing.parse_authorization(header)
    except signing.SignatureError:
        return False
    want = signing.CHAIN_HEADERS if request_signature is not None else signing.STD_HEADERS
    created, expires = int(a["created"]), int(a["expires"])
    if a["headers"] != want or a["algorithm"] != "ed25519" or expires <= created:
        return False
    if created > now + 5 or expires < now:
        return False
    digest = prefix + base64.b64encode(hashlib.blake2b(body.encode("utf-8"), digest_size=64).digest()).decode()
    return signing.verify(v["public_b64"], signing.signing_string(created, expires, digest, request_signature),
                          a["signature"])


def _ours_with_prefix(v, body, prefix, request_signature=None):
    digest = prefix + base64.b64encode(hashlib.blake2b(body.encode("utf-8"), digest_size=64).digest()).decode()
    return signing.signing_string(v["created"], v["expires"], digest, request_signature)


def compare(v: dict, onix: dict, now=None) -> dict:
    now = int(time.time()) if now is None else now
    rows = []

    def add(case, check, ours, theirs, detail=""):
        rows.append({"case": case, "check": check, "ours": ours, "onix": theirs,
                     "verdict": "AGREE" if ours == theirs else "DIFFER", "detail": detail})

    for c in v["cases"]:
        r = onix["cases"][c["name"]]
        add(c["name"], "validates our request signature",
            ours_accepts(v, c["header"], c["body"], now, prefix=c["ours_prefix"]), r["validates_ours"]["ok"],
            c["why"] + ("" if r["validates_ours"]["ok"] else f"; peer said: {r['validates_ours']['error']}"))
        if c["ack_header"]:
            add(c["name"], "validates our chained ack signature",
                ours_accepts(v, c["ack_header"], c["ack_body"], now, c["request_signature"], prefix=c["ours_prefix"]),
                r["validates_ours_ack"]["ok"])
        if c["sign"]:
            ok = (signing.verify(v["public_b64"], _ours_with_prefix(v, c["body"], signing.DIGEST_PREFIX), r["signature"])
                  and signing.verify(v["public_b64"], _ours_with_prefix(v, c["ack_body"], signing.DIGEST_PREFIX,
                                                                        c["request_signature"]), r["ack_signature"]))
            add(c["name"], "we verify the signature the peer makes", ok, True)
    # cause isolation, reported as information rather than agreement
    for c in v["cases"]:
        if c["sign"]:
            r = onix["cases"][c["name"]]
            ok = (signing.verify(v["public_b64"], _ours_with_prefix(v, c["body"], ONIX_PREFIX), r["signature"])
                  and signing.verify(v["public_b64"], _ours_with_prefix(v, c["ack_body"], ONIX_PREFIX,
                                                                        c["request_signature"]), r["ack_signature"]))
            rows.append({"case": c["name"], "check": "diagnostic: peer signatures verify under prefix " + ONIX_PREFIX,
                         "ours": ok, "onix": None, "verdict": "DIAGNOSTIC", "detail": ""})
    return {"spec": "beckn-2.0.0", "rows": rows,
            "note": "evidence about the peer at this commit; not a certification of either side"}


def baseline_of(report) -> dict:
    return {f"{r['case']} | {r['check']}": r["verdict"] + ("" if r["verdict"] != "DIAGNOSTIC" else f" {r['ours']}")
            for r in report["rows"]}


def diff_baseline(report, baseline) -> list:
    now = baseline_of(report)
    out = [f"{k}: expected {baseline.get(k, 'absent')}, got {now.get(k, 'absent')}"
           for k in sorted(set(now) | set(baseline)) if now.get(k) != baseline.get(k)]
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("vectors")
    g.add_argument("out")
    c = sub.add_parser("compare")
    c.add_argument("vectors")
    c.add_argument("onix_results")
    c.add_argument("--onix-commit", default="UNKNOWN")
    c.add_argument("--out")
    c.add_argument("--baseline", help="expected verdicts; exit 1 if they differ")
    c.add_argument("--write-baseline", help="write the current verdicts here")
    a = ap.parse_args(argv)
    if a.cmd == "vectors":
        now = int(time.time())  # the validator checks the created/expires window against its clock
        Path(a.out).write_text(json.dumps(make_vectors(created=now - 5, expires=now + 300), indent=2) + "\n")
        return 0
    v = json.loads(Path(a.vectors).read_text())
    rep = compare(v, json.loads(Path(a.onix_results).read_text()))
    rep["onix_commit"] = a.onix_commit
    if a.out:
        Path(a.out).write_text(json.dumps(rep, indent=2) + "\n")
    for r in rep["rows"]:
        print(f"{r['verdict']:10} {r['case']:16} {r['check']}" + (f" -- {r['detail']}" if r["detail"] else ""))
    if a.write_baseline:
        Path(a.write_baseline).write_text(json.dumps(baseline_of(rep), indent=2, sort_keys=True) + "\n")
    if a.baseline:
        diffs = diff_baseline(rep, json.loads(Path(a.baseline).read_text()))
        for d in diffs:
            print("BASELINE CHANGED " + d)
        return 1 if diffs else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
