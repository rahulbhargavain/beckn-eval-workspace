"""Cross-verify message signing against an independent implementation (beckn-onix, Go).

`vectors` writes signed messages made by this workspace's signer. The Go test in `onix_interop_test.go`
(copied into the ONIX checkout by CI) validates them with ONIX's own validator and signs the same bodies
with ONIX's own signer. `compare` then checks ONIX's signatures with our verifier and reports, per
check, whether the two implementations agree. It also isolates the cause of a disagreement by retrying
with the digest prefix ONIX uses.

The report is evidence about ONIX at a pinned commit, not a conformance verdict for either side.
"""
import argparse
import base64
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "mockup"))
from beckn_mock import signing  # noqa: E402

KEY_ID = "interop.example.org|key-1|ed25519"
ONIX_PREFIX = "BLAKE-512="
BODY = '{"context":{"action":"select","version":"2.0.0"},"message":{"contract":{"commitments":[]}}}'
ACK = '{"message":{"ack":{"status":"ACK"}}}'


def make_vectors(seed: bytes = bytes(range(32)), created: int = 1_900_000_000, expires: int = 1_900_000_300) -> dict:
    kp = signing.Keypair(signing.nacl.signing.SigningKey(seed))
    body, ack = BODY.encode(), ACK.encode()
    header = signing.sign_message(kp, KEY_ID, body, created, expires)
    req_sig = signing.parse_authorization(header)["signature"]
    ack_header = signing.sign_message(kp, KEY_ID, ack, created, expires, request_signature=req_sig)
    return {"seed_b64": base64.b64encode(seed).decode(), "public_b64": kp.public_b64, "key_id": KEY_ID,
            "created": created, "expires": expires, "body": BODY, "ack_body": ACK,
            "header": header, "ack_header": ack_header, "request_signature": req_sig}


def _ours_with_prefix(v, body, prefix, request_signature=None):
    import hashlib
    digest = prefix + base64.b64encode(hashlib.blake2b(body.encode(), digest_size=64).digest()).decode()
    return signing.signing_string(v["created"], v["expires"], digest, request_signature)


def compare(v: dict, onix: dict) -> list:
    """onix: {"validates_ours": {"ok": bool, "error": str}, "validates_ours_ack": {...},
              "signature": b64, "ack_signature": b64}"""
    checks = []

    def add(name, ok, detail=""):
        checks.append({"name": name, "agree": bool(ok), "detail": detail})

    for key, name in (("validates_ours", "ONIX validates our request signature"),
                      ("validates_ours_ack", "ONIX validates our chained ack signature")):
        r = onix[key]
        add(name, r["ok"], "" if r["ok"] else r["error"])
    pub = v["public_b64"]
    s3 = _ours_with_prefix(v, v["body"], signing.DIGEST_PREFIX)
    add("we verify the signature ONIX makes over the same body",
        signing.verify(pub, s3, onix["signature"]),
        f"we expect signing string digest prefix {signing.DIGEST_PREFIX}")
    s4 = _ours_with_prefix(v, v["ack_body"], signing.DIGEST_PREFIX, v["request_signature"])
    add("we verify the chained ack signature ONIX makes",
        signing.verify(pub, s4, onix["ack_signature"]),
        "request-signature line appended as the fourth line")
    # cause isolation: only meaningful when the strict checks above disagree
    s3o = _ours_with_prefix(v, v["body"], ONIX_PREFIX)
    s4o = _ours_with_prefix(v, v["ack_body"], ONIX_PREFIX, v["request_signature"])
    add("ONIX signatures verify if the digest prefix is " + ONIX_PREFIX,
        signing.verify(pub, s3o, onix["signature"]) and signing.verify(pub, s4o, onix["ack_signature"]),
        "diagnostic: shows whether the digest prefix is the only difference")
    return checks


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
    a = ap.parse_args(argv)
    if a.cmd == "vectors":
        now = int(time.time())  # the validator checks the created/expires window against its clock
        Path(a.out).write_text(json.dumps(make_vectors(created=now - 5, expires=now + 300), indent=2) + "\n")
        return 0
    v = json.loads(Path(a.vectors).read_text())
    checks = compare(v, json.loads(Path(a.onix_results).read_text()))
    rep = {"onix_commit": a.onix_commit, "spec": "beckn-2.0.0", "checks": checks,
           "note": "evidence about ONIX at this commit; not a certification of either side"}
    text = json.dumps(rep, indent=2)
    if a.out:
        Path(a.out).write_text(text + "\n")
    for ch in checks:
        print(("AGREE   " if ch["agree"] else "DIFFER  ") + ch["name"] + (f" -- {ch['detail']}" if ch["detail"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
