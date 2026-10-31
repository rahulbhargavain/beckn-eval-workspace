"""Send one signed request to an ONIX BPP receiver and print what comes back.
usage: probe.py OUTDIR VARIANT [BASE_URL]   VARIANT: onix (3-part keyId, BLAKE-512= digest: what ONIX parses and validates),
                                          spec (keyId and digest as the v2.0.0 spec words them),
                                          or a mix such as onix+spec (ONIX keyId, spec digest)"""
import base64
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import crosscheck as cc  # noqa: E402

def send(out, variant, base="http://127.0.0.1:8082"):
    """Returns (status, parsed JSON body or None, headers) for one signed /select."""
    out = Path(out)
    # variant = <keyId shape>[+<digest prefix>]; the prefix defaults to the keyId's own side
    shape, _, dig = variant.partition("+")
    ident = json.loads((out / f"identity-{shape}.json").read_text())
    prefix = cc.ONIX_PREFIX if (dig or shape) == "onix" else cc.signing.DIGEST_PREFIX
    kp = cc.signing.Keypair(cc.signing.nacl.signing.SigningKey(base64.b64decode(ident["private_key_seed_b64"])))
    body = json.dumps({"context": {"action": "select", "version": "2.0.0", "domain": "beckn.one:deg:ev-charging:2.0.0",
                                   "bapId": ident["bap_id"], "bapUri": ident["bap_uri"], "bppId": "bpp.example.com",
                                   "networkId": ident["network_id"], "transactionId": str(uuid.uuid4()),
                                   "messageId": str(uuid.uuid4()),
                                   "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())},
                       "message": {"contract": {"commitments": []}}}).encode()
    now = int(time.time())
    hdr = cc._header(kp, ident["key_id"], body, now - 1, now + 120, prefix)
    req = urllib.request.Request(base + "/bpp/receiver/select", data=body, method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": hdr})
    try:
        r = urllib.request.urlopen(req, timeout=15)
        code, text, h = r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        code, text, h = e.code, e.read().decode(), e.headers
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None
    return code, doc, h


if __name__ == "__main__":
    code, doc, h = send(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "http://127.0.0.1:8082")
    print(sys.argv[2], "->", code, json.dumps(doc)[:300])
    print("  Signature response header present:", bool(h.get("Signature")))
