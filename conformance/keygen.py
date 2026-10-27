"""Generate a harness identity locally. The private seed never leaves the file and is never printed;
only the public key is returned/printed so it can be registered in the target registry (done by a human)."""
import argparse
import base64
import json
import os
from pathlib import Path
from urllib.parse import urlsplit


def make_identity(out, key_id, bap_id, bap_uri, network_id):
    from nacl.signing import SigningKey
    if urlsplit(bap_uri).scheme != "https":
        raise ValueError("bap_uri must be https")
    out = Path(out)
    sk = SigningKey.generate()
    doc = {"key_id": key_id, "bap_id": bap_id, "bap_uri": bap_uri, "network_id": network_id,
           "private_key_seed_b64": base64.b64encode(bytes(sk)).decode()}
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # FileExistsError, never overwrite
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    return base64.b64encode(bytes(sk.verify_key)).decode()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True)
    ap.add_argument("--key-id", required=True)
    ap.add_argument("--bap-id", required=True)
    ap.add_argument("--bap-uri", required=True)
    ap.add_argument("--network-id", required=True)
    a = ap.parse_args()
    print("public key (base64, register this):", make_identity(a.out, a.key_id, a.bap_id, a.bap_uri, a.network_id))
