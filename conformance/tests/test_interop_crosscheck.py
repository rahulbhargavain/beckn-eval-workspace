"""The ONIX cross-check comparator, exercised with simulated peers so it needs no Go toolchain.
The real peer run happens in CI (see docs/interop-onix.md)."""
import base64
import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("nacl.signing")

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("crosscheck", ROOT / "interop" / "onix" / "crosscheck.py")
cc = importlib.util.module_from_spec(spec)
sys.modules["crosscheck"] = cc
spec.loader.exec_module(cc)

V = cc.make_vectors()


def peer(prefix, validates):
    """A simulated peer that signs with the given digest prefix."""
    kp = cc.signing.Keypair(cc.signing.nacl.signing.SigningKey(base64.b64decode(V["seed_b64"])))
    s3 = cc._ours_with_prefix(V, V["body"], prefix)
    s4 = cc._ours_with_prefix(V, V["ack_body"], prefix, V["request_signature"])
    verdict = {"ok": validates, "error": "" if validates else "signature verification failed"}
    return {"validates_ours": verdict, "validates_ours_ack": verdict,
            "signature": kp.sign(s3), "ack_signature": kp.sign(s4)}


def by_name(checks):
    return {c["name"]: c["agree"] for c in checks}


def test_a_peer_that_follows_the_spec_prefix_agrees_on_everything_strict():
    got = by_name(cc.compare(V, peer(cc.signing.DIGEST_PREFIX, True)))
    strict = [v for k, v in got.items() if not k.startswith("ONIX signatures verify if")]
    assert strict and all(strict)


def test_a_peer_using_the_other_prefix_differs_and_the_cause_is_isolated():
    checks = cc.compare(V, peer(cc.ONIX_PREFIX, False))
    got = by_name(checks)
    assert sum(1 for v in got.values() if not v) == 4
    assert got["ONIX signatures verify if the digest prefix is BLAKE-512="] is True


def test_the_vectors_use_the_spec_digest_prefix():
    assert len(base64.b64decode(V["public_b64"])) == 32
    digest = base64.b64encode(hashlib.blake2b(V["body"].encode(), digest_size=64).digest()).decode()
    assert digest in cc._ours_with_prefix(V, V["body"], cc.signing.DIGEST_PREFIX)
