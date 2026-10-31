"""The ONIX cross-check comparator, exercised with simulated peers so it needs no Go toolchain.
The real peer run happens in CI (see docs/interop-onix.md)."""
import base64
import importlib.util
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("nacl.signing")

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("crosscheck", ROOT / "interop" / "onix" / "crosscheck.py")
cc = importlib.util.module_from_spec(spec)
sys.modules["crosscheck"] = cc
spec.loader.exec_module(cc)

NOW = int(time.time())
V = cc.make_vectors(created=NOW - 5, expires=NOW + 300)
CASES = {c["name"]: c for c in V["cases"]}


def peer(prefix, accepts):
    """A simulated peer: signs every case body with `prefix`; `accepts(case, kind)` decides validation."""
    kp = cc.signing.Keypair(cc.signing.nacl.signing.SigningKey(base64.b64decode(V["seed_b64"])))
    out = {}
    for c in V["cases"]:
        r = {"validates_ours": {"ok": accepts(c, "req"), "error": ""},
             "validates_ours_ack": {"ok": accepts(c, "ack"), "error": ""} if c["ack_header"] else None}
        if c["sign"]:
            r["signature"] = kp.sign(cc._ours_with_prefix(V, c["body"], prefix))
            r["ack_signature"] = kp.sign(cc._ours_with_prefix(V, c["ack_body"], prefix, c["request_signature"]))
        out[c["name"]] = r
    return {"cases": out}


def rows(report):
    return {(r["case"], r["check"]): r for r in report["rows"]}


def test_the_vectors_cover_the_planned_shapes():
    assert {"base", "v2-keyid", "empty-body", "non-ascii-body", "onix-prefix", "headers-wrong",
            "headers-missing", "expired"} <= set(CASES)
    assert "BLAKE2b-512=" not in CASES["base"]["body"]
    assert "आ" in CASES["non-ascii-body"]["body"] or "क" in CASES["non-ascii-body"]["body"]
    assert CASES["empty-body"]["body"] == ""
    assert "|ed25519" in CASES["v2-keyid"]["key_id"] and CASES["v2-keyid"]["key_id"].count("/") >= 2


def test_our_strict_verifier_accepts_only_what_the_spec_allows():
    ok = {n: cc.ours_accepts(V, c["header"], c["body"], NOW) for n, c in CASES.items()}
    assert ok["base"] and ok["v2-keyid"] and ok["empty-body"] and ok["non-ascii-body"]
    assert not ok["onix-prefix"] and not ok["headers-wrong"] and not ok["headers-missing"] and not ok["expired"]


def test_a_spec_following_peer_agrees_on_every_row():
    rep = cc.compare(V, peer(cc.signing.DIGEST_PREFIX, lambda c, k: cc.ours_accepts(
        V, c["header"] if k == "req" else c["ack_header"], c["body"] if k == "req" else c["ack_body"], NOW,
        c["request_signature"] if k == "ack" else None)), now=NOW)
    assert [r for r in rep["rows"] if r["verdict"] == "DIFFER"] == []


def test_a_lenient_onix_style_peer_differs_where_expected_and_only_there():
    rep = cc.compare(V, peer(cc.ONIX_PREFIX, lambda c, k: c["onix_would_accept"]), now=NOW)
    r = rows(rep)
    differ = {(k[0], k[1]) for k, v in r.items() if v["verdict"] == "DIFFER"}
    assert ("base", "validates our request signature") in differ
    assert ("headers-wrong", "validates our request signature") in differ
    assert ("onix-prefix", "validates our request signature") in differ  # ONIX accepts, we do not
    assert r[("base", "we verify the signature the peer makes")]["verdict"] == "DIFFER"


def test_the_diagnostic_is_not_labelled_agree_or_differ():
    rep = cc.compare(V, peer(cc.ONIX_PREFIX, lambda c, k: False), now=NOW)
    diag = [r for r in rep["rows"] if r["check"].startswith("diagnostic")]
    assert diag and all(r["verdict"] == "DIAGNOSTIC" for r in diag)
    assert any(r["detail"] == "peer signatures verify under the other prefix" or r["ours"] for r in diag)


def test_baseline_comparison_flags_a_change():
    rep = cc.compare(V, peer(cc.ONIX_PREFIX, lambda c, k: False), now=NOW)
    base = cc.baseline_of(rep)
    assert cc.diff_baseline(rep, base) == []
    mutated = dict(base)
    key = next(iter(mutated))
    mutated[key] = "AGREE" if mutated[key] != "AGREE" else "DIFFER"
    assert cc.diff_baseline(rep, mutated) and key in cc.diff_baseline(rep, mutated)[0]


def _runner_accepts(c):
    from conformance import signing as runner_signing
    try:
        runner_signing.check_response({"signature": c["ack_header"]}, c["ack_body"].encode(), c["header"],
                                      {c["key_id"]: V["public_b64"]}, now=NOW)
        return True
    except runner_signing.ResponseSignatureError:
        return False


def test_the_runners_own_verifier_agrees_with_the_cross_check_on_the_positive_vectors():
    got = {n: _runner_accepts(c) for n, c in CASES.items() if c["ack_header"]}
    assert got == {"base": True, "v2-keyid": True, "empty-body": True, "non-ascii-body": True, "onix-prefix": False}
