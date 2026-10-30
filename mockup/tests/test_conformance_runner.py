"""The shared conformance runner (conformance/runner.py) against the independent
mockup node: proves runner signing/templating/fault injection interoperates with a
separate implementation of the same spec, and that the pinned profiles + signed
reports + registry gate work end to end.

The mockup co-hosts a Discovery Service in its BPP (docs/mockup-findings.md), so the
same URL is certified for both the DS and the PN profile."""
import base64
import json
import sys
from pathlib import Path

import nacl.signing
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from conformance import runner  # noqa: E402

OP = nacl.signing.SigningKey.generate()
ISSUER = {"key_id": "operator/keys/1", "private_key_seed_b64": base64.b64encode(bytes(OP)).decode()}
ISSUER_PUB = base64.b64encode(bytes(OP.verify_key)).decode()


def identity_for(net, subscriber="harness.example", register=True):
    ident = net.new_identity(subscriber, "BAP", net.bap_url, register=register)
    return {"key_id": ident.key_id, "bap_id": subscriber, "bap_uri": net.bap_url, "network_id": net.network_id,
            "private_key_seed_b64": base64.b64encode(bytes(ident.keypair.signing_key)).decode()}


def sut_keys(net):
    """Operator-supplied trust for the node under test; the harness never fetches keys named in headers."""
    return {net.bpp.identity.key_id: net.bpp.identity.keypair.public_b64}


def profile(name):
    return json.loads((ROOT / "conformance" / "profiles" / f"{name}.json").read_text(encoding="utf-8-sig"))


@pytest.mark.parametrize("name", ["ds-core", "bpp-core"])
def test_mockup_is_certified_and_admitted(net, name):
    prof = profile(name)
    rep = runner.run(runner.load_scenarios(runner.DEFAULT_SCENARIOS), prof, net.bpp_url, "mock-bpp",
                     identity=identity_for(net), issuer=ISSUER, sut_keys=sut_keys(net))
    assert rep["verdict"] == "CERTIFIED", [r for r in rep["results"] if r["outcome"] != "pass"]
    assert runner.admit(rep, spec="beckn-2.0.0", role=prof["role"], participant="mock-bpp", profile=prof,
                        issuer_public_key_b64=ISSUER_PUB) == (True, "ok")


def test_unregistered_harness_identity_fails(net):
    rep = runner.run(runner.load_scenarios(runner.DEFAULT_SCENARIOS), profile("ds-core"), net.bpp_url, "mock-bpp",
                     identity=identity_for(net, "ghost.example", register=False),
                     sut_keys=sut_keys(net))
    assert rep["verdict"] == "FAILED"


def test_subset_of_scenarios_cannot_certify(net):
    scs = [s for s in runner.load_scenarios(runner.DEFAULT_SCENARIOS) if s["id"] == "DISC-001"]
    rep = runner.run(scs, profile("ds-core"), net.bpp_url, "mock-bpp", identity=identity_for(net), sut_keys=sut_keys(net))
    assert rep["verdict"] == "INCOMPLETE"


def test_node_that_chains_its_response_signature_to_the_wrong_request_fails(net):
    """Mutation check: sign_response chains to a constant instead of the incoming request signature."""
    real = net.bpp.sign_response
    net.bpp.sign_response = lambda raw, request_signature: real(raw, "AAAA")
    rep = runner.run(runner.load_scenarios(runner.DEFAULT_SCENARIOS), profile("ds-core"), net.bpp_url, "mock-bpp",
                     identity=identity_for(net), sut_keys=sut_keys(net))
    assert rep["verdict"] == "FAILED"
    assert any("response Signature" in r.get("detail", "") for r in rep["results"] if r["outcome"] == "fail")


def test_certification_is_impossible_without_the_nodes_public_key(net):
    rep = runner.run(runner.load_scenarios(runner.DEFAULT_SCENARIOS), profile("ds-core"), net.bpp_url, "mock-bpp",
                     identity=identity_for(net))
    assert rep["verdict"] == "FAILED"
    assert any("--sut-key" in r.get("detail", "") for r in rep["results"])


# ---------------------------------------------------------------- async on_* callbacks (local listener)
def _cb_base():
    s = next(x for x in runner.load_scenarios(runner.DEFAULT_SCENARIOS) if x["id"] == "CB-001")
    return json.loads(json.dumps(s))


def _cb_scenario(**over):
    s = _cb_base()
    s["expect"]["callback"].update(over)
    return s


def _free_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _cb_identity(net):
    """A harness identity registered with the loopback URL the runner's listener will bind."""
    uri = f"http://127.0.0.1:{_free_port()}"
    ident = net.new_identity("cb.harness.example", "BAP", uri, register=True)
    net.bpp.callback_allowlist = [*net.bpp.callback_allowlist, uri]  # the node's own SSRF policy: allow this origin
    return {"key_id": ident.key_id, "bap_id": "cb.harness.example", "bap_uri": uri, "network_id": net.network_id,
            "private_key_seed_b64": base64.b64encode(bytes(ident.keypair.signing_key)).decode()}


def _run_cb(net, scenario, identity=None):
    prof = {"name": "p", "spec": "beckn-2.0.0", "role": "DS"}
    return runner.run([scenario], prof, net.bpp_url, "mock-bpp", identity=identity or _cb_identity(net),
                      sut_keys=sut_keys(net))["results"][0]


def test_cb001_the_mockup_delivers_a_verifiable_on_discover(net):
    r = _run_cb(net, _cb_scenario())
    assert r["outcome"] == "pass", r


def test_cb001_a_callback_chained_to_the_wrong_request_fails(net, monkeypatch):
    """Only the asynchronous callback is mis-chained. The synchronous Ack stays valid, so the scenario must
    reach the callback stage and fail there (not earlier on the Ack, which would also close the listener
    before the node's callback arrives)."""
    import sys
    from beckn_mock import signing as msign
    real = msign.sign_message

    def sign(kp, kid, raw, c, e, request_signature=None):
        in_callback = sys._getframe(1).f_code.co_name == "_deliver"
        return real(kp, kid, raw, c, e, request_signature="AAAA" if (in_callback and request_signature) else request_signature)

    monkeypatch.setattr(msign, "sign_message", sign)
    r = _run_cb(net, _cb_scenario(within=2))
    assert r["outcome"] == "fail" and r["detail"].startswith("callback refused:") and "does not verify" in r["detail"], r


def test_cb001_a_callback_that_never_comes_fails_after_the_wait(net):
    net.bpp.callback_delay = 5
    r = _run_cb(net, _cb_scenario(within=0.5))
    assert r["outcome"] == "fail" and "no on_discover callback" in r["detail"], r


def test_cb001_expected_callback_content_is_asserted(net):
    r = _run_cb(net, _cb_scenario(jsonpath={"$.message.catalogs[0].id": {"pattern": "^never-matches$"}}))
    assert r["outcome"] == "fail" and "catalogs" in r["detail"], r


def test_callback_scenarios_fail_clearly_against_a_remote_target():
    prof = {"name": "p", "spec": "beckn-2.0.0", "role": "DS"}
    ident = {"key_id": "k|ed25519", "bap_id": "h", "bap_uri": "https://h.example", "network_id": "n",
             "private_key_seed_b64": base64.b64encode(bytes(nacl.signing.SigningKey.generate())).decode()}
    r = runner.run([_cb_base()], prof, "https://sut.example", "p", identity=ident,
                   allow_hosts={"sut.example"})["results"][0]
    assert r["outcome"] == "fail" and "loopback" in r["detail"], r


def test_callback_scenario_needs_a_loopback_bap_uri_even_on_a_loopback_target(net):
    r = _run_cb(net, _cb_scenario(), identity=dict(identity_for(net), bap_uri="https://harness.example/b"))
    assert r["outcome"] == "fail" and "bap_uri" in r["detail"], r


def test_callback_scenario_validation():
    for bad in ({"action": "discover"}, {"action": "on_x", "within": 0}, {"action": "on_x", "within": 61},
                {"action": "on_x", "extra": 1}, "on_x", {"within": 3}):
        s = _cb_base()
        s["expect"]["callback"] = bad
        with pytest.raises(runner.ScenarioError):
            runner.validate_scenario(s)
    s = _cb_base()
    s["request"].pop("auth")
    with pytest.raises(runner.ScenarioError):
        runner.validate_scenario(s)
