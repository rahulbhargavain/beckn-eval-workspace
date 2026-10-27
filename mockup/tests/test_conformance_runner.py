"""The shared conformance runner (conformance/runner.py) against the independent
mockup BPP: proves runner signing/templating interoperates with a separate
implementation of the same spec, and that bad identities are rejected."""
import base64
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from conformance import runner  # noqa: E402


def identity_for(net, subscriber="harness.example"):
    ident = net.new_identity(subscriber, "BAP", net.bap_url)
    return {"key_id": ident.key_id, "bap_id": subscriber, "bap_uri": net.bap_url,
            "network_id": net.network_id,
            "private_key_seed_b64": base64.b64encode(bytes(ident.keypair.signing_key)).decode()}


def test_scenario_001_certifies_bpp(net):
    profile = {"name": "bpp-core", "spec": "beckn-2.0.0", "role": "BPP"}
    rep = runner.run(runner.load_scenarios(runner.DEFAULT_SCENARIOS), profile, net.bpp_url, "mock-bpp",
                     identity=identity_for(net))
    assert rep["verdict"] == "CERTIFIED", rep["results"]
    assert runner.admit(rep, spec="beckn-2.0.0", role="BPP") == (True, "ok")


def test_unregistered_identity_fails(net):
    ident = net.new_identity("ghost.example", "BAP", net.bap_url, register=False)
    idd = identity_for(net)
    idd.update(key_id=ident.key_id, bap_id="ghost.example",
               private_key_seed_b64=base64.b64encode(bytes(ident.keypair.signing_key)).decode())
    profile = {"name": "bpp-core", "spec": "beckn-2.0.0", "role": "BPP"}
    rep = runner.run(runner.load_scenarios(runner.DEFAULT_SCENARIOS), profile, net.bpp_url, "mock-bpp", identity=idd)
    assert rep["verdict"] == "FAILED"
