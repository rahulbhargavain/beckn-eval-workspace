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


def profile(name):
    return json.loads((ROOT / "conformance" / "profiles" / f"{name}.json").read_text(encoding="utf-8-sig"))


@pytest.mark.parametrize("name", ["ds-core", "bpp-core"])
def test_mockup_is_certified_and_admitted(net, name):
    prof = profile(name)
    rep = runner.run(runner.load_scenarios(runner.DEFAULT_SCENARIOS), prof, net.bpp_url, "mock-bpp",
                     identity=identity_for(net), issuer=ISSUER)
    assert rep["verdict"] == "CERTIFIED", [r for r in rep["results"] if r["outcome"] != "pass"]
    assert runner.admit(rep, spec="beckn-2.0.0", role=prof["role"], participant="mock-bpp", profile=prof,
                        issuer_public_key_b64=ISSUER_PUB) == (True, "ok")


def test_unregistered_harness_identity_fails(net):
    rep = runner.run(runner.load_scenarios(runner.DEFAULT_SCENARIOS), profile("ds-core"), net.bpp_url, "mock-bpp",
                     identity=identity_for(net, "ghost.example", register=False))
    assert rep["verdict"] == "FAILED"


def test_subset_of_scenarios_cannot_certify(net):
    scs = [s for s in runner.load_scenarios(runner.DEFAULT_SCENARIOS) if s["id"] == "DISC-001"]
    rep = runner.run(scs, profile("ds-core"), net.bpp_url, "mock-bpp", identity=identity_for(net))
    assert rep["verdict"] == "INCOMPLETE"
