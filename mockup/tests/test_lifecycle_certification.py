"""LIFE-001: the mandatory provider lifecycle (select, init, confirm, status) as one signed flow.

The oracle is the spec (beckn.yaml, commit a22300a), not the mockup: each mutant below breaks one MUST and the
flow has to FAIL. The node under test gets a `seed` (what to select, who the buyer is, how payment is evidenced)
because catalogs and payment evidence are node- and domain-specific; the harness derives every later request from
the callbacks it receives."""
import copy
import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from beckn_mock.lifecycle_seed import seed_for  # noqa: E402
from conformance import runner  # noqa: E402
from test_conformance_runner import _cb_identity, profile, sut_keys  # noqa: E402

FLOW_SCENARIOS = Path(ROOT / "tests" / "scenarios")


def life(**over):
    s = next(x for x in runner.load_scenarios(runner.DEFAULT_SCENARIOS) if x["id"] == "LIFE-001")
    s = copy.deepcopy(s)
    s["flow"].update(over)
    return s


def run_life(net, scenario=None, seed="default"):
    prof = {"name": "p", "spec": "beckn-2.0.0", "role": "BPP"}
    seed = seed_for(net) if seed == "default" else seed
    return runner.run([scenario or life()], prof, net.bpp_url, "mock-bpp", identity=_cb_identity(net),
                      sut_keys=sut_keys(net), seed=seed)["results"][0]


def test_the_mockup_passes_the_whole_lifecycle(net):
    r = run_life(net)
    assert r["outcome"] == "pass", r


def test_without_a_seed_the_lifecycle_fails_and_says_why(net):
    r = run_life(net, seed=None)
    assert r["outcome"] == "fail" and "--seed" in r["detail"], r


def test_a_remote_target_fails_clearly_because_callbacks_need_the_local_listener():
    prof = {"name": "p", "spec": "beckn-2.0.0", "role": "BPP"}
    ident = {"key_id": "k|ed25519", "bap_id": "h", "bap_uri": "https://h.example", "network_id": "n",
             "private_key_seed_b64": "A" * 43 + "="}
    r = runner.run([life()], prof, "https://sut.example", "p", identity=ident, allow_hosts={"sut.example"},
                   seed={"select": {"contract": {"commitments": []}}})["results"][0]
    assert r["outcome"] == "fail" and "loopback" in r["detail"], r


def test_a_node_that_acks_but_never_calls_back_fails_at_the_first_step(net):
    net.bpp.callback_delay = 5
    r = run_life(net, life(within=0.5))
    assert r["outcome"] == "fail" and "select" in r["detail"] and "no on_select callback" in r["detail"], r


def _mutate(net, action, fn):
    real = net.bpp._callback_body

    def wrapped(act, ctx, message, *a, **k):
        body = real(act, ctx, message, *a, **k)
        if act == action:
            fn(body)
        return body

    net.bpp._callback_body = wrapped


def _drop_contract_id(b):
    b["message"]["contract"].pop("id", None)


def _bad_id(b):
    b["message"]["contract"]["id"] = "not-a-uuid"


def _not_active(b):
    b["message"]["contract"]["status"] = {"code": "DRAFT"}


def _no_performance(b):
    b["message"]["contract"].pop("performance", None)


def _other_txn(b):
    b["context"]["transactionId"] = "00000000-0000-4000-8000-000000000000"


def _empty_commitments(b):
    b["message"]["contract"]["commitments"] = []


def _other_contract(b):
    b["message"]["contract"]["id"] = "00000000-0000-4000-8000-000000000001"


@pytest.mark.parametrize("action,fn,where", [
    ("select", _empty_commitments, "select"),
    ("select", _other_txn, "select"),
    ("init", _drop_contract_id, "init"),
    ("init", _bad_id, "init"),
    ("confirm", _not_active, "confirm"),
    ("confirm", _no_performance, "confirm"),
    ("confirm", _bad_id, "confirm"),
    ("status", _other_contract, "status"),
    ("status", _other_txn, "status"),
])
def test_each_broken_must_fails_the_flow_at_its_step(net, action, fn, where):
    _mutate(net, action, fn)
    r = run_life(net)
    assert r["outcome"] == "fail" and r["detail"].startswith(f"step {where}"), r


def test_bpp_core_requires_the_lifecycle_and_is_certified_for_the_mockup(net):
    prof = profile("bpp-core")
    assert "LIFE-001" in prof["required"]
    rep = runner.run(runner.load_scenarios(runner.DEFAULT_SCENARIOS), prof, net.bpp_url, "mock-bpp",
                     identity=_cb_identity(net), sut_keys=sut_keys(net), seed=seed_for(net))
    assert rep["verdict"] == "CERTIFIED", [r for r in rep["results"] if r["outcome"] != "pass"]


def test_bpp_core_without_a_seed_cannot_be_certified(net):
    rep = runner.run(runner.load_scenarios(runner.DEFAULT_SCENARIOS), profile("bpp-core"), net.bpp_url, "mock-bpp",
                     identity=_cb_identity(net), sut_keys=sut_keys(net))
    assert rep["verdict"] == "FAILED"
    assert any(r["id"] == "LIFE-001" and r["outcome"] == "fail" for r in rep["results"])
