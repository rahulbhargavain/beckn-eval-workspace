"""Run the language-agnostic scenario tests/scenarios/001-search-ack.json against the
mockup BPP, so the shared fixture is proven against the real spec envelope.

The scenario runner (scripts/test.ps1) does not sign requests; here we sign as the
mockup BAP and template the participant fields (bapId, bapUri, messageId), which
any real harness also has to do (see tests/scenarios notes).
"""
import json
import uuid
from pathlib import Path

from beckn_mock import client, spec

TESTS = Path(__file__).resolve().parents[2] / "tests"


def _jsonpath_get(doc, path):
    assert path.startswith("$.")
    cur = doc
    for part in path[2:].split("."):
        cur = cur[part]
    return cur


def test_fixture_is_schema_valid():
    scenario = json.loads((TESTS / "scenarios" / "001-search-ack.json").read_text(encoding="utf-8"))
    body = json.loads((TESTS / scenario["request"]["body"]).read_text(encoding="utf-8"))
    assert spec.request_errors(scenario["request"]["path"], body) == []
    assert "pending" not in scenario
    assert scenario["spec"].startswith("beckn-2.0.0")


def test_scenario_passes_against_mockup(net):
    scenario = json.loads((TESTS / "scenarios" / "001-search-ack.json").read_text(encoding="utf-8"))
    body = json.loads((TESTS / scenario["request"]["body"]).read_text(encoding="utf-8"))
    body["context"].update(bapId=net.bap.subscriber_id, bapUri=net.bap_url,
                           messageId=str(uuid.uuid4()), networkId=net.network_id)
    res = client.post_signed(net.bpp_url + scenario["request"]["path"], body, net.bap.identity)
    assert res.status_code == scenario["expect"]["status"], res.text
    for path, expected in scenario["expect"]["jsonpath"].items():
        assert _jsonpath_get(res.json(), path) == expected
