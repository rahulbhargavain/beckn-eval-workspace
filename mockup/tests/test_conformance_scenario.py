"""The shared fixtures must be valid against the real v2 request schemas. Executing the
scenarios is done by the conformance runner (see test_conformance_runner.py)."""
import json
from pathlib import Path

import pytest

from beckn_mock import spec

TESTS = Path(__file__).resolve().parents[2] / "tests"


@pytest.mark.parametrize("name", ["disc-001.json", "pnneg-001.json"])
def test_fixture_is_schema_valid(name):
    scenario = json.loads((TESTS / "scenarios" / name).read_text(encoding="utf-8"))
    body = json.loads((TESTS / scenario["request"]["body"]).read_text(encoding="utf-8"))
    assert spec.request_errors(scenario["request"]["path"], body) == []
    assert not scenario.get("pending")
    assert scenario["spec"].startswith("beckn-2.0.0")
