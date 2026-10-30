"""The `if_present` operator: a field the spec allows to be absent must be well-formed when it is there."""
from conformance import runner

UUID = {"if_present": True, "type": "string", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"}


def test_absent_passes():
    assert runner.op_match(runner.MISSING, UUID)


def test_present_and_valid_passes():
    assert runner.op_match("3f8a2b1c-6d4e-4f0a-9b7c-1e2d3c4b5a61", UUID)


def test_present_but_malformed_fails():
    assert not runner.op_match("not-a-uuid", UUID)
    assert not runner.op_match(7, UUID)


def test_scenarios_may_use_it():
    s = {"id": "X", "level": "recommended", "roles": ["BPP"], "spec": "s", "request": {"path": "/x"},
         "expect": {"status": 200, "jsonpath": {"$.a": UUID}}}
    runner.validate_scenario(s)
