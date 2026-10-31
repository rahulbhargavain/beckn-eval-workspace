"""The ONIX deployment kit writes a coherent throwaway setup (the live run happens in CI, see docs/interop-onix.md)."""
import base64
import importlib.util
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("nacl.signing")
yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("prepare", ROOT / "interop" / "onix" / "deploy" / "prepare.py")
prepare = importlib.util.module_from_spec(spec)
sys.modules["prepare"] = prepare
spec.loader.exec_module(prepare)


@pytest.fixture()
def dep(tmp_path):
    prepare.main(tmp_path, "/opt/onix", "/run/dep")
    return tmp_path


def test_config_does_not_set_the_locked_registry_url(dep):
    cfg = yaml.safe_load((dep / "config.yaml").read_text())
    plugins = cfg["modules"][0]["handler"]["plugins"]
    assert plugins["registry"]["id"] == "dediregistry" and "url" not in plugins["registry"]["config"]
    assert cfg["pluginManager"]["root"] == "/opt/onix/plugins"
    assert plugins["router"]["config"]["routingConfig"] == "/run/dep/routing.yaml"  # path as the adapter sees it


def test_the_two_identities_differ_only_in_key_id_shape(dep):
    a = json.loads((dep / "identity-onix.json").read_text())
    b = json.loads((dep / "identity-spec.json").read_text())
    assert a["key_id"].count("|") == 2 and a["key_id"].endswith("|ed25519")  # subscriber|uniqueKeyId|ed25519
    assert b["key_id"].count("|") == 1 and b["key_id"].count("/") == 2  # {namespace}/{registry}/{record}|ed25519
    assert {k: v for k, v in a.items() if k != "key_id"} == {k: v for k, v in b.items() if k != "key_id"}


def test_the_registry_holds_the_identity_public_key(dep):
    ident = json.loads((dep / "identity-onix.json").read_text())
    pub = prepare.keypair(base64.b64decode(ident["private_key_seed_b64"]))[1]
    rec = json.loads((dep / "registry.json").read_text())[ident["bap_id"]]["bap-key-1"]
    assert rec["data"]["details"]["signing_public_key"] == pub
    assert rec["data"]["details"]["subscriber_id"] == ident["bap_id"]


def test_each_run_gets_fresh_keys(tmp_path):
    prepare.main(tmp_path / "a", "/o")
    prepare.main(tmp_path / "b", "/o")
    assert (tmp_path / "a" / "identity-onix.json").read_text() != (tmp_path / "b" / "identity-onix.json").read_text()
