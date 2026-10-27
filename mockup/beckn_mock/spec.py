"""Loads the Beckn v2.0.0 OpenAPI contract (read-only, parsed with yaml.safe_load) and
exposes JSON Schema 2020-12 validators for request bodies and components.

The spec repo is treated as untrusted data: nothing from it is executed or imported.
Location can be overridden with BECKN_SPEC_DIR.
"""
import functools
import os
import re
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

_REPO = Path(__file__).resolve().parents[2]
SPEC_DIR = Path(os.environ.get("BECKN_SPEC_DIR", _REPO / "vendor" / "protocol-specifications-v2"))
SPEC_PATH = SPEC_DIR / "api" / "v2.0.0" / "beckn.yaml"
SPEC = yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))
SPEC_URI = "urn:beckn:protocol-specifications-v2:api:v2.0.0"

_REGISTRY = Registry().with_resource(SPEC_URI, Resource(contents=SPEC, specification=DRAFT202012))
# 'format' is annotation-only in 2020-12; opt in to assertion so uuid/date-time/uri are enforced.
_FORMATS = Draft202012Validator.FORMAT_CHECKER


def _pointer(*parts):
    return "/".join(p.replace("~", "~0").replace("/", "~1") for p in parts)


@functools.lru_cache(maxsize=None)
def _validator(ref):
    return Draft202012Validator({"$ref": f"{SPEC_URI}#/{ref}"}, registry=_REGISTRY, format_checker=_FORMATS)


def has_path(path):
    return path in SPEC["paths"] and "post" in SPEC["paths"][path]


def _fmt(err):
    loc = "$" + "".join(f"[{p!r}]" if isinstance(p, int) else f".{p}" for p in err.absolute_path)
    return f"{loc}: {err.message}"


def request_errors(path, body):
    """Validate a request body against paths[path].post.requestBody (application/json)."""
    ref = _pointer("paths", path, "post", "requestBody", "content", "application/json", "schema")
    errs = sorted(_validator(ref).iter_errors(body), key=lambda e: list(e.absolute_path))
    return [_fmt(e) for e in errs]


def component(name):
    return SPEC["components"]["schemas"][name]


def component_errors(name, instance):
    errs = _validator(_pointer("components", "schemas", name)).iter_errors(instance)
    return [_fmt(e) for e in errs]


def matches_pattern(name, value):
    pattern = component(name)["pattern"]
    return value is not None and re.search(pattern, value) is not None


def doc_text(name):
    return (SPEC_DIR / "docs" / name).read_text(encoding="utf-8")


# Forward actions whose async callbacks are on_<action> (beckn.yaml paths).
ACTIONS = ["discover", "select", "init", "confirm", "status", "track",
           "update", "cancel", "rate", "support"]
assert all(has_path("/" + a) and has_path("/on_" + a) for a in ACTIONS)
