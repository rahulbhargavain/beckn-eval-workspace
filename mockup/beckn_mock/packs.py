"""Domain schema packs: one directory per schema and version, as in beckn/schemas.

    <root>/schemas/<Type>/<vN.M>/{schema.json, context.jsonld, ...}
    <root>/external/*.json     upstream schemas we recognise but do not mirror (validation deferred)

schema.json is structural JSON Schema only. Mandatory fields and controlled vocabularies are a
network policy (policy.py), not part of the schema (docs/Schema_Design_Guide.md). Pack files are
untrusted data: parsed with json, never executed. The attributes `@context` is derived from the
schema's `$id`, so a context URL names exactly one schema directory.
"""
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator


class PackError(Exception):
    pass


def _fmt(err):
    loc = "".join(f"[{p!r}]" if isinstance(p, int) else f".{p}" for p in err.absolute_path)
    return f"{loc or '$'}: {err.message}"


def _vkey(version):
    return tuple(int(x) for x in version.lstrip("v").split("."))


class _Entry:
    def __init__(self, schema_json: Path):
        ver_dir = schema_json.parent
        self.type_name, self.version = ver_dir.parent.name, ver_dir.name
        if not re.fullmatch(r"v\d+\.\d+", self.version):
            raise PackError(f"{ver_dir}: version directory must look like v1.0")
        try:
            schema = json.loads(schema_json.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
        except (OSError, ValueError) as e:
            raise PackError(f"{schema_json}: unreadable schema ({e})") from None
        sid = schema.get("$id") if isinstance(schema, dict) else None
        if not isinstance(sid, str):
            raise PackError(f"{schema_json}: schema needs a string $id")
        if not sid.endswith(f"/schemas/{self.type_name}/{self.version}/schema.json"):
            raise PackError(f"{schema_json}: $id {sid!r} does not name its own directory")
        if not (ver_dir / "context.jsonld").is_file():
            raise PackError(f"{ver_dir}: context.jsonld is missing")
        self.context = sid.rsplit("/", 1)[0] + "/context.jsonld"
        self.validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


class PackRegistry:
    def __init__(self, entries, externals=(), strict=True):
        self.strict = strict
        self._by_context = {}
        self._externals = {}
        for e in entries:
            self._claim(e.context)
            self._by_context[e.context] = e
        for ctx, types in externals:
            self._claim(ctx)
            self._externals[ctx] = set(types)

    def _claim(self, ctx):
        if ctx in self._by_context or ctx in self._externals:
            raise PackError(f"context {ctx} is claimed twice")

    @classmethod
    def from_dir(cls, root, strict=True):
        root = Path(root)
        entries = [_Entry(p) for p in sorted((root / "schemas").glob("*/*/schema.json"))]
        externals = []
        for p in sorted((root / "external").glob("*.json")):
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
            except ValueError as e:
                raise PackError(f"{p}: not valid JSON ({e})") from None
            if (not isinstance(d, dict) or not isinstance(d.get("context"), str)
                    or not isinstance(d.get("types"), list) or d.get("validation") != "deferred"):
                raise PackError(f"{p}: needs context, types and validation=deferred")
            externals.append((d["context"], d["types"]))
        return cls(entries, externals, strict=strict)

    def type_names(self):
        return {e.type_name for e in self._by_context.values()}

    def deferred_contexts(self):
        return set(self._externals)

    def context_for(self, type_name, version=None):
        found = [e for e in self._by_context.values()
                 if e.type_name == type_name and (version is None or e.version == version)]
        if not found:
            raise KeyError(type_name)
        return max(found, key=lambda e: _vkey(e.version)).context

    def attribute_errors(self, attrs):
        """Structural errors for one Attributes container; [] when valid."""
        if not isinstance(attrs, dict):
            return ["attributes must be an object"]
        ctx, typ = attrs.get("@context"), attrs.get("@type")
        if not isinstance(ctx, str) or not isinstance(typ, str):
            return ["attributes need string @context and @type"]
        entry = self._by_context.get(ctx)
        if entry is not None:
            if typ != entry.type_name:
                return [f"@type {typ!r} does not match {entry.type_name!r} for this @context"]
            return [_fmt(e) for e in sorted(entry.validator.iter_errors(attrs), key=lambda e: list(e.absolute_path))]
        if ctx in self._externals:
            return [] if typ in self._externals[ctx] else [f"@type {typ!r} is not defined for external @context"]
        return [f"unknown @context {ctx!r}"] if self.strict else []
