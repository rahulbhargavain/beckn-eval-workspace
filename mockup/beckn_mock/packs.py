"""Domain schema packs: a directory holding pack.json plus JSON Schema files, one per @type.

A pack is data, not code. Adding a domain means adding a directory under packs/ (see
docs/Schema_Design_Guide.md: an Attributes container carries @context + @type that resolve to a
published schema artifact). Pack files are untrusted data: parsed with json, never executed, and
schema paths may not leave the pack directory.
"""
import json
from pathlib import Path

from jsonschema import Draft202012Validator


class PackError(Exception):
    pass


def _fmt(err):
    loc = "".join(f"[{p!r}]" if isinstance(p, int) else f".{p}" for p in err.absolute_path)
    return f"{loc or '$'}: {err.message}"


class Pack:
    def __init__(self, directory: Path):
        self.dir = directory.resolve()
        try:
            m = json.loads((self.dir / "pack.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise PackError(f"{directory}: unreadable pack.json ({e})") from None
        for key in ("name", "version", "context", "types"):
            if key not in m:
                raise PackError(f"{directory}: pack.json lacks '{key}'")
        if not isinstance(m["types"], dict) or not m["types"]:
            raise PackError(f"{directory}: 'types' must be a non-empty object")
        self.name, self.version, self.context = m["name"], m["version"], m["context"]
        self.status = m.get("status", "experimental")
        self.validators = {}
        for type_name, rel in m["types"].items():
            path = (self.dir / rel).resolve()
            if self.dir not in path.parents:
                raise PackError(f"{self.name}: schema path {rel!r} leaves the pack directory")
            try:
                schema = json.loads(path.read_text(encoding="utf-8"))
                Draft202012Validator.check_schema(schema)
            except (OSError, ValueError) as e:
                raise PackError(f"{self.name}: bad schema {rel!r} ({e})") from None
            self.validators[type_name] = Draft202012Validator(
                schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


class PackRegistry:
    def __init__(self, packs, strict=True):
        self.strict = strict
        self._by_context = {}
        self._by_name = {}
        for p in packs:
            if p.context in self._by_context:
                raise PackError(f"context {p.context} is claimed by two packs")
            self._by_context[p.context] = p
            self._by_name[p.name] = p

    @classmethod
    def from_dir(cls, root, strict=True):
        root = Path(root)
        return cls([Pack(d) for d in sorted(root.iterdir()) if (d / "pack.json").exists()], strict=strict)

    def names(self):
        return sorted(self._by_name)

    def pack(self, name):
        return self._by_name[name]

    def attribute_errors(self, attrs):
        """Errors for one Attributes container; [] when valid."""
        if not isinstance(attrs, dict):
            return ["attributes must be an object"]
        ctx, typ = attrs.get("@context"), attrs.get("@type")
        if not isinstance(ctx, str) or not isinstance(typ, str):
            return ["attributes need string @context and @type"]
        pack = self._by_context.get(ctx)
        if pack is None:
            return [f"unknown @context {ctx!r}"] if self.strict else []
        validator = pack.validators.get(typ)
        if validator is None:
            return [f"@type {typ!r} is not defined in pack {pack.name}"]
        return [_fmt(e) for e in sorted(validator.iter_errors(attrs), key=lambda e: list(e.absolute_path))]
