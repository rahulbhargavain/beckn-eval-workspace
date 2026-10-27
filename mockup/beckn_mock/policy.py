"""Network policy: which attributes a network requires and which value lists it enforces.

Kept apart from the schemas because the schema design guide makes every attribute optional by
default; mandatoriness is a per-network choice. Rules are keyed by `@type`. This is a small
stand-in for the Rego policy-as-code the guide mentions, not an implementation of it.
"""
import json
from pathlib import Path


class PolicyError(Exception):
    pass


class Policy:
    def __init__(self, name, rules):
        self.name = name
        self._rules = {}
        for r in rules:
            if not isinstance(r, dict) or not isinstance(r.get("type"), str):
                raise PolicyError("each rule needs a string 'type'")
            req, vocab = r.get("require", []), r.get("vocabulary", {})
            if not isinstance(req, list) or not all(isinstance(x, str) for x in req):
                raise PolicyError(f"{r['type']}: 'require' must be a list of field names")
            if not isinstance(vocab, dict) or not all(isinstance(v, list) for v in vocab.values()):
                raise PolicyError(f"{r['type']}: 'vocabulary' must map fields to lists")
            if r["type"] in self._rules:
                raise PolicyError(f"two rules for {r['type']}")
            self._rules[r["type"]] = (req, vocab)

    @classmethod
    def from_file(cls, path):
        try:
            d = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise PolicyError(f"{path}: unreadable ({e})") from None
        if not isinstance(d, dict) or not isinstance(d.get("rules"), list):
            raise PolicyError(f"{path}: needs a 'rules' list")
        return cls(str(d.get("name", Path(path).stem)), d["rules"])

    def attribute_errors(self, attrs):
        if not isinstance(attrs, dict):
            return []
        rule = self._rules.get(attrs.get("@type"))
        if rule is None:
            return []
        require, vocab = rule
        errs = [f"policy {self.name}: {attrs['@type']} requires {f!r}" for f in require if f not in attrs]
        for field, allowed in vocab.items():
            if field not in attrs:
                continue
            values = attrs[field] if isinstance(attrs[field], list) else [attrs[field]]
            for v in values:
                if v not in allowed:
                    errs.append(f"policy {self.name}: {field} {v!r} is not in the controlled vocabulary")
        return errs
