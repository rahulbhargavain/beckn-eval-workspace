"""scripts/build_site.py assembles the GitHub Pages site: the static viewer, the docs
pages and a throwaway sample report from the mockup. The sample report is a demo of
the report format, not a certification of anything."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import build_site  # noqa: E402


def test_site_has_pages_and_no_secrets(tmp_path):
    build_site.build(tmp_path)
    for rel in ("index.html", "viewer/index.html", "viewer/app.js", "viewer/render.js",
                "docs/marketplace-summary.html", "docs/cottonspace-capability.html",
                "sample/ds-core.report.json", "sample/bpp-core.report.json", ".nojekyll"):
        assert (tmp_path / rel).is_file(), rel
    blob = "\n".join(p.read_text(encoding="utf-8") for p in tmp_path.rglob("*") if p.is_file())
    assert "private_key_seed" not in blob
    assert "security.md" not in blob and "evaluation.md" not in blob


def test_sample_reports_are_genuine_and_labelled(tmp_path):
    from conformance import runner
    build_site.build(tmp_path)
    for name in ("ds-core", "bpp-core"):
        rep = json.loads((tmp_path / "sample" / f"{name}.report.json").read_text(encoding="utf-8"))
        assert rep["verdict"] == "CERTIFIED"
        assert rep["participant"] == "sample-mockup-node"
        assert rep["issuer_key_id"].startswith("sample-operator")
    index = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "not a certification" in index.lower()
    assert runner  # imported via build_site's sys.path setup
