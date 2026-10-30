"""Assemble the GitHub Pages site into <out>: the static viewer, the docs pages and
throwaway sample reports from the in-process mockup. Needs the spec under
vendor/protocol-specifications-v2 (or BECKN_SPEC_DIR) and the mockup requirements.

    python scripts/build_site.py site
"""
import base64
import html
import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT, ROOT / "mockup"):
    sys.path.insert(0, str(p))

import nacl.signing  # noqa: E402

from beckn_mock.network import MockNetwork  # noqa: E402
from conformance import runner  # noqa: E402

PROFILES = ("ds-core", "bpp-core")
PAGES = ("marketplace-summary.html", "cottonspace-capability.html")
PARTICIPANT = "sample-mockup-node"
SPEC_COMMIT = "a22300a"


def _sample_reports():
    """Run both profiles against a fresh mockup with throwaway keys. The keys are never written out."""
    op = nacl.signing.SigningKey.generate()
    issuer = {"key_id": "sample-operator/keys/1", "private_key_seed_b64": base64.b64encode(bytes(op)).decode()}
    scenarios = runner.load_scenarios(runner.DEFAULT_SCENARIOS)
    reports = {}
    with MockNetwork() as net:
        ident = net.new_identity("sample-harness.example", "BAP", net.bap_url)
        identity = {"key_id": ident.key_id, "bap_id": "sample-harness.example", "bap_uri": net.bap_url,
                    "network_id": net.network_id,
                    "private_key_seed_b64": base64.b64encode(bytes(ident.keypair.signing_key)).decode()}
        sut_keys = {net.bpp.identity.key_id: net.bpp.identity.keypair.public_b64}
        for name in PROFILES:
            prof = json.loads((ROOT / "conformance" / "profiles" / f"{name}.json").read_text(encoding="utf-8-sig"))
            reports[name] = runner.run(scenarios, prof, net.bpp_url, PARTICIPANT, identity=identity,
                                       issuer=issuer, sut_keys=sut_keys)
    return reports


def _index(reports):
    sha = os.environ.get("GITHUB_SHA", "")[:7] or "local build"
    rows = "".join(
        f"<tr><td>{html.escape(n)}</td><td>{html.escape(r['verdict'])}</td>"
        f"<td><a href=\"sample/{html.escape(n)}.report.json\">report.json</a></td></tr>"
        for n, r in reports.items())
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Beckn evaluation workspace</title>
<style>
  :root {{ --bg:#fff; --fg:#1b1f24; --muted:#59636e; --line:#d1d9e0; }}
  @media (prefers-color-scheme: dark) {{ :root {{ --bg:#0d1117; --fg:#e6edf3; --muted:#9198a1; --line:#30363d; }} }}
  body {{ margin:0; padding:16px; background:var(--bg); color:var(--fg); font:16px/1.5 system-ui, sans-serif;
         max-width:760px; margin-inline:auto; }}
  table {{ border-collapse:collapse; width:100%; }}
  th, td {{ text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); }}
  .note {{ border-left:4px solid var(--muted); padding:6px 12px; color:var(--muted); }}
  a {{ color:inherit; }}
</style>
</head>
<body>
<h1>Beckn evaluation workspace</h1>
<p>Test-first conformance harness and Python mockup for Beckn Protocol v2.0.0 server-to-server transactions.
Independent and unofficial; not affiliated with the Beckn or ONDC owners.</p>
<ul>
  <li><a href="viewer/index.html">Report viewer</a> (drop a report JSON on it; nothing is uploaded)</li>
  <li><a href="docs/marketplace-summary.html">Where the decentralised marketplace stands</a></li>
  <li><a href="docs/cottonspace-capability.html">Capability note</a></li>
  <li><a href="https://github.com/rahulbhargavain/beckn-eval-workspace">Source and licence (Apache-2.0)</a></li>
</ul>
<h2>Sample reports</h2>
<p class="note">These come from the repository's own mockup, run with throwaway keys at build time
(spec commit {SPEC_COMMIT}, build {html.escape(sha)}). They show the report format. They are not a certification of
any real node, and CERTIFIED here means only that the mockup passes this repository's pinned scenarios. The recommended
callback scenario CB-001 is not set up in this build, so it shows as a (non-blocking) failure in the ds-core sample.</p>
<table>
<tr><th>Profile</th><th>Verdict</th><th>File</th></tr>
{rows}
</table>
</body>
</html>
"""


def build(out):
    out = Path(out)
    if out.exists():
        shutil.rmtree(out)
    (out / "docs").mkdir(parents=True)
    (out / "sample").mkdir()
    shutil.copytree(ROOT / "viewer", out / "viewer", ignore=shutil.ignore_patterns("test"))
    for page in PAGES:
        shutil.copy(ROOT / "docs" / page, out / "docs" / page)
    reports = _sample_reports()
    for name, rep in reports.items():
        (out / "sample" / f"{name}.report.json").write_text(json.dumps(rep, indent=2), encoding="utf-8")
    (out / "index.html").write_text(_index(reports), encoding="utf-8")
    (out / ".nojekyll").write_text("", encoding="utf-8")
    return reports


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "site")
