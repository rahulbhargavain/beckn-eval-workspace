"""Exercise a running ONIX deployment (see start.sh) and compare the outcomes to baseline.json.
usage: check.py OUTDIR BASE_URL [--write-baseline FILE | --baseline FILE]
Records: the status and error code for four signed requests that differ only in keyId shape and digest prefix,
whether the backend saw each, and the per-scenario results of the bpp-core profile run with the runner
(runner talks loopback only, so BASE_URL must be loopback)."""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
VARIANTS = ["onix", "onix+spec", "spec+onix", "spec"]


def backend_hits(out):
    p = Path(out) / "backend.log"
    return len(p.read_text().splitlines()) if p.exists() else 0


def collect(out, base):
    res = {}
    for v in VARIANTS:
        before = backend_hits(out)
        code, doc, h = probe.send(out, v, base)
        err = ((doc or {}).get("message") or {}).get("error") or {}
        res[f"probe {v}"] = f"{code} {err.get('code', 'ACK' if code == 200 else '-')}; " \
                            f"backend {'reached' if backend_hits(out) > before else 'not reached'}; " \
                            f"signed reply {'yes' if h.get('Signature') else 'no'}"
    for shape in ("onix", "spec"):
        rep = Path(out) / f"report-{shape}.json"
        subprocess.run([sys.executable, "-m", "conformance.runner", "--base-url", base + "/bpp/receiver",
                        "--profile", "conformance/profiles/bpp-core.json", "--participant", "onix-eval",
                        "--identity", str(Path(out) / f"identity-{shape}.json"),
                        "--issuer-key", str(Path(out) / "issuer.json"), "--out", str(rep)],
                       cwd=ROOT, check=False, capture_output=True)
        r = json.loads(rep.read_text())
        res[f"runner identity={shape} verdict"] = r["verdict"]
        for x in r["results"]:
            res[f"runner identity={shape} {x['id']}"] = "PASS" if x.get("passed") else "FAIL: " + str(x.get("detail", ""))[:90]
    return res


if __name__ == "__main__":
    out, base = sys.argv[1], sys.argv[2]
    res = collect(out, base)
    for k, v in res.items():
        print(f"{k}: {v}")
    if "--write-baseline" in sys.argv:
        Path(sys.argv[sys.argv.index("--write-baseline") + 1]).write_text(json.dumps(res, indent=2, sort_keys=True) + "\n")
    if "--baseline" in sys.argv:
        want = json.loads(Path(sys.argv[sys.argv.index("--baseline") + 1]).read_text())
        diff = [f"{k}: expected {want.get(k)!r}, got {res.get(k)!r}" for k in sorted(set(want) | set(res)) if want.get(k) != res.get(k)]
        print("\n".join("BASELINE CHANGED " + d for d in diff))
        sys.exit(1 if diff else 0)
