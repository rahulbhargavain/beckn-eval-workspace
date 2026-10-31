"""Write a throwaway ONIX BPP-receiver deployment: adapter config, routing, a registry file for the DeDi stub,
and two BAP identities for our runner (one with the spec's keyId shape, one with the keyId shape ONIX parses).
All keys are generated here and written under OUTDIR, which must not be committed."""
import base64
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "mockup"))
from beckn_mock import signing  # noqa: E402

BAP, BPP = "bap.example.com", "bpp.example.com"
BAP_KEY, BPP_KEY = "bap-key-1", "bpp-key-1"
DOMAIN = "beckn.one:deg:ev-charging:2.0.0"

CONFIG = """appName: "onix-eval"
log:
  level: debug
  destinations:
    - type: stdout
  contextKeys: [transaction_id, message_id, subscriber_id, module_id]
http:
  port: 8082
  timeout: {{read: 30, write: 30, idle: 30}}
pluginManager:
  root: {plugins}
modules:
  - name: bppTxnReceiver
    path: /bpp/receiver/
    handler:
      type: std
      role: bpp
      httpClientConfig: {{maxIdleConns: 100, maxIdleConnsPerHost: 20, idleConnTimeout: 60s, responseHeaderTimeout: 5s}}
      plugins:
        registry:
          id: dediregistry
          config: {{timeout: 10, retry_max: 1, retry_wait_min: 100ms, retry_wait_max: 200ms}}
        keyManager:
          id: simplekeymanager
          config:
            subscriberId: {bpp}
            keyId: {bpp_key}
            signingPrivateKey: {seed}
            signingPublicKey: {pub}
            encrPrivateKey: {seed}
            encrPublicKey: {pub}
        cache:
          id: cache
          config: {{addr: "127.0.0.1:6379"}}
        signValidator: {{id: signvalidator}}
        signer: {{id: signer}}
        router:
          id: router
          config: {{routingConfig: {routing}}}
        middleware:
          - id: reqpreprocessor
            config: {{contextKeys: "transaction_id,message_id", role: bpp}}
      steps: [validateSign, addRoute, signAck]
"""

ROUTING = """routingRules:
  - domain: "{domain}"
    version: "2.0.0"
    targetType: "url"
    target:
      url: "http://127.0.0.1:3031/api/webhook"
    endpoints: [select, init, confirm, status, track, cancel, update, rating, support, discover]
"""


def keypair(seed):
    kp = signing.Keypair(signing.nacl.signing.SigningKey(seed))
    return base64.b64encode(seed).decode(), kp.public_b64


def main(out, onix_dir, rt=None):
    rt = rt or str(out)  # where the adapter will see OUTDIR (it may run in WSL or a container)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    bpp_seed, bpp_pub = keypair(os.urandom(32))
    bap_seed, bap_pub = keypair(os.urandom(32))
    (out / "config.yaml").write_text(CONFIG.format(plugins=f"{onix_dir}/plugins", bpp=BPP, bpp_key=BPP_KEY,
                                                   seed=bpp_seed, pub=bpp_pub, routing=f"{rt}/routing.yaml"))
    (out / "routing.yaml").write_text(ROUTING.format(domain=DOMAIN))
    rec = lambda sub, pub, url: {"data": {"details": {"subscriber_id": sub, "url": url, "type": "BAP",  # noqa: E731
                                                       "domain": DOMAIN, "signing_public_key": pub,
                                                       "encr_public_key": pub},
                                          "network_memberships": ["eval.example.org"],
                                          "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"}}
    (out / "registry.json").write_text(json.dumps({BAP: {BAP_KEY: rec(BAP, bap_pub, "http://127.0.0.1:9")},
                                                    BPP: {BPP_KEY: rec(BPP, bpp_pub, "http://127.0.0.1:8082")}}, indent=2))
    base = {"bap_id": BAP, "bap_uri": "http://127.0.0.1:9", "network_id": "eval.example.org",
            "private_key_seed_b64": bap_seed}
    # the spec's shape: {namespace}/{registry}/{record}|ed25519
    (out / "identity-spec.json").write_text(json.dumps({**base, "key_id": f"{BAP}/dedi/{BAP_KEY}|ed25519"}, indent=2))
    # the shape ONIX parses: subscriber|uniqueKeyId|ed25519
    (out / "identity-onix.json").write_text(json.dumps({**base, "key_id": f"{BAP}|{BAP_KEY}|ed25519"}, indent=2))
    # key that signs the runner's report; throwaway, only so the runner can produce one
    (out / "issuer.json").write_text(json.dumps({"key_id": "eval-operator-throwaway",
                                                  "private_key_seed_b64": base64.b64encode(os.urandom(32)).decode()}))
    print(f"wrote {out}")


if __name__ == "__main__":
    main(*sys.argv[1:4])
