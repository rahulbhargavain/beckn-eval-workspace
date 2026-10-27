"""In-process mock Beckn network: registry + BPP (with co-hosted DS) + BAP."""
import time
import uuid

from . import registry, signing
from .bap import BapNode
from .bpp import DEFAULT_CATALOG, BppNode
from .node import Identity
from .server import ServerThread

NETWORK_ID = "mock.local/test-net"
_DEFAULT = object()


class MockNetwork:
    def __init__(self, callback_allowlist=_DEFAULT, catalog_path=DEFAULT_CATALOG, store=None):
        self.store = store
        self._allowlist_arg = callback_allowlist
        self.catalog_path = catalog_path
        self.network_id = NETWORK_ID
        self._servers = []
        self.last_transaction_id = None

    # ------------------------------------------------------------ lifecycle
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def start(self):
        reg_srv, bap_srv, bpp_srv = ServerThread(), ServerThread(), ServerThread()
        self.registry_url, self.bap_url, self.bpp_url = reg_srv.url, bap_srv.url, bpp_srv.url
        self.registry = registry.RegistryState()
        bap_id = self._identity("bap.mock.local", "BAP", self.bap_url)
        bpp_id = self._identity("bpp.mock.local", "BPP", self.bpp_url)
        allow = [self.bap_url] if self._allowlist_arg is _DEFAULT else self._allowlist_arg
        trusted = [self.registry_url]
        self.bpp = BppNode(bpp_id, self.registry_url, NETWORK_ID, trusted, callback_allowlist=allow,
                           catalog_path=self.catalog_path, store=self.store)
        self.bap = BapNode(bap_id, self.registry_url, NETWORK_ID, trusted, default_bpp_id=bpp_id.subscriber_id,
                           bpp_allowlist=[self.bpp_url])
        for srv, app in ((reg_srv, registry.create_app(self.registry)), (bap_srv, self.bap.app),
                         (bpp_srv, self.bpp.app)):
            self._servers.append(srv.start(app))

    def stop(self):
        for srv in reversed(self._servers):
            srv.stop()
        self._servers.clear()
        for node in (getattr(self, "bap", None), getattr(self, "bpp", None)):
            if node:
                node.close()

    # ------------------------------------------------------------ identities
    def _identity(self, subscriber_id, role, url, register=True):
        ident = Identity(subscriber_id, f"{subscriber_id}/keys/k1|ed25519", signing.Keypair.generate(), url, role)
        if register:
            now = int(time.time())
            self.registry.add_subscriber(subscriber_id, NETWORK_ID, url, role)
            self.registry.add_key(ident.key_id, subscriber_id, NETWORK_ID, ident.keypair.public_b64,
                                  now - 60, now + 365 * 86400)
        return ident

    def new_identity(self, subscriber_id, role="BAP", url="https://unused.invalid", register=True):
        return self._identity(subscriber_id, role, url, register)

    def start_canary(self):
        """A server that records every request it receives (to prove nothing was fetched)."""
        hits = []

        async def app(scope, receive, send):
            if scope["type"] != "http":
                return
            hits.append(scope["path"])
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"{}"})
        srv = ServerThread()
        self._servers.append(srv.start(app))
        return srv.url, hits

    # ------------------------------------------------------------ flows
    def draft_contract_after_init(self):
        from . import flows
        return flows.until_init(self)

    def confirmed_contract(self):
        from . import flows
        return flows.until_confirm(self)
