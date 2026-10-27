"""Unknown / revoked participants and keyId resolution (NFH-007 §2)."""
import time

from beckn_mock import client
import payloads as P


def _discover(net, identity, **ctx):
    body = net.bap.envelope("discover", P.discover(), **ctx)
    return client.post_signed(net.bpp_url + "/discover", body, identity)


def test_unknown_key_rejected(net):
    """§2.3: lookup fails or returns no key -> 401."""
    ghost = net.new_identity("ghost.mock.local", role="BAP", url=net.bap_url, register=False)
    res = _discover(net, ghost, bapId="ghost.mock.local")
    assert res.status_code == 401
    assert res.json()["message"]["error"]["code"] in {"AUT_KEY_NOT_FOUND", "AUT_SUBSCRIBER_NOT_FOUND"}


def test_revoked_key_rejected(net):
    """Cross-cutting 'Key compromise': revocation MUST be checked at verification time;
    cached keys from revoked records MUST NOT be used."""
    assert _discover(net, net.bap.identity).status_code == 200  # warms any cache
    net.registry.revoke(net.bap.identity.key_id)
    res = _discover(net, net.bap.identity)
    assert res.status_code == 401
    assert res.json()["message"]["error"]["code"] == "AUT_KEY_EXPIRED_OR_REVOKED"


def test_expired_key_registration_rejected(net):
    net.registry.key(net.bap.identity.key_id)["validUntil"] = int(time.time()) - 1
    res = _discover(net, net.bap.identity)
    assert res.status_code == 401


def test_signer_registered_but_bapid_unregistered_rejected(net):
    """Valid key, but context.bapId names a subscriber the registry does not know."""
    res = _discover(net, net.bap.identity, bapId="not-registered.mock.local")
    assert res.status_code == 401


def test_explicit_keyid_to_trusted_registry_accepted(net):
    """§2.2 explicit format: https://{registry}/{ns}/{reg}/{record}|ed25519, resolved
    against that URL. Our registry is configured as trusted, so this must work."""
    ident = net.bap.identity.with_key_id(net.registry_url + "/" +
                                         net.bap.identity.key_id.split("|")[0] + "|ed25519")
    res = _discover(net, ident)
    assert res.status_code == 200, res.text


def test_explicit_keyid_to_untrusted_url_rejected_without_fetch(net):
    """§2.2 + CON-004-14: untrusted explicit registries MUST be rejected. Security
    assumption: the verifier must not even fetch the URL (it is attacker-controlled
    and fetched before authentication -> SSRF)."""
    canary_url, hits = net.start_canary()
    ident = net.bap.identity.with_key_id(canary_url + "/bap.mock.local/keys/k1|ed25519")
    res = _discover(net, ident)
    assert res.status_code == 401
    time.sleep(0.3)
    assert hits == []
