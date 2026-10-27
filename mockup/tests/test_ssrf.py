"""Callback-URL SSRF guard.

Spec basis: beckn.yaml Context.bapUri "MUST match the subscriber_url returned by the
subnet registry lookup". The spec is silent on private-address filtering, scheme
restrictions, redirects and DNS rebinding; those rules are mockup assumptions,
documented per test.
"""
import time

import pytest

from beckn_mock import client, urlguard
import payloads as P


def _discover_as(net, identity, **ctx):
    body = net.bap.envelope("discover", P.discover(), **ctx)
    body["context"]["bapId"] = identity.subscriber_id
    if "bapUri" not in ctx:
        body["context"]["bapUri"] = identity.url
    return client.post_signed(net.bpp_url + "/discover", body, identity)


def test_bap_uri_not_matching_registry_rejected(net):
    """bapUri differs from the registered subscriber_url -> NACK, nothing is called."""
    canary_url, hits = net.start_canary()
    res = _discover_as(net, net.bap.identity, bapUri=canary_url)
    assert res.status_code == 400
    assert res.json()["message"]["error"]["code"] == "CTX_INVALID_FIELD"
    time.sleep(0.5)
    assert hits == []


def test_registered_but_not_allowlisted_callback_rejected(net):
    """Assumption: in allowlist mode only configured origins may receive callbacks, even
    if the registry vouches for the URL (registry entries are self-declared)."""
    canary_url, hits = net.start_canary()
    evil = net.new_identity("evil-bap.mock.local", role="BAP", url=canary_url)
    res = _discover_as(net, evil)
    assert res.status_code == 400
    time.sleep(0.5)
    assert hits == []


@pytest.mark.parametrize("url", [
    "http://10.0.0.1:8080/cb",
    "http://169.254.169.254/latest/meta-data",
    "http://[::1]:9/cb",
    "http://localhost:9/cb",
    "http://2130706433/cb",            # decimal form of 127.0.0.1
    "http://[::ffff:127.0.0.1]:9/cb",  # IPv4-mapped IPv6
    "http://0.0.0.0:9/cb",
])
def test_private_callback_targets_rejected_in_open_mode(open_net, url):
    """Assumption: with no allowlist, callbacks to loopback/private/link-local/reserved
    addresses are refused (after DNS resolution)."""
    evil = open_net.new_identity("evil-bap.mock.local", role="BAP", url=url)
    res = _discover_as(open_net, evil)
    assert res.status_code == 400, res.text
    assert res.json()["message"]["error"]["code"] == "CTX_INVALID_FIELD"


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "gopher://127.0.0.1:25/",
    "ftp://example.org/",
    "http://user:pw@public.example/",
    "http:///nohost",
    "http://public.example:0/",
])
def test_urlguard_rejects_bad_schemes_and_shapes(url):
    with pytest.raises(urlguard.UnsafeURL):
        urlguard.check_url(url, allowlist=None, resolver=lambda h: ["93.184.216.34"])


def test_urlguard_open_mode_allows_public_and_blocks_rebinding_names():
    urlguard.check_url("https://public.example/cb", allowlist=None, resolver=lambda h: ["93.184.216.34"])
    with pytest.raises(urlguard.UnsafeURL):  # any resolved address private -> reject
        urlguard.check_url("https://rebind.example/cb", allowlist=None,
                           resolver=lambda h: ["93.184.216.34", "127.0.0.1"])


def test_urlguard_allowlist_mode_is_exact_origin():
    allow = ["http://127.0.0.1:8000"]
    urlguard.check_url("http://127.0.0.1:8000/on_select", allowlist=allow)
    for bad in ["http://127.0.0.1:8001/x", "https://127.0.0.1:8000/x", "http://127.0.0.1.evil.example:8000/"]:
        with pytest.raises(urlguard.UnsafeURL):
            urlguard.check_url(bad, allowlist=allow, resolver=lambda h: ["93.184.216.34"])


def test_bap_does_not_trust_bpp_uri_from_catalog(net):
    """on_discover catalogs carry bppId/bppUri chosen by the DS. Assumption: the CN
    resolves the PN address from the registry and refuses a catalog whose bppUri
    disagrees, instead of POSTing to whatever the catalog says."""
    canary_url, hits = net.start_canary()
    r = net.bap.send("discover", P.discover())
    catalog = dict(net.bap.wait_callback(r.message_id)["message"]["catalogs"][0], bppUri=canary_url)
    with pytest.raises(urlguard.UnsafeURL):
        net.bap.bpp_from_catalog(catalog)
    assert hits == []


def test_callback_redirects_not_followed(net):
    """Assumption: callback delivery never follows HTTP redirects (a 30x from an
    allowlisted host could otherwise bounce the BPP to an internal address)."""
    assert net.bpp.http_follows_redirects is False
