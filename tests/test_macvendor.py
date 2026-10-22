import asyncio
import json

from prowl.scan import macvendor
from prowl.scan.model import Host


def test_parse_found_and_not_found():
    ok = json.dumps({"success": True, "found": True, "macPrefix": "04:D5:90",
                     "company": "ASUSTek COMPUTER INC."}).encode()
    assert macvendor._parse(ok) == "ASUSTek COMPUTER INC."
    miss = json.dumps({"success": True, "found": False, "company": ""}).encode()
    assert macvendor._parse(miss) is None
    assert macvendor._parse(b"not json") is None
    assert macvendor._parse(b"[]") is None


def test_enrich_hosts_fills_and_persists(monkeypatch):
    monkeypatch.setattr(macvendor, "FREE_DELAY", 0)
    # fake the network: resolve one prefix, leave another unknown
    def fake_fetch(prefix, timeout, api_key):
        return {"AABBCC": "Acme Networks"}.get(prefix)   # None for unknown
    monkeypatch.setattr(macvendor, "_fetch", fake_fetch)
    persisted = {}
    monkeypatch.setattr(macvendor.oui, "add_user_entries", lambda m: persisted.update(m) or len(m))

    hosts = [
        Host(ip="10.0.0.1", mac="aa:bb:cc:11:22:33"),              # unknown -> resolved
        Host(ip="10.0.0.2", mac="de:ad:be:00:00:00"),              # unknown -> stays None
        Host(ip="10.0.0.3", mac="aa:bb:cc:44:55:66", vendor="X"),  # already known -> skipped
        Host(ip="10.0.0.4"),                                       # no mac -> skipped
    ]
    n = asyncio.run(macvendor.enrich_hosts(hosts, timeout=1.0))
    assert n == 1
    assert hosts[0].vendor == "Acme Networks"
    assert hosts[1].vendor is None
    assert hosts[2].vendor == "X"
    assert persisted == {"AABBCC": "Acme Networks"}


def test_enrich_stops_on_rate_limit(monkeypatch):
    monkeypatch.setattr(macvendor, "FREE_DELAY", 0)
    calls = []
    def fake_fetch(prefix, timeout, api_key):
        calls.append(prefix)
        return False   # throttled immediately
    monkeypatch.setattr(macvendor, "_fetch", fake_fetch)
    got = macvendor._enrich_blocking(["AAAAAA", "BBBBBB", "CCCCCC"], 1.0, None)
    assert got == {} and calls == ["AAAAAA"]   # stopped after the first 429


def test_enrich_noop_when_nothing_unknown():
    hosts = [Host(ip="10.0.0.1", mac="aa:bb:cc:11:22:33", vendor="Known")]
    assert asyncio.run(macvendor.enrich_hosts(hosts)) == 0
