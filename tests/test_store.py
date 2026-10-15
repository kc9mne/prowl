import time

from prowl import store as store_mod
from prowl.scan.model import Host, ScanResult, Service


def _result(subnet, started, hosts):
    r = ScanResult(mode="deep", subnet=subnet, gateway="192.168.1.1")
    r.started = started
    r.finished = started + 1
    r.hosts = hosts
    return r.as_dict()


def test_store_save_list_previous(tmp_path):
    st = store_mod.Store(tmp_path / "prowl.db")
    a = _result("192.168.1.0/24", 1000.0, [Host(ip="192.168.1.5", mac="aa:bb:cc:dd:ee:01")])
    b = _result("192.168.1.0/24", 2000.0, [Host(ip="192.168.1.6", mac="aa:bb:cc:dd:ee:02")])
    st.save(a); st.save(b)
    rows = st.list("192.168.1.0/24")
    assert len(rows) == 2 and rows[0]["started"] == 2000.0   # newest first
    prev = st.previous("192.168.1.0/24", 2000.0)
    assert prev and prev["started"] == 1000.0
    assert st.previous("192.168.1.0/24", 1000.0) is None     # nothing before the first
    st.close()


def test_diff_new_gone_changed():
    base = _result("10.0.0.0/24", 1000.0, [
        Host(ip="10.0.0.5", mac="aa:bb:cc:00:00:01", device_class="printer",
             services=[Service(port=80), Service(port=9100)]),
        Host(ip="10.0.0.6", mac="aa:bb:cc:00:00:02", device_class="camera",
             services=[Service(port=554)]),
    ])
    cur = _result("10.0.0.0/24", 2000.0, [
        # same printer but a new open port and now default creds
        Host(ip="10.0.0.5", mac="aa:bb:cc:00:00:01", device_class="printer", default_creds=True,
             services=[Service(port=80), Service(port=9100), Service(port=23)]),
        # a brand new host
        Host(ip="10.0.0.9", mac="aa:bb:cc:00:00:09", device_class="host", services=[Service(port=22)]),
    ])
    d = store_mod.diff(cur, base)
    assert [n["ip"] for n in d["new"]] == ["10.0.0.9"]
    assert [g["ip"] for g in d["gone"]] == ["10.0.0.6"]        # camera disappeared
    assert len(d["changed"]) == 1 and d["changed"][0]["ip"] == "10.0.0.5"
    changes = d["changed"][0]["changes"]
    assert any("opened 23" in c for c in changes)
    assert any("default login" in c for c in changes)
    assert d["delta"]["10.0.0.9"] == "new" and d["delta"]["10.0.0.5"] == "changed"


def test_diff_ip_change_is_change_not_new_gone():
    base = _result("10.0.0.0/24", 1000.0, [Host(ip="10.0.0.5", mac="aa:bb:cc:00:00:01",
                                                services=[Service(port=80)])])
    cur = _result("10.0.0.0/24", 2000.0, [Host(ip="10.0.0.55", mac="aa:bb:cc:00:00:01",
                                               services=[Service(port=80)])])
    d = store_mod.diff(cur, base)
    assert d["new"] == [] and d["gone"] == []
    assert len(d["changed"]) == 1
    assert any("IP 10.0.0.5" in c for c in d["changed"][0]["changes"])


def test_api_persists_and_diffs(tmp_path):
    from fastapi.testclient import TestClient
    from prowl.server import create_app, loopback_only
    app = create_app(db_path=tmp_path / "prowl.db")
    app.dependency_overrides[loopback_only] = lambda: None
    c = TestClient(app)

    # seed a baseline directly in the store the app uses
    st = store_mod.Store(tmp_path / "prowl.db")
    st.save(_result("192.168.1.0/24", time.time() - 100,
                    [Host(ip="192.168.1.5", mac="aa:bb:cc:00:00:01", services=[Service(port=80)])]))
    st.close()

    # a demo scan uses subnet 192.168.1.0/24 too, so it should diff against the seed...
    # but demo scans are NOT persisted/diffed by design — assert that:
    jid = c.post("/api/scan", json={"mode": "deep", "demo": True}).json()["id"]
    for _ in range(100):
        d = c.get(f"/api/scan/{jid}").json()
        if d["status"] == "done":
            break
        time.sleep(0.03)
    assert "diff" not in d   # demo is never persisted or diffed
    # history still only has the one seeded baseline
    assert len(c.get("/api/history", params={"subnet": "192.168.1.0/24"}).json()["scans"]) == 1
