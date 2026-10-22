import asyncio
import base64

import pytest

from prowl.scan import creds
from prowl.scan.model import Host, Service
from prowl.scan.scanner import ScanManager


def test_mask():
    assert creds.mask("") == "(blank)"
    assert creds.mask("a") == "a*"
    assert creds.mask("admin") == "a****"


def test_candidates_caps_two_passwords_per_user():
    h = Host(ip="10.0.0.9", vendor="Netgear", device_class="router")
    cands = dict(creds.candidates(h))
    for user, pws in cands.items():
        assert len(pws) <= creds.MAX_PW_PER_USER, f"{user} exceeds the lockout cap"
    assert len(cands) <= creds.MAX_USERS_PER_HOST
    assert "admin" in cands  # generic + netgear + router all contribute admin


def test_candidates_vendor_and_class_matched():
    cam = Host(ip="10.0.0.7", vendor="Hangzhou Hikvision", device_class="camera")
    cands = dict(creds.candidates(cam))
    # hikvision default admin/12345 should be among admin's (deduped, capped) passwords
    assert "12345" in cands.get("admin", [])


def test_targets_picks_one_web_then_telnet_ssh():
    h = Host(ip="10.0.0.5", services=[Service(port=8080, name="http-alt"),
                                      Service(port=22, name="ssh"), Service(port=23, name="telnet")])
    t = creds._targets(h)
    methods = [m for m, _, _ in t]
    assert methods[0] == "http"
    assert "ssh" in methods and "telnet" in methods


def test_ssh_try_handles_unreachable():
    # closed port -> None (never raises), paramiko present or not
    assert creds._ssh_try("127.0.0.1", 1, "x", "y", 0.4) is None


# ---- HTTP Basic path against a real local server -------------------------------------

async def _basic_server(user, pw):
    good = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()

    async def handle(reader, writer):
        data = await asyncio.wait_for(reader.read(1024), timeout=2)
        text = data.decode("latin-1")
        if good in text:
            resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        else:
            resp = (b"HTTP/1.1 401 Unauthorized\r\n"
                    b'WWW-Authenticate: Basic realm="dev"\r\nConnection: close\r\n\r\n')
        writer.write(resp)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


def test_http_basic_detection_and_confirmation():
    async def go():
        server, port = await _basic_server("admin", "admin")
        async with server:
            assert await creds._http_basic_realm("127.0.0.1", port, False, 2.0) is True
            assert await creds._http_basic_try("127.0.0.1", port, False, "admin", "wrong", 2.0) is False
            assert await creds._http_basic_try("127.0.0.1", port, False, "admin", "admin", 2.0) is True
    asyncio.run(go())


def test_demo_cred_check_flags_camera_and_printer():
    async def go():
        job = ScanManager().start(mode="deep", subnet=None, demo=True,
                                  deep_opts={"check_default_creds": True})
        while job.status in ("queued", "running"):
            await asyncio.sleep(0.05)
        return job
    job = asyncio.run(go())
    flagged = {h.ip: h.default_cred_detail for h in job.result.hosts if h.default_creds}
    assert "192.168.1.77" in flagged and "192.168.1.50" in flagged
    assert flagged["192.168.1.50"]["username"] == "admin"
    # every host with services should be marked as checked
    assert all(h.cred_checked for h in job.result.hosts if h.services)


# ---- authorization gate at the API ---------------------------------------------------

def test_authorization_gate():
    from fastapi.testclient import TestClient
    from prowl.server import create_app, loopback_only
    app = create_app()
    app.dependency_overrides[loopback_only] = lambda: None  # bypass the loopback check in-process
    c = TestClient(app)
    # cred scan without authorization -> 403
    r = c.post("/api/scan", json={"mode": "deep", "demo": True, "deep_opts": {"check_default_creds": True}})
    assert r.status_code == 403
    # authorize, then it is allowed
    assert c.post("/api/authorize", json={"ack": True}).json()["authorized"] is True
    r2 = c.post("/api/scan", json={"mode": "deep", "demo": True, "deep_opts": {"check_default_creds": True}})
    assert r2.status_code == 200
    # acknowledgement is required
    app2 = create_app()
    app2.dependency_overrides[loopback_only] = lambda: None
    assert TestClient(app2).post("/api/authorize", json={"ack": False}).status_code == 400


# ---- importing an external default-credentials database --------------------------------

def test_parse_cred_export_csv_and_json():
    csv_text = ("vendor,product,username,password\n"
                "Acme,Router 1,admin,admin\n"
                "Acme,Router 1,admin,password\n"
                "Globex,Cam,root,\n")      # blank password kept
    rows = creds.parse_cred_export(csv_text)
    assert ("Acme", "admin", "admin") in rows
    assert ("Globex", "root", "") in rows

    json_text = '[{"manufacturer":"Initech","user":"super","pass":"1234"}]'
    assert creds.parse_cred_export(json_text) == [("Initech", "super", "1234")]

    # combined credentials column
    combo = "vendor,credentials\nFoo,admin/secret\n"
    assert creds.parse_cred_export(combo) == [("Foo", "admin", "secret")]


def test_import_and_candidates_use_imported_db(tmp_path, monkeypatch):
    monkeypatch.setattr(creds, "user_db_path", lambda: tmp_path / "creds-user.json")
    creds._user_db.cache_clear()
    res = creds.import_from_text(
        "vendor,username,password\nTenda,admin,tenda1234\nTenda,admin,admin\nTenda,root,root\n")
    assert res["vendors"] == 1 and res["entries"] == 3
    creds._user_db.cache_clear()

    h = Host(ip="10.0.0.5", vendor="Tenda Technology", device_class="router")
    cands = dict(creds.candidates(h))
    # imported admin passwords should appear, still capped to two per username
    assert "admin" in cands and len(cands["admin"]) <= creds.MAX_PW_PER_USER
    assert "tenda1234" in cands["admin"]   # imported vendor default present


def test_import_rejects_empty():
    import pytest
    with pytest.raises(ValueError):
        creds.import_from_text("just,some\nrandom,text\n")
