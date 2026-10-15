import asyncio
import ipaddress

from prowl.scan import net, oui
from prowl.scan.model import Host, ScanResult, Service
from prowl.scan.scanner import ScanManager
from prowl import report


def test_norm_mac():
    assert net.norm_mac("4C:5E:0C:11:22:33") == "4c:5e:0c:11:22:33"
    assert net.norm_mac("4c5e0c-112233") == "4c:5e:0c:11:22:33"
    assert net.norm_mac("ff:ff:ff:ff:ff:ff") is None
    assert net.norm_mac("not a mac") is None
    assert net.norm_mac(None) is None


def test_oui_lookup_known_and_random():
    assert oui.lookup("4c:5e:0c:11:22:33") == "MikroTik"
    assert oui.lookup("b8:27:eb:de:ad:01") == "Raspberry Pi Foundation"
    # locally-administered bit set -> randomized marker
    assert "randomized" in (oui.lookup("02:11:22:33:44:55") or "")
    assert oui.lookup(None) is None


def test_host_sort_key_and_serialization():
    h = Host(ip="192.168.1.10", mac="4c:5e:0c:11:22:33", services=[Service(port=80, name="http")])
    d = h.as_dict()
    assert d["ip"] == "192.168.1.10"
    assert d["services"][0]["port"] == 80
    assert h.ip_sort_key == (192, 168, 1, 10)


def test_scanresult_sorts_hosts():
    r = ScanResult(mode="discovery", subnet="192.168.1.0/24")
    r.hosts = [Host(ip="192.168.1.20"), Host(ip="192.168.1.3")]
    ips = [h["ip"] for h in r.as_dict()["hosts"]]
    assert ips == ["192.168.1.3", "192.168.1.20"]


def test_demo_scan_end_to_end():
    async def go():
        mgr = ScanManager()
        job = mgr.start(mode="deep", subnet=None, demo=True)
        while job.status in ("queued", "running"):
            await asyncio.sleep(0.05)
        return job
    job = asyncio.run(go())
    assert job.status == "done"
    assert len(job.result.hosts) == 8
    gw = [h for h in job.result.hosts if h.is_gateway]
    assert gw and gw[0].ip == "192.168.1.1"
    printer = [h for h in job.result.hosts if h.device_class == "printer"]
    assert printer, "expected the demo printer to be classified"


def test_reports_render():
    mgr = ScanManager()
    r = ScanResult(mode="discovery", subnet="10.0.0.0/24", gateway="10.0.0.1")
    r.hosts = [Host(ip="10.0.0.5", mac="4c:5e:0c:00:00:01", vendor="MikroTik",
                    services=[Service(port=22, name="ssh")])]
    assert "10.0.0.5" in report.to_csv(r)
    assert "10.0.0.5" in report.to_html(r)
    assert '"ip": "10.0.0.5"' in report.to_json(r)


def test_large_subnet_refused():
    async def go():
        mgr = ScanManager()
        job = mgr.start(mode="discovery", subnet="10.0.0.0/8")
        while job.status in ("queued", "running"):
            await asyncio.sleep(0.05)
        return job
    job = asyncio.run(go())
    assert job.status == "error"
    assert "allow_large" in (job.error or "")
