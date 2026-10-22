from prowl import assess, report
from prowl.scan.model import Host, ScanResult, Service


def _result():
    r = ScanResult(mode="deep", subnet="192.168.1.0/24", gateway="192.168.1.1")
    r.hosts = [
        Host(ip="192.168.1.1", is_gateway=True, device_class="router/switch", vendor="MikroTik",
             services=[Service(port=23, name="telnet", secure=False), Service(port=80, name="http", secure=False)]),
        Host(ip="192.168.1.50", device_class="printer", vendor="Brother",
             services=[Service(port=9100, name="jetdirect", secure=False)],
             default_creds=True, default_cred_detail={"service": "http", "port": 80,
                                                       "username": "admin", "password": "admin"}),
        Host(ip="192.168.1.60", device_class="host",
             services=[Service(port=5900, name="vnc", secure=False), Service(port=6379, name="redis", secure=False)],
             vulns=[{"severity": "critical", "title": "Unauthenticated Redis",
                     "evidence": "PING answered without AUTH on :6379",
                     "recommendation": "Require a password.", "category": "data-service"}]),
        Host(ip="192.168.1.70", device_class="host", services=[Service(port=22, name="ssh")]),  # clean
    ]
    return r.as_dict()


def test_findings_severity_and_order():
    d = _result()
    fl = assess.findings(d)
    # default creds on .50 is critical and must sort first
    assert fl[0]["severity"] == "critical" and fl[0]["ip"] == "192.168.1.50"
    titles = {(f["ip"], f["title"]) for f in fl}
    assert ("192.168.1.1", "Cleartext management (Telnet)") in titles
    assert ("192.168.1.60", "VNC exposed") in titles
    # the Redis finding now comes from the host's vuln probe (host.vulns), as critical
    assert ("192.168.1.60", "Unauthenticated Redis") in titles
    # a host with only SSH gets no finding
    assert not any(f["ip"] == "192.168.1.70" for f in fl)


def test_summary_counts():
    d = _result()
    fl = assess.findings(d)
    s = assess.summary(d, fl)
    assert s["counts"]["critical"] == 2   # default creds (.50) + unauthenticated Redis (.60)
    assert s["hosts_affected"] == 3
    assert s["default_cred_hosts"] == ["192.168.1.50"]


def test_assessment_html_renders():
    r = ScanResult(mode="deep", subnet="192.168.1.0/24", gateway="192.168.1.1")
    r.hosts = [Host(ip="192.168.1.50", device_class="printer", default_creds=True,
                    default_cred_detail={"service": "http", "port": 80, "username": "admin", "password": "admin"},
                    services=[Service(port=9100, name="jetdirect")])]
    out = report.to_assessment_html(r)
    assert "Network Security Assessment" in out
    assert "Accepts default credentials" in out
    assert "192.168.1.50" in out


def test_assessment_html_no_findings():
    r = ScanResult(mode="deep", subnet="10.0.0.0/24")
    r.hosts = [Host(ip="10.0.0.9", services=[Service(port=22, name="ssh")])]
    out = report.to_assessment_html(r)
    assert "No findings" in out
