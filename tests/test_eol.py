from prowl.scan import eol
from prowl.scan.model import Host, Service


def test_windows_build_eol_high():
    h = Host(ip="10.0.0.5", services=[Service(port=445, name="smb",
                                              banner="SMB WIN7BOX / CORP  OS 6.1 build 7601")])
    f = eol.check(h)
    assert any(x["severity"] == "high" and "Unsupported Windows" in x["title"] for x in f)


def test_windows_current_build_no_finding():
    h = Host(ip="10.0.0.6", services=[Service(port=445, name="smb",
                                              banner="SMB PC / WG  OS 10.0 build 19045")])
    assert eol.check(h) == []


def test_server_2019_build_not_flagged():
    # build 17763 is Server 2019 (still supported) — must not be flagged EOL
    h = Host(ip="10.0.0.7", services=[Service(port=445, name="smb", banner="OS 10.0 build 17763")])
    assert eol.check(h) == []


def test_banner_eol_software():
    h = Host(ip="10.0.0.8", services=[Service(port=80, name="http", banner="Apache/2.2.15 (CentOS)")])
    f = eol.check(h)
    assert any("End-of-life software" in x["title"] for x in f)


def test_old_openssh():
    h = Host(ip="10.0.0.9", services=[Service(port=22, name="ssh", banner="SSH-2.0-OpenSSH_6.6.1")])
    f = eol.check(h)
    assert any("OpenSSH" in x["title"] for x in f)


def test_unknown_banner_no_false_positive():
    h = Host(ip="10.0.0.10", services=[Service(port=22, name="ssh", banner="SSH-2.0-OpenSSH_9.6")])
    assert eol.check(h) == []
