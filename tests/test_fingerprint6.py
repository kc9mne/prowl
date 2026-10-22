import asyncio
import socket
import struct
import threading

from prowl.scan import classify, oui, smb, snmp, ssdp
from prowl.scan.model import Host, Service


# ---- SNMP ----------------------------------------------------------------------------

def _snmp_response(community, sysdescr, sysname, req_id=1):
    vb1 = snmp._tlv(0x30, snmp._oid(snmp.SYS_DESCR) + snmp._tlv(0x04, sysdescr.encode()))
    vb2 = snmp._tlv(0x30, snmp._oid(snmp.SYS_NAME) + snmp._tlv(0x04, sysname.encode()))
    pdu = snmp._tlv(0xA2, snmp._int(req_id) + snmp._int(0) + snmp._int(0) + snmp._tlv(0x30, vb1 + vb2))
    msg = snmp._int(1) + snmp._tlv(0x04, community.encode()) + pdu
    return snmp._tlv(0x30, msg)


def test_snmp_parse_roundtrip():
    resp = _snmp_response("public", "Cisco IOS Software, C2960", "sw-core")
    vals = snmp._parse(resp)
    assert vals["0"] == "Cisco IOS Software, C2960"
    assert vals["1"] == "sw-core"


def test_snmp_probe_against_local_agent():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    resp = _snmp_response("public", "MikroTik RouterOS 7.11 (RB750)", "gw")

    def serve():
        srv.settimeout(3)
        try:
            _, addr = srv.recvfrom(4096)
            srv.sendto(resp, addr)
        except socket.timeout:
            pass
        finally:
            srv.close()

    threading.Thread(target=serve, daemon=True).start()
    res = asyncio.run(snmp.probe("127.0.0.1", timeout=2.0, port=port))
    assert res and "MikroTik RouterOS" in res["sysDescr"]
    assert res["sysName"] == "gw"


# ---- SMB / NTLM ----------------------------------------------------------------------

def _ntlm_type2(nb_computer, nb_domain, dns_computer, os_ver=(10, 0, 19045)):
    def av(av_id, s):
        v = s.encode("utf-16-le")
        return struct.pack("<HH", av_id, len(v)) + v
    target_info = av(1, nb_computer) + av(2, nb_domain) + av(3, dns_computer) + struct.pack("<HH", 0, 0)
    sig = b"NTLMSSP\x00"
    msg_type = struct.pack("<I", 2)
    target_name = struct.pack("<HHI", 0, 0, 0)
    flags = struct.pack("<I", 0x02000000)   # NEGOTIATE_VERSION set
    challenge = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    reserved = b"\x00" * 8
    # placeholder for target info fields; offset computed after fixed header (48 bytes + version 8 = 56)
    ti_offset = 56
    ti_fields = struct.pack("<HHI", len(target_info), len(target_info), ti_offset)
    version = struct.pack("<BBHBBBB", os_ver[0], os_ver[1], os_ver[2], 0, 0, 0, 15)
    header = sig + msg_type + target_name + flags + challenge + reserved + ti_fields + version
    assert len(header) == ti_offset
    return header + target_info


def test_parse_ntlm_type2():
    blob = _ntlm_type2("WIN-DESK01", "CORP", "win-desk01.corp.local")
    info = smb.parse_type2(blob)
    assert info["nb_computer"] == "WIN-DESK01"
    assert info["nb_domain"] == "CORP"
    assert info["dns_computer"] == "win-desk01.corp.local"
    assert info["os"] == "10.0 build 19045"


def test_parse_ntlm_type2_rejects_garbage():
    assert smb.parse_type2(b"not ntlm at all") is None


# ---- SSDP ----------------------------------------------------------------------------

def test_ssdp_header_parse():
    sample = ("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\n"
              "SERVER: Linux/3.14 UPnP/1.0 MiniDLNA/1.2\r\n"
              "ST: urn:schemas-upnp-org:device:MediaServer:1\r\n"
              "USN: uuid:abcd::urn:schemas-upnp-org:device:MediaServer:1\r\n\r\n")
    assert "MiniDLNA" in ssdp._header(sample, "SERVER")
    assert "MediaServer" in ssdp._header(sample, "ST")
    assert ssdp._header(sample, "NOPE") is None


# ---- OUI loader ----------------------------------------------------------------------

def test_parse_ieee_txt_and_csv():
    txt = "FC-FB-FB   (hex)\t\tCisco Systems, Inc\nAA-BB-CC   (hex)\t\tExample Corp\n"
    t = oui.parse_ieee(txt)
    assert t["FCFBFB"] == "Cisco Systems, Inc" and t["AABBCC"] == "Example Corp"
    csv_text = ("Registry,Assignment,Organization Name,Organization Address\n"
                "MA-L,001122,Acme Networks,Somewhere\n")
    c = oui.parse_ieee(csv_text)
    assert c["001122"] == "Acme Networks"
    # maclookup.app CSV: Mac Prefix,Vendor Name,Private,Block Type,Last Update
    ml = ("Mac Prefix,Vendor Name,Private,Block Type,Last Update\n"
          "00:00:0C,Cisco Systems Inc,false,MA-L,2015/11/17\n"
          "8C:1F:64:B8,Some MA-M Vendor,false,MA-M,2020/01/01\n")
    m = oui.parse_ieee(ml)
    assert m["00000C"] == "Cisco Systems Inc"
    assert m["8C1F64"] == "Some MA-M Vendor"   # MA-M prefix truncated to the 24-bit OUI


def test_update_oui_user_db(tmp_path, monkeypatch):
    dest = tmp_path / "oui.csv"
    monkeypatch.setattr(oui, "user_db_path", lambda: dest)
    oui._table.cache_clear()
    path = tmp_path / "ieee.txt"
    path.write_text("D4-CA-6D   (hex)\t\tRouterboard.com\n")
    n = oui.update_from_ieee(path)
    assert n == 1
    oui._table.cache_clear()
    assert oui.lookup("d4:ca:6d:11:22:33") == "Routerboard.com"


# ---- classify uses SNMP ---------------------------------------------------------------

def test_classify_uses_snmp_sysdescr():
    h = Host(ip="10.0.0.1", services=[Service(port=161, proto="udp", name="snmp",
                                              banner="Cisco IOS Software, C2960X", secure=False)])
    classify.classify(h)
    assert "network gear" in h.device_class or "router" in h.device_class
    assert h.model and "Cisco" in h.model
