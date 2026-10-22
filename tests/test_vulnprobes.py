import asyncio
import socket
import threading

from prowl.scan import vulnprobes


def _serve_once(handler):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        srv.settimeout(3)
        try:
            conn, _ = srv.accept()
            with conn:
                conn.settimeout(2)
                try:
                    data = conn.recv(256)
                except OSError:
                    data = b""
                handler(conn, data)
        except socket.timeout:
            pass
        finally:
            srv.close()

    threading.Thread(target=run, daemon=True).start()
    return port


def _serve_raw(handler):
    """Like _serve_once but does NOT pre-read — for server-speaks-first protocols (FTP, VNC)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        srv.settimeout(3)
        try:
            conn, _ = srv.accept()
            with conn:
                conn.settimeout(2)
                try:
                    handler(conn)
                except OSError:
                    pass
        except socket.timeout:
            pass
        finally:
            srv.close()

    threading.Thread(target=run, daemon=True).start()
    return port


def test_redis_tcp_primitive():
    # _datastore_blocking only probes fixed ports (6379, ...), which need privilege to bind,
    # so exercise the detection primitive: an unauth Redis answers +PONG; an authed one -NOAUTH.
    unauth = _serve_once(lambda c, d: c.sendall(b"+PONG\r\n"))
    assert vulnprobes._tcp("127.0.0.1", unauth, b"PING\r\n", 2.0).startswith(b"+PONG")
    authed = _serve_once(lambda c, d: c.sendall(b"-NOAUTH Authentication required.\r\n"))
    assert vulnprobes._tcp("127.0.0.1", authed, b"PING\r\n", 2.0).startswith(b"-NOAUTH")


def test_anonymous_ftp_detected():
    def handler(c):
        c.sendall(b"220 ready\r\n")
        c.recv(64)                 # USER anonymous
        c.sendall(b"331 need password\r\n")
        c.recv(64)                 # PASS
        c.sendall(b"230 logged in\r\n")
    port = _serve_raw(handler)
    out = vulnprobes._ftp_anon_blocking("127.0.0.1", 2.0, port=port)
    assert out and out[0]["title"] == "Anonymous FTP enabled"


def test_ftp_anon_rejected_no_finding():
    def handler(c):
        c.sendall(b"220 ready\r\n"); c.recv(64)
        c.sendall(b"331 need password\r\n"); c.recv(64)
        c.sendall(b"530 login incorrect\r\n")
    port = _serve_raw(handler)
    assert vulnprobes._ftp_anon_blocking("127.0.0.1", 2.0, port=port) == []


def test_vnc_no_auth_detected():
    def handler(c):
        c.sendall(b"RFB 003.008\n")
        c.recv(12)                 # client version
        c.sendall(bytes([2, 1, 2]))   # 2 security types: None(1), VNCAuth(2)
    port = _serve_raw(handler)
    out = vulnprobes._vnc_noauth_blocking("127.0.0.1", port, 2.0)
    assert out and "unauthenticated" in out[0]["title"]


def test_vnc_auth_required_no_finding():
    def handler(c):
        c.sendall(b"RFB 003.008\n"); c.recv(12)
        c.sendall(bytes([1, 2]))   # only VNCAuth(2)
    port = _serve_raw(handler)
    assert vulnprobes._vnc_noauth_blocking("127.0.0.1", port, 2.0) == []


def test_dns_open_resolver_detected():
    import socket as _s

    srv = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def run():
        srv.settimeout(3)
        try:
            data, addr = srv.recvfrom(512)
            # echo id, set flags RA+QR+RD (0x8180), 1 question, 1 answer
            resp = data[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + data[12:]
            resp += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22"
            srv.sendto(resp, addr)
        except _s.timeout:
            pass
        finally:
            srv.close()

    threading.Thread(target=run, daemon=True).start()
    out = vulnprobes._dns_resolver_blocking("127.0.0.1", 2.0, port=port)
    assert out and out[0]["title"] == "Open DNS resolver"


def test_elasticsearch_unauth_shape():
    body = b'{"name":"n","cluster_name":"docker-cluster","version":{"lucene_version":"8.0"}}'
    def handler(c, d):
        c.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" + body)
    port = _serve_once(handler)
    r = vulnprobes._tcp("127.0.0.1", port, b"GET / HTTP/1.0\r\nHost: x\r\n\r\n", 2.0, 2048)
    assert b" 200 " in r and b"cluster_name" in r


def test_tls_self_signed_and_cert(tmp_path):
    # generate a self-signed cert, serve TLS, assert the audit flags self-signed.
    import datetime
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        import pytest
        pytest.skip("cryptography not installed")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "prowl-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=5))   # expiring soon
            .sign(key, hashes.SHA256()))
    cfile = tmp_path / "c.pem"
    cfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM) +
                      key.private_bytes(serialization.Encoding.PEM,
                                        serialization.PrivateFormat.TraditionalOpenSSL,
                                        serialization.NoEncryption()))
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cfile))
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    def run():
        srv.settimeout(4)
        try:
            c, _ = srv.accept()
            with ctx.wrap_socket(c, server_side=True) as s:
                s.recv(16)
        except (OSError, ssl.SSLError):
            pass
        finally:
            srv.close()
    threading.Thread(target=run, daemon=True).start()
    out = vulnprobes._tls_audit_blocking("127.0.0.1", port, 3.0)
    titles = {f["title"] for f in out}
    assert "Self-signed TLS certificate" in titles
    assert "TLS certificate expiring soon" in titles
