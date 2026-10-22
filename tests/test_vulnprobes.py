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


def test_redis_tcp_primitive():
    # _datastore_blocking only probes fixed ports (6379, ...), which need privilege to bind,
    # so exercise the detection primitive: an unauth Redis answers +PONG; an authed one -NOAUTH.
    unauth = _serve_once(lambda c, d: c.sendall(b"+PONG\r\n"))
    assert vulnprobes._tcp("127.0.0.1", unauth, b"PING\r\n", 2.0).startswith(b"+PONG")
    authed = _serve_once(lambda c, d: c.sendall(b"-NOAUTH Authentication required.\r\n"))
    assert vulnprobes._tcp("127.0.0.1", authed, b"PING\r\n", 2.0).startswith(b"-NOAUTH")


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
