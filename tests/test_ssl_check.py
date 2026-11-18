
import socket
import ssl
from datetime import datetime, timedelta, timezone

import checks.ssl_check as ssl_module


def make_certificate(not_after):
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(days=30)

    return {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Test CA"),),),
        "notBefore": not_before.strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": not_after.strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (
            ("DNS", "example.com"),
            ("DNS", "www.example.com"),
        ),
    }


class FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeTLSSocket(FakeSocket):
    def __init__(self, certificate):
        self.certificate = certificate

    def getpeercert(self):
        return self.certificate

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)


class FakeSSLContext:
    def __init__(self, certificate):
        self.certificate = certificate

    def wrap_socket(self, sock, server_hostname):
        return FakeTLSSocket(self.certificate)


def mock_successful_connection(monkeypatch, certificate):
    monkeypatch.setattr(
        ssl_module.socket,
        "create_connection",
        lambda address, timeout: FakeSocket()
    )

    monkeypatch.setattr(
        ssl_module.ssl,
        "create_default_context",
        lambda: FakeSSLContext(certificate)
    )


# Test 1: Valid certificate
def test_ssl_valid_certificate(monkeypatch):
    future_date = datetime.now(timezone.utc) + timedelta(days=90)
    certificate = make_certificate(future_date)

    mock_successful_connection(monkeypatch, certificate)

    result = ssl_module.check_ssl("example.com")

    assert result["success"] is True
    assert result["check"] == "SSL/TLS Certificate"
    assert result["details"]["tls_version"] == "TLSv1.3"
    assert result["details"]["subject_cn"] == "example.com"
    assert result["details"]["issuer"] == "Test CA"
    assert "example.com" in result["details"]["alt_names"]


# Test 2: Expired certificate
def test_ssl_expired_certificate(monkeypatch):
    expired_date = datetime.now(timezone.utc) - timedelta(days=10)
    certificate = make_certificate(expired_date)

    mock_successful_connection(monkeypatch, certificate)

    result = ssl_module.check_ssl("example.com")

    assert result["success"] is False
    assert result["error_type"] == "expired"
    assert result["details"]["days_remaining"] < 0


# Test 3: Certificate expiring soon
def test_ssl_certificate_expiring_soon(monkeypatch):
    expiry_date = datetime.now(timezone.utc) + timedelta(days=7)
    certificate = make_certificate(expiry_date)

    mock_successful_connection(monkeypatch, certificate)

    result = ssl_module.check_ssl("example.com")

    assert result["success"] is True
    assert result["error_type"] == "expiring_soon"
    assert result["details"]["days_remaining"] <= 14


# Test 4: Certificate verification failure
def test_ssl_certificate_verification_error(monkeypatch):
    def fake_connection(address, timeout):
        raise ssl.SSLCertVerificationError(
            1, "certificate verify failed"
        )

    monkeypatch.setattr(
        ssl_module.socket,
        "create_connection",
        fake_connection
    )

    result = ssl_module.check_ssl("example.com")

    assert result["success"] is False
    assert result["error_type"] == "certificate_error"


# Test 5: TLS handshake failure
def test_ssl_handshake_error(monkeypatch):
    def fake_connection(address, timeout):
        raise ssl.SSLError("TLS handshake failed")

    monkeypatch.setattr(
        ssl_module.socket,
        "create_connection",
        fake_connection
    )

    result = ssl_module.check_ssl("example.com")

    assert result["success"] is False
    assert result["error_type"] == "handshake_error"


# Test 6: Connection timeout
def test_ssl_connection_timeout(monkeypatch):
    def fake_connection(address, timeout):
        raise socket.timeout("Connection timed out")

    monkeypatch.setattr(
        ssl_module.socket,
        "create_connection",
        fake_connection
    )

    result = ssl_module.check_ssl("example.com")

    assert result["success"] is False
    assert result["error_type"] == "timeout"


# Test 7: DNS resolution failure
def test_ssl_dns_error(monkeypatch):
    def fake_connection(address, timeout):
        raise socket.gaierror("Name resolution failed")

    monkeypatch.setattr(
        ssl_module.socket,
        "create_connection",
        fake_connection
    )

    result = ssl_module.check_ssl("invalid.example")

    assert result["success"] is False
    assert result["error_type"] == "dns_error"


# Test 8: Connection refused
def test_ssl_connection_refused(monkeypatch):
    def fake_connection(address, timeout):
        raise ConnectionRefusedError("Connection refused")

    monkeypatch.setattr(
        ssl_module.socket,
        "create_connection",
        fake_connection
    )

    result = ssl_module.check_ssl("example.com")

    assert result["success"] is False
    assert result["error_type"] == "connection_refused"


# Test 9: Unexpected error
def test_ssl_unexpected_error(monkeypatch):
    def fake_connection(address, timeout):
        raise RuntimeError("Unexpected test error")

    monkeypatch.setattr(
        ssl_module.socket,
        "create_connection",
        fake_connection
    )

    result = ssl_module.check_ssl("example.com")

    assert result["success"] is False
    assert result["error_type"] == "unknown"
