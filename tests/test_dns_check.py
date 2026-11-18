
import socket
from unittest.mock import MagicMock

import checks.dns_check as dns_module


# Test 1: Successful DNS resolution
def test_dns_success(monkeypatch):
    monkeypatch.setattr(
        dns_module,
        "_resolve",
        lambda domain: (["142.250.183.14"], [])
    )

    result = dns_module.check_dns("google.com")

    assert result["success"] is True
    assert result["check"] == "DNS Resolution"
    assert result["details"]["primary_ip"] == "142.250.183.14"
    assert result["error_type"] is None


# Test 2: IPv6 resolution
def test_dns_ipv6_success(monkeypatch):
    monkeypatch.setattr(
        dns_module,
        "_resolve",
        lambda domain: ([], ["2606:4700:4700::1111"])
    )

    result = dns_module.check_dns("example.com")

    assert result["success"] is True
    assert result["details"]["primary_ip"] == "2606:4700:4700::1111"
    assert len(result["details"]["ipv6"]) == 1


# Test 3: No IP address returned
def test_dns_no_ip_found(monkeypatch):
    monkeypatch.setattr(
        dns_module,
        "_resolve",
        lambda domain: ([], [])
    )

    result = dns_module.check_dns("example.com")

    assert result["success"] is False
    assert result["error_type"] == "not_found"


# Test 4: Domain not found
def test_dns_domain_not_found(monkeypatch):
    error_code = getattr(socket, "EAI_NONAME", -2)

    monkeypatch.setattr(
        dns_module,
        "_resolve",
        lambda domain: (_ for _ in ()).throw(
            socket.gaierror(error_code, "Name not found")
        )
    )

    result = dns_module.check_dns("invalid.example")

    assert result["success"] is False
    assert result["error_type"] == "not_found"


# Test 5: Temporary DNS server error
def test_dns_temporary_error(monkeypatch):
    monkeypatch.setattr(
        dns_module,
        "_resolve",
        lambda domain: (_ for _ in ()).throw(
            socket.gaierror(11002, "Temporary DNS failure")
        )
    )

    result = dns_module.check_dns("google.com")

    assert result["success"] is False
    assert result["error_type"] == "dns_server_error"


# Test 6: DNS timeout
def test_dns_timeout(monkeypatch):
    fake_future = MagicMock()
    fake_future.result.side_effect = dns_module.FutureTimeout()

    fake_executor = MagicMock()
    fake_executor.submit.return_value = fake_future

    monkeypatch.setattr(
        dns_module,
        "ThreadPoolExecutor",
        lambda max_workers: fake_executor
    )

    result = dns_module.check_dns("google.com", timeout=2)

    assert result["success"] is False
    assert result["error_type"] == "timeout"
    assert "timed out" in result["message"].lower()
    fake_executor.shutdown.assert_called_once_with(wait=False)


# Test 7: Unexpected DNS error
def test_dns_unexpected_error(monkeypatch):
    monkeypatch.setattr(
        dns_module,
        "_resolve",
        lambda domain: (_ for _ in ()).throw(
            RuntimeError("Unexpected test error")
        )
    )

    result = dns_module.check_dns("google.com")

    assert result["success"] is False
    assert result["error_type"] == "unknown"
