
import requests

import checks.http_check as http_module


def make_fake_response(
    status_code=200,
    reason="OK",
    url="https://google.com",
    history=None,
    headers=None
):
    return {
        "url_tested": url,
        "final_url": url,
        "status_code": status_code,
        "reason": reason,
        "redirects": len(history or []),
        "response_time_ms": 25.0,
        "server": (headers or {}).get("Server", "unknown"),
        "scheme_used": url.split(":")[0],
    }


# Test 1: Successful HTTPS response
def test_http_https_success(monkeypatch):
    monkeypatch.setattr(
        http_module,
        "_fetch",
        lambda url: make_fake_response(url=url)
    )

    result = http_module.check_http("google.com")

    assert result["success"] is True
    assert result["check"] == "HTTP/HTTPS Check"
    assert result["details"]["status_code"] == 200
    assert result["details"]["reachable"] is True
    assert result["details"]["https_failed"] is False


# Test 2: HTTP fallback after HTTPS failure
def test_http_fallback_after_ssl_error(monkeypatch):
    calls = []

    def fake_fetch(url):
        calls.append(url)

        if url.startswith("https://"):
            raise requests.exceptions.SSLError("Certificate error")

        return make_fake_response(
            url=url,
            status_code=200
        )

    monkeypatch.setattr(http_module, "_fetch", fake_fetch)

    result = http_module.check_http("example.com")

    assert result["success"] is False
    assert result["error_type"] == "https_failed"
    assert result["details"]["reachable"] is True
    assert result["details"]["https_failed"] is True
    assert result["details"]["scheme_used"] == "http"
    assert len(calls) == 2


# Test 3: HTTP 404 response
def test_http_404_response(monkeypatch):
    monkeypatch.setattr(
        http_module,
        "_fetch",
        lambda url: make_fake_response(
            status_code=404,
            reason="Not Found",
            url=url
        )
    )

    result = http_module.check_http("example.com")

    assert result["success"] is False
    assert result["error_type"] == "http_status"
    assert result["details"]["reachable"] is True
    assert result["details"]["status_code"] == 404
    assert "client error 404" in result["message"]


# Test 4: HTTP 500 server error
def test_http_500_response(monkeypatch):
    monkeypatch.setattr(
        http_module,
        "_fetch",
        lambda url: make_fake_response(
            status_code=500,
            reason="Internal Server Error",
            url=url
        )
    )

    result = http_module.check_http("example.com")

    assert result["success"] is False
    assert result["error_type"] == "http_status"
    assert result["details"]["status_code"] == 500
    assert "server error 500" in result["message"]


# Test 5: Request timeout
def test_http_timeout(monkeypatch):
    calls = []

    def fake_fetch(url):
        calls.append(url)
        raise requests.exceptions.Timeout("Request timed out")

    monkeypatch.setattr(http_module, "_fetch", fake_fetch)

    result = http_module.check_http("google.com")

    assert result["success"] is False
    assert result["error_type"] == "timeout"
    assert result["details"]["reachable"] is False
    assert len(calls) == 1


# Test 6: Connection refused
def test_http_connection_refused(monkeypatch):
    def fake_fetch(url):
        raise requests.exceptions.ConnectionError(
            "Connection refused"
        )

    monkeypatch.setattr(http_module, "_fetch", fake_fetch)

    result = http_module.check_http("example.com")

    assert result["success"] is False
    assert result["error_type"] == "connection_refused"
    assert result["details"]["reachable"] is False


# Test 7: Too many redirects classification
def test_http_too_many_redirects():
    error_type, message = http_module._classify(
        requests.exceptions.TooManyRedirects("Redirect loop")
    )

    assert error_type == "too_many_redirects"
    assert "redirects" in message.lower()


# Test 8: Unexpected error
def test_http_unexpected_error(monkeypatch):
    def fake_fetch(url):
        raise RuntimeError("Unexpected test error")

    monkeypatch.setattr(http_module, "_fetch", fake_fetch)

    result = http_module.check_http("example.com")

    assert result["success"] is False
    assert result["error_type"] == "unknown"
    assert result["details"]["reachable"] is False
