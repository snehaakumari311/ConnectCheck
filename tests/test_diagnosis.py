
import diagnosis


def make_result(
    success=True,
    message="Test successful",
    error_type=None,
    details=None
):
    return {
        "success": success,
        "message": message,
        "error_type": error_type,
        "details": details or {},
    }


def healthy_inputs():
    dns = make_result(
        details={"primary_ip": "142.250.183.14"}
    )

    ping = make_result(
        message="Host replied to 4/4 pings."
    )

    http = make_result(
        message="Website responded with 200 OK.",
        details={
            "reachable": True,
            "status_code": 200,
            "https_failed": False,
        }
    )

    tls = make_result(
        message="Certificate is valid.",
        details={"days_remaining": 90}
    )

    return dns, ping, http, tls


# Test 1: DNS timeout
def test_diagnose_dns_timeout():
    dns, ping, http, tls = healthy_inputs()

    dns = make_result(
        False,
        "DNS lookup timed out.",
        "timeout"
    )

    result = diagnosis.diagnose(dns, ping, http, tls)

    assert result["status"] == "critical"
    assert result["category"] == "DNS"
    assert "DNS server" in result["probable_cause"]


# Test 2: Domain not found
def test_diagnose_domain_not_found():
    dns, ping, http, tls = healthy_inputs()

    dns = make_result(
        False,
        "Domain could not be resolved.",
        "not_found"
    )

    result = diagnosis.diagnose(dns, ping, http, tls)

    assert result["status"] == "critical"
    assert result["category"] == "DNS"
    assert "Domain does not exist" in result["probable_cause"]


# Test 3: All checks successful
def test_diagnose_healthy_connection():
    dns, ping, http, tls = healthy_inputs()

    result = diagnosis.diagnose(dns, ping, http, tls)

    assert result["status"] == "healthy"
    assert result["category"] == "None"
    assert result["probable_cause"] == "No problem detected."


# Test 4: Ping fails but website works
def test_diagnose_ping_fails_website_works():
    dns, ping, http, tls = healthy_inputs()

    ping = make_result(
        False,
        "No ping replies.",
        "timeout"
    )

    result = diagnosis.diagnose(dns, ping, http, tls)

    assert result["status"] == "healthy"
    assert result["category"] == "None"
    assert any("ICMP" in finding for finding in result["findings"])


# Test 5: TLS certificate expiring soon
def test_diagnose_certificate_expiring_soon():
    dns, ping, http, tls = healthy_inputs()

    tls = make_result(
        True,
        "Certificate expires soon.",
        "expiring_soon",
        {"days_remaining": 7}
    )

    result = diagnosis.diagnose(dns, ping, http, tls)

    assert result["status"] == "warning"
    assert result["category"] == "TLS Certificate"
    assert "expiry" in result["probable_cause"].lower()


# Test 6: HTTPS fails due to certificate problem
def test_diagnose_https_certificate_failure():
    dns, ping, http, tls = healthy_inputs()

    http = make_result(
        False,
        "HTTPS failed, but plain HTTP responded.",
        "https_failed",
        {
            "reachable": True,
            "status_code": 200,
            "https_failed": True,
        }
    )

    tls = make_result(
        False,
        "Certificate verification failed.",
        "certificate_error"
    )

    result = diagnosis.diagnose(dns, ping, http, tls)

    assert result["status"] == "critical"
    assert result["category"] == "TLS Certificate"
    assert "certificate problem" in result["probable_cause"].lower()


# Test 7: HTTP 500 server error
def test_diagnose_http_500():
    dns, ping, http, tls = healthy_inputs()

    http["details"]["status_code"] = 500
    http["message"] = "Internal Server Error"

    result = diagnosis.diagnose(dns, ping, http, tls)

    assert result["status"] == "critical"
    assert result["category"] == "Web Server"
    assert "500" in result["probable_cause"]


# Test 8: HTTP 403 access restriction
def test_diagnose_http_403():
    dns, ping, http, tls = healthy_inputs()

    http["details"]["status_code"] = 403

    result = diagnosis.diagnose(dns, ping, http, tls)

    assert result["status"] == "warning"
    assert result["category"] == "Access"
    assert "403" in result["probable_cause"]


# Test 9: HTTP 429 rate limiting
def test_diagnose_http_429():
    dns, ping, http, tls = healthy_inputs()

    http["details"]["status_code"] = 429

    result = diagnosis.diagnose(dns, ping, http, tls)

    assert result["status"] == "warning"
    assert result["category"] == "Access"
    assert "429" in result["probable_cause"]


# Test 10: HTTP 404 client error
def test_diagnose_http_404():
    dns, ping, http, tls = healthy_inputs()

    http["details"]["status_code"] = 404

    result = diagnosis.diagnose(dns, ping, http, tls)

    assert result["status"] == "warning"
    assert result["category"] == "Web Server"
    assert "404" in result["probable_cause"]


# Test 11: Web server connection refused
def test_diagnose_connection_refused():
    dns, ping, http, tls = healthy_inputs()

    http = make_result(
        False,
        "Connection refused.",
        "connection_refused",
        {"reachable": False}
    )

    result = diagnosis.diagnose(dns, ping, http, tls)

    assert result["status"] == "critical"
    assert result["category"] == "Web Server"
    assert "not listening" in result["probable_cause"]


# Test 12: Host appears unreachable
def test_diagnose_network_unreachable():
    dns, ping, http, tls = healthy_inputs()

    ping = make_result(
        False,
        "No ping replies.",
        "timeout"
    )

    http = make_result(
        False,
        "Connection timed out.",
        "timeout",
        {"reachable": False}
    )

    result = diagnosis.diagnose(dns, ping, http, tls)

    assert result["status"] == "critical"
    assert result["category"] == "Network"
    assert "unreachable" in result["probable_cause"].lower()


# Test 13: DNS server unavailable
def test_diagnose_dns_server_error():
    dns, ping, http, tls = healthy_inputs()

    dns = make_result(
        False,
        "DNS server unavailable.",
        "dns_server_error"
    )

    result = diagnosis.diagnose(dns, ping, http, tls)

    assert result["status"] == "critical"
    assert result["category"] == "DNS"
    assert "DNS server" in result["probable_cause"]
