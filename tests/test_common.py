
from checks.common import clean_domain, make_result, skipped_result


# Test 1: Valid domain
def test_clean_domain_valid_input():
    domain, error = clean_domain("google.com")
    assert domain == "google.com"
    assert error is None


# Test 2: Uppercase domain
def test_clean_domain_uppercase_input():
    domain, error = clean_domain("GOOGLE.COM")
    assert domain == "google.com"
    assert error is None


# Test 3: HTTPS URL
def test_clean_domain_with_https():
    domain, error = clean_domain("https://google.com")
    assert domain == "google.com"
    assert error is None


# Test 4: URL containing a path
def test_clean_domain_with_path():
    domain, error = clean_domain("https://google.com/search")
    assert domain == "google.com"
    assert error is None


# Test 5: Empty input
def test_clean_domain_empty_input():
    domain, error = clean_domain("")
    assert domain is None
    assert error is not None


# Test 6: Invalid domain
def test_clean_domain_invalid_input():
    domain, error = clean_domain("invalid_domain")
    assert domain is None
    assert error is not None


# Test 7: Standard diagnostic result
def test_make_result():
    result = make_result(
        check="DNS",
        success=True,
        message="DNS resolution successful"
    )

    assert result["check"] == "DNS"
    assert result["success"] is True
    assert result["message"] == "DNS resolution successful"


# Test 8: Skipped diagnostic result
def test_skipped_result():
    result = skipped_result("Ping", "DNS resolution failed")

    assert result["check"] == "Ping"
    assert result["success"] is False
    assert result["skipped"] is True
