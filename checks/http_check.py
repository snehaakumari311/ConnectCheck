
import json
import sys
import time

import requests

from checks.common import make_result

CHECK_NAME = "HTTP/HTTPS Check"
HEADERS = {"User-Agent": "ConnectCheck/1.0 (network diagnostic tool)"}
TIMEOUT = (5, 10)  # (connect, read) seconds


def _fetch(url):
    start = time.perf_counter()
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                        allow_redirects=True, stream=True)
    try:
        elapsed = round((time.perf_counter() - start) * 1000, 1)
        return {
            "url_tested": url,
            "final_url": resp.url,
            "status_code": resp.status_code,
            "reason": resp.reason,
            "redirects": len(resp.history),
            "response_time_ms": elapsed,
            "server": resp.headers.get("Server", "unknown"),
            "scheme_used": url.split(":")[0],
        }
    finally:
        resp.close()


def _classify(exc):
    text = str(exc).lower()
    if isinstance(exc, requests.exceptions.SSLError):
        return "ssl_error", "TLS/SSL handshake or certificate validation failed."
    if isinstance(exc, requests.exceptions.Timeout):
        return "timeout", "The request timed out (no response in time)."
    if isinstance(exc, requests.exceptions.TooManyRedirects):
        return "too_many_redirects", "Too many redirects (possible redirect loop)."
    if isinstance(exc, requests.exceptions.ConnectionError):
        if "refused" in text:
            return "connection_refused", "Connection refused (nothing is listening on that port)."
        return "connection_error", "Could not establish a connection to the server."
    return "unknown", f"Unexpected HTTP error: {exc}"


def _status_message(code, reason):
    if code < 300:
        return f"Website responded with {code} {reason} (success)."
    if code < 400:
        return f"Website responded with redirect {code} {reason}."
    if code < 500:
        return f"Website responded with client error {code} {reason}."
    return f"Website responded with server error {code} {reason}."


def check_http(domain):
    attempts = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            details = _fetch(url)
        except Exception as exc:
            etype, msg = _classify(exc)
            attempts.append({"url": url, "error_type": etype, "error": msg})
            if etype == "timeout":
                break
            continue

        code = details["status_code"]
        https_failed = scheme == "http" and len(attempts) > 0
        details.update({"reachable": True, "https_failed": https_failed, "attempts": attempts})
        message = _status_message(code, details["reason"])
        if https_failed:
            message = "HTTPS failed, but plain HTTP responded. " + message
            details["https_error"] = attempts[0]["error"]
        success = code < 400 and not https_failed
        return make_result(CHECK_NAME, success, message, details=details,
                           error_type=None if success else ("https_failed" if https_failed else "http_status"))

    first = attempts[0] if attempts else {"error_type": "unknown", "error": "No attempt was made."}
    return make_result(
        CHECK_NAME, False, first["error"],
        details={"reachable": False, "attempts": attempts},
        error_type=first["error_type"])


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    print(json.dumps(check_http(target), indent=2))
