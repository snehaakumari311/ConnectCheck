
import json
import socket
import ssl
import sys
from datetime import datetime, timezone

from checks.common import make_result

CHECK_NAME = "SSL/TLS Certificate"
EXPIRY_WARNING_DAYS = 14


def _name_to_dict(rdn_sequence):
    result = {}
    for rdn in rdn_sequence or ():
        for key, value in rdn:
            result[key] = value
    return result


def check_ssl(domain, port=443, timeout=5):
    context = ssl.create_default_context()

    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
                tls_version = tls_sock.version()
                cipher = tls_sock.cipher()[0] if tls_sock.cipher() else "unknown"

    except ssl.SSLCertVerificationError as exc:
        verify_message = getattr(exc, "verify_message", str(exc))

        return make_result(
            CHECK_NAME,
            False,
            f"Certificate verification failed: {verify_message}.",
            details={"verify_message": verify_message},
            error_type="certificate_error"
        )

    except ssl.SSLError as exc:
        reason = getattr(exc, "reason", str(exc))

        return make_result(
            CHECK_NAME,
            False,
            f"TLS handshake failed: {reason}.",
            error_type="handshake_error"
        )

    except socket.timeout:
        return make_result(
            CHECK_NAME,
            False,
            f"Connection to port {port} timed out.",
            error_type="timeout"
        )

    except socket.gaierror:
        return make_result(
            CHECK_NAME,
            False,
            "Could not resolve the domain.",
            error_type="dns_error"
        )

    except ConnectionRefusedError:
        return make_result(
            CHECK_NAME,
            False,
            f"Connection refused on port {port} (HTTPS is not available).",
            error_type="connection_refused"
        )

    except OSError as exc:
        return make_result(
            CHECK_NAME,
            False,
            f"Network error: {exc}",
            error_type="connection_error"
        )

    except Exception as exc:
        return make_result(
            CHECK_NAME,
            False,
            f"Unexpected SSL error: {exc}",
            error_type="unknown"
        )

    try:
        not_before = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notBefore"]),
            tz=timezone.utc
        )

        not_after = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notAfter"]),
            tz=timezone.utc
        )

    except (KeyError, ValueError):
        return make_result(
            CHECK_NAME,
            False,
            "Could not read certificate dates.",
            error_type="unknown"
        )

    days_remaining = (not_after - datetime.now(timezone.utc)).days

    subject = _name_to_dict(cert.get("subject"))
    issuer = _name_to_dict(cert.get("issuer"))

    san = [
        value
        for kind, value in cert.get("subjectAltName", ())
        if kind == "DNS"
    ][:10]

    details = {
        "subject_cn": subject.get("commonName", "unknown"),
        "issuer": issuer.get("organizationName")
        or issuer.get("commonName", "unknown"),
        "valid_from": not_before.strftime("%Y-%m-%d"),
        "valid_until": not_after.strftime("%Y-%m-%d"),
        "days_remaining": days_remaining,
        "tls_version": tls_version,
        "cipher": cipher,
        "alt_names": san,
    }

    if days_remaining < 0:
        return make_result(
            CHECK_NAME,
            False,
            f"Certificate expired {abs(days_remaining)} day(s) ago.",
            details=details,
            error_type="expired"
        )

    if days_remaining <= EXPIRY_WARNING_DAYS:
        return make_result(
            CHECK_NAME,
            True,
            f"Certificate is valid but expires in {days_remaining} day(s).",
            details=details,
            error_type="expiring_soon"
        )

    return make_result(
        CHECK_NAME,
        True,
        f"Certificate is valid for {days_remaining} more day(s).",
        details=details
    )


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    print(json.dumps(check_ssl(target), indent=2))
