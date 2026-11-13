
import socket
import sys
import json
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

from checks.common import make_result

CHECK_NAME = "DNS Resolution"


def _resolve(domain):
    infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    ipv4, ipv6 = [], []
    for family, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if family == socket.AF_INET and ip not in ipv4:
            ipv4.append(ip)
        elif family == socket.AF_INET6 and ip not in ipv6:
            ipv6.append(ip)
    return ipv4, ipv6


def check_dns(domain, timeout=5):
    start = time.perf_counter()
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(_resolve, domain)
    try:
        ipv4, ipv6 = future.result(timeout=timeout)
        elapsed = round((time.perf_counter() - start) * 1000, 1)
        primary = ipv4[0] if ipv4 else (ipv6[0] if ipv6 else None)
        if primary is None:
            return make_result(CHECK_NAME, False,
                               f"No IP address returned for {domain}.",
                               error_type="not_found")
        return make_result(
            CHECK_NAME, True,
            f"{domain} resolved to {primary} in {elapsed} ms.",
            details={"domain": domain, "primary_ip": primary,
                     "ipv4": ipv4, "ipv6": ipv6, "resolution_time_ms": elapsed},
        )
    except FutureTimeout:
        return make_result(CHECK_NAME, False,
                           f"DNS lookup timed out after {timeout} seconds.",
                           error_type="timeout")
    except socket.gaierror as exc:
        if exc.errno in (11002, getattr(socket, "EAI_AGAIN", -99999)):
            return make_result(CHECK_NAME, False,
                               "DNS server did not respond or is temporarily unavailable.",
                               error_type="dns_server_error")
        return make_result(CHECK_NAME, False,
                           f"Domain '{domain}' could not be resolved (does not exist or has no records).",
                           error_type="not_found")
    except Exception as exc:
        return make_result(CHECK_NAME, False, f"Unexpected DNS error: {exc}",
                           error_type="unknown")
    finally:
        executor.shutdown(wait=False)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    print(json.dumps(check_dns(target), indent=2))
