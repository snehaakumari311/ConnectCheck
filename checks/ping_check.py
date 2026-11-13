
import ipaddress
import json
import os
import re
import subprocess
import sys

from checks.common import DOMAIN_REGEX, make_result

CHECK_NAME = "Ping Test (ICMP)"
PING_COUNT = 4


def _valid_target(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return bool(DOMAIN_REGEX.match(target or ""))


def check_ping(target):
    if not _valid_target(target):
        return make_result(CHECK_NAME, False, "Invalid ping target.", error_type="invalid_input")

    if os.name == "nt":  # Windows
        cmd = ["ping", "-n", str(PING_COUNT), "-w", "2000", target]
    else:                # Linux/macOS (fallback)
        cmd = ["ping", "-c", str(PING_COUNT), "-W", "2", target]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20,
                              shell=False, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return make_result(CHECK_NAME, False, "Ping command timed out.", error_type="timeout")
    except FileNotFoundError:
        return make_result(CHECK_NAME, False, "The 'ping' command was not found on this system.",
                           error_type="tool_missing")
    except Exception as exc:
        return make_result(CHECK_NAME, False, f"Unexpected ping error: {exc}", error_type="unknown")

    output = proc.stdout or ""
    # A real reply contains "TTL=" (Windows) or "ttl=" (Linux).
    received = len(re.findall(r"ttl=", output, re.IGNORECASE))
    times = [float(t) for t in re.findall(r"time[=<]\s*([\d.]+)\s*ms", output, re.IGNORECASE)]
    sent = PING_COUNT
    loss = round((sent - received) / sent * 100)

    details = {"target": target, "sent": sent, "received": received, "packet_loss_percent": loss}
    if times:
        details.update({"min_ms": min(times), "max_ms": max(times),
                        "avg_ms": round(sum(times) / len(times), 1)})

    if received > 0:
        return make_result(CHECK_NAME, True,
                           f"Host replied to {received}/{sent} pings ({loss}% loss).",
                           details=details)

    if "unreachable" in output.lower():
        return make_result(CHECK_NAME, False, "Destination unreachable (no route to host).",
                           details=details, error_type="unreachable")
    return make_result(
        CHECK_NAME, False,
        "No ping replies (request timed out). The host may be down, or it may simply block ICMP.",
        details=details, error_type="timeout")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    print(json.dumps(check_ping(target), indent=2))
