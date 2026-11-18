"""PCAP analyzer for ConnectCheck (Scapy based).

Public API:
    validate_capture_file(path) -> error string or None
    analyze_pcap(path, display_name) -> result dictionary (see _empty_result)
"""
import logging
import os
from collections import Counter
from datetime import datetime, timezone

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.utils import PcapReader

log = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}
MAX_PACKETS = 50000
SAMPLE_ROWS = 50
LIST_LIMIT = 25

# First 4 bytes of pcap (both byte orders, micro/nano) and pcapng files
CAPTURE_MAGIC = {
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
}

SERVICE_NAMES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-submission", 993: "IMAPS",
    995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP-alt", 8443: "HTTPS-alt",
}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
             16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
              4: "NOTIMP", 5: "REFUSED"}
RCODE_HINTS = {
    "NXDOMAIN": "The queried name may not exist or may be mistyped.",
    "SERVFAIL": "The resolver could not complete the lookup (upstream, zone or DNSSEC problem).",
    "REFUSED": "The server declined to answer, for example because of an access policy.",
}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")
TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
                0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
TLS_HANDSHAKE_TYPES = {1, 2, 4, 11, 12, 13, 14, 15, 16, 20}
LEGACY_TLS = {"SSL 3.0", "TLS 1.0", "TLS 1.1"}


# ---------------------------------------------------------------- helpers
def _printable(value, limit=120):
    """Convert any value to a short, display-safe string."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    elif isinstance(value, (list, tuple)):
        value = ", ".join(_printable(v, limit) for v in value)
    else:
        value = str(value)
    value = "".join(ch if ch.isprintable() else "?" for ch in value)
    return value[:limit]


def _name(value):
    return _printable(value).rstrip(".").lower()


def _u16(data, index):
    return (data[index] << 8) | data[index + 1]


def _flag_name(flags):
    if flags & 0x04:
        return "RST-ACK" if flags & 0x10 else "RST"
    if flags & 0x02:
        return "SYN-ACK" if flags & 0x10 else "SYN"
    if flags & 0x01:
        return "FIN-ACK" if flags & 0x10 else "FIN"
    if flags & 0x08:
        return "PSH-ACK" if flags & 0x10 else "PSH"
    if flags & 0x10:
        return "ACK"
    return "NONE" if flags == 0 else f"OTHER(0x{flags:02x})"


def _records(field, record_type):
    """Return the DNS question/answer records of a field as a plain list."""
    if field is None:
        return []
    if isinstance(field, list):
        return [r for r in field if isinstance(r, record_type)][:100]
    items, node = [], field
    while isinstance(node, record_type) and len(items) < 100:
        items.append(node)
        node = node.payload
    return items


def _fmt_time(ts):
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError, TypeError):
        return "n/a"


def _flow(key, count):
    src, sport, dst, dport = key
    return {"src": src, "sport": sport, "dst": dst, "dport": dport,
            "service": SERVICE_NAMES.get(dport, ""), "count": count}


# ------------------------------------------------------------- validation
def validate_capture_file(path):
    """Return an error message, or None if the file looks like a capture."""
    try:
        size = os.path.getsize(path)
        if size == 0:
            return "The uploaded file is empty."
        with open(path, "rb") as fh:
            magic = fh.read(4)
    except OSError:
        return "The uploaded file could not be read."
    if magic not in CAPTURE_MAGIC:
        return "This is not a valid pcap/pcapng capture (unrecognised file header)."
    return None


# ------------------------------------------------------------------ state
class _State:
    def __init__(self):
        self.total = 0
        self.total_bytes = 0
        self.malformed = 0
        self.truncated = False
        self.partial = False
        self.first_ts = None
        self.last_ts = None
        self.proto = Counter()
        self.counts = Counter()          # dns / http / tls packet counts
        self.src_ips, self.dst_ips = set(), set()
        self.tcp_flags = Counter()
        self.sample = []
        # DNS
        self.dns_query_count = 0
        self.dns_response_count = 0
        self.dns_queries = Counter()     # (name, type)
        self.dns_pending = Counter()     # (id, name)
        self.dns_answered = set()        # (id, name)
        self.dns_responses = []
        self.dns_rcodes = Counter()
        self.dns_error_names = Counter() # (rcode, name)
        # TCP
        self.flag_totals = Counter()     # syn / synack / rst / fin
        self.syn = Counter()             # client key -> SYN count
        self.synack = set()              # client keys that got a SYN-ACK
        self.reset_reply = set()         # client keys that got an RST
        self.rst = Counter()
        self.syn_ports = Counter()
        # HTTP
        self.http_requests = Counter()   # (method, host, path)
        self.http_status = Counter()     # (status, reason)
        self.http_request_count = 0
        self.http_response_count = 0
        # TLS
        self.tls_counts = Counter()
        self.tls_client = Counter()      # (sni, highest version offered)
        self.tls_server_versions = Counter()


# ------------------------------------------------------------ DNS parsing
def _analyze_dns(pkt, st):
    dns = pkt[DNS]
    questions = _records(dns.qd, DNSQR)
    name, qtype = "", ""
    if questions:
        name = _name(questions[0].qname)
        qtype = DNS_TYPES.get(questions[0].qtype, str(questions[0].qtype))
    if dns.qr == 0:
        st.dns_query_count += 1
        st.dns_queries[(name, qtype)] += 1
        st.dns_pending[(dns.id, name)] += 1
        return
    st.dns_response_count += 1
    rcode = DNS_RCODES.get(dns.rcode, str(dns.rcode))
    st.dns_rcodes[rcode] += 1
    st.dns_answered.add((dns.id, name))
    if rcode != "NOERROR":
        st.dns_error_names[(rcode, name)] += 1
    if len(st.dns_responses) < 50:
        answers = []
        for rr in _records(dns.an, DNSRR)[:10]:
            rtype = DNS_TYPES.get(rr.type, str(rr.type))
            answers.append(f"{rtype} {_printable(rr.rdata)}")
        st.dns_responses.append({"name": name, "type": qtype, "rcode": rcode, "answers": answers})


# ------------------------------------------------------------ TCP tracking
def _track_tcp(tcp, src, dst, st):
    flags = int(tcp.flags)
    name = _flag_name(flags)
    st.tcp_flags[name] += 1
    key = (src, tcp.sport, dst, tcp.dport)
    reverse = (dst, tcp.dport, src, tcp.sport)
    if flags & 0x04:
        st.flag_totals["rst"] += 1
        st.rst[key] += 1
        st.reset_reply.add(reverse)
    elif (flags & 0x12) == 0x12:
        st.flag_totals["synack"] += 1
        st.synack.add(reverse)
    elif flags & 0x02:
        st.flag_totals["syn"] += 1
        st.syn[key] += 1
        st.syn_ports[tcp.dport] += 1
    if flags & 0x01:
        st.flag_totals["fin"] += 1
    return name


# ----------------------------------------------------------- HTTP parsing
def _analyze_http(payload, st):
    """Detect cleartext HTTP request/response lines. Returns True if HTTP."""
    if payload.startswith(HTTP_METHODS):
        lines = payload.split(b"\r\n\r\n", 1)[0].split(b"\r\n")
        parts = lines[0].decode("latin-1").split(" ")
        if len(parts) >= 3 and parts[-1].startswith("HTTP/"):
            host = ""
            for line in lines[1:]:
                if line.lower().startswith(b"host:"):
                    host = _printable(line[5:].decode("latin-1").strip())
                    break
            path = _printable(parts[1].split("?")[0], 150)  # query strings may hold secrets
            st.http_request_count += 1
            st.http_requests[(_printable(parts[0], 10), host, path)] += 1
            return True
    elif payload.startswith(b"HTTP/1."):
        parts = payload.split(b"\r\n", 1)[0].decode("latin-1").split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            reason = _printable(parts[2]) if len(parts) > 2 else ""
            st.http_response_count += 1
            st.http_status[(int(parts[1]), reason)] += 1
            return True
    return False


# ------------------------------------------------------------ TLS parsing
def _tls_extensions(p, pos):
    total = _u16(p, pos)
    pos += 2
    end = min(pos + total, len(p))
    while pos + 4 <= end:
        etype, elen = _u16(p, pos), _u16(p, pos + 2)
        pos += 4
        yield etype, p[pos:pos + elen]
        pos += elen


def _parse_client_hello(p):
    sni, version = "", "Unknown"
    try:
        version = TLS_VERSIONS.get(_u16(p, 9), "Unknown")
        pos = 43
        pos += 1 + p[pos]            # session id
        pos += 2 + _u16(p, pos)      # cipher suites
        pos += 1 + p[pos]            # compression methods
        for etype, data in _tls_extensions(p, pos):
            if etype == 0 and len(data) >= 5:          # server_name
                nlen = _u16(data, 3)
                sni = _printable(data[5:5 + nlen].decode("ascii", errors="replace"))
            elif etype == 43 and len(data) >= 3:       # supported_versions
                offered = [_u16(data, i) for i in range(1, min(data[0], len(data) - 1), 2)]
                known = [v for v in offered if v in TLS_VERSIONS]
                if known:
                    version = TLS_VERSIONS[max(known)]
    except IndexError:
        pass
    return sni, version


def _parse_server_hello(p):
    version = "Unknown"
    try:
        version = TLS_VERSIONS.get(_u16(p, 9), "Unknown")
        pos = 43
        pos += 1 + p[pos]            # session id
        pos += 3                     # cipher suite (2) + compression (1)
        for etype, data in _tls_extensions(p, pos):
            if etype == 43 and len(data) >= 2:
                version = TLS_VERSIONS.get(_u16(data, 0), version)
    except IndexError:
        pass
    return version


def _analyze_tls(payload, st):
    """Detect a TLS handshake record at the start of a TCP payload."""
    if len(payload) < 6 or payload[0] != 0x16 or payload[1] != 0x03 or payload[2] > 0x04:
        return False
    hs_type = payload[5]
    if hs_type not in TLS_HANDSHAKE_TYPES:
        return False
    if hs_type == 1:
        st.tls_counts["client_hello"] += 1
        st.tls_client[_parse_client_hello(payload)] += 1
    elif hs_type == 2:
        st.tls_counts["server_hello"] += 1
        st.tls_server_versions[_parse_server_hello(payload)] += 1
    elif hs_type == 11:
        st.tls_counts["certificate"] += 1
    else:
        st.tls_counts["other_handshake"] += 1
    return True


# ------------------------------------------------------ per-packet driver
def _process_packet(pkt, number, st):
    st.total_bytes += len(pkt)
    ts = None
    try:
        ts = float(pkt.time)
    except Exception:
        pass
    if ts is not None:
        st.first_ts = ts if st.first_ts is None else min(st.first_ts, ts)
        st.last_ts = ts if st.last_ts is None else max(st.last_ts, ts)

    src = dst = None
    is_ip = pkt.haslayer(IP) or pkt.haslayer(IPv6)
    if pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    elif pkt.haslayer(ARP):
        src, dst = pkt[ARP].psrc, pkt[ARP].pdst
    if is_ip:
        st.src_ips.add(src)
        st.dst_ips.add(dst)

    proto, sport, dport, flags_text = "Other", None, None, ""
    if pkt.haslayer(TCP):
        proto, tcp = "TCP", pkt[TCP]
        sport, dport = tcp.sport, tcp.dport
        flags_text = _track_tcp(tcp, src, dst, st)
    elif pkt.haslayer(UDP):
        proto = "UDP"
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
    elif pkt.haslayer(ARP):
        proto = "ARP"
    elif pkt.haslayer(IPv6):
        proto = "IPv6-other"
    st.proto[proto] += 1

    is_dns = pkt.haslayer(DNS)
    if is_dns:
        st.counts["dns"] += 1
        try:
            _analyze_dns(pkt, st)
        except Exception:
            st.malformed += 1
    if proto == "TCP" and not is_dns:
        payload = bytes(pkt[TCP].payload)
        if payload:
            if _analyze_http(payload, st):
                st.counts["http"] += 1
            elif _analyze_tls(payload, st):
                st.counts["tls"] += 1

    if len(st.sample) < SAMPLE_ROWS:
        st.sample.append({"no": number, "ts": ts, "src": src or "-", "dst": dst or "-",
                          "proto": proto, "sport": sport if sport is not None else "-",
                          "dport": dport if dport is not None else "-",
                          "length": len(pkt), "flags": flags_text or "-"})


# ----------------------------------------------------------- result build
def _empty_result(filename):
    return {
        "success": False, "filename": filename, "summary": {},
        "protocol_statistics": {}, "dns_analysis": {}, "tcp_analysis": {},
        "http_analysis": {}, "tls_analysis": {}, "packet_sample": [],
        "findings": [], "notes": [], "warnings": [], "errors": [],
    }


def _build_result(st, result):
    first, last = st.first_ts, st.last_ts
    duration = round(last - first, 3) if first is not None and last is not None else None
    tcp_n, udp_n, icmp_n = st.proto["TCP"], st.proto["UDP"], st.proto["ICMP"]

    result["summary"] = {
        "total_packets": st.total, "total_bytes": st.total_bytes,
        "first_packet_time": _fmt_time(first), "last_packet_time": _fmt_time(last),
        "duration_seconds": duration,
        "unique_source_ips": len(st.src_ips), "unique_destination_ips": len(st.dst_ips),
        "truncated": st.truncated, "unparseable_packets": st.malformed,
    }
    result["protocol_statistics"] = {
        "distribution": dict(st.proto.most_common()),
        "tcp_packets": tcp_n, "udp_packets": udp_n, "icmp_packets": icmp_n,
        "dns_packets": st.counts["dns"], "http_packets": st.counts["http"],
        "tls_packets": st.counts["tls"],
        "other_packets": st.total - tcp_n - udp_n - icmp_n,
        "tcp_flags": dict(st.tcp_flags.most_common()),
        "source_ips": sorted(st.src_ips)[:LIST_LIMIT],
        "destination_ips": sorted(st.dst_ips)[:LIST_LIMIT],
    }

    unanswered_dns = sorted({n for (i, n), _c in st.dns_pending.items()
                             if (i, n) not in st.dns_answered})
    result["dns_analysis"] = {
        "query_count": st.dns_query_count, "response_count": st.dns_response_count,
        "queries": [{"name": n, "type": t, "count": c}
                    for (n, t), c in st.dns_queries.most_common(50)],
        "responses": st.dns_responses,
        "rcode_counts": dict(st.dns_rcodes),
        "unanswered_count": len(unanswered_dns),
        "unanswered_queries": unanswered_dns[:LIST_LIMIT],
    }

    unanswered = [(k, c) for k, c in st.syn.items()
                  if k not in st.synack and k not in st.reset_reply]
    unanswered.sort(key=lambda item: -item[1])
    established = sum(1 for k in st.syn if k in st.synack)
    result["tcp_analysis"] = {
        "tcp_packets": tcp_n,
        "syn_packets": st.flag_totals["syn"], "synack_packets": st.flag_totals["synack"],
        "rst_packets": st.flag_totals["rst"], "fin_packets": st.flag_totals["fin"],
        "connection_attempts": len(st.syn), "established_connections": established,
        "unanswered_attempt_count": len(unanswered),
        "repeated_unanswered_count": sum(1 for _k, c in unanswered if c >= 2),
        "unanswered_attempts": [_flow(k, c) for k, c in unanswered[:20]],
        "reset_flow_count": len(st.rst),
        "resets": [_flow(k, c) for k, c in st.rst.most_common(20)],
        "top_destination_ports": [{"port": p, "service": SERVICE_NAMES.get(p, ""), "count": c}
                                  for p, c in st.syn_ports.most_common(10)],
    }

    result["http_analysis"] = {
        "request_count": st.http_request_count, "response_count": st.http_response_count,
        "requests": [{"method": m, "host": h, "path": p, "count": c}
                     for (m, h, p), c in st.http_requests.most_common(50)],
        "responses": [{"status": s, "reason": r, "count": c}
                      for (s, r), c in sorted(st.http_status.items())],
    }

    tc = st.tls_counts
    result["tls_analysis"] = {
        "handshake_packets": st.counts["tls"],
        "client_hello_count": tc["client_hello"], "server_hello_count": tc["server_hello"],
        "certificate_messages": tc["certificate"],
        "client_hellos": [{"sni": s, "version": v, "count": c}
                          for (s, v), c in st.tls_client.most_common(50)],
        "server_versions": dict(st.tls_server_versions),
    }

    rows = []
    for row in st.sample:
        row = dict(row)
        ts = row.pop("ts")
        row["time"] = round(ts - first, 6) if ts is not None and first is not None else "-"
        rows.append(row)
    result["packet_sample"] = rows

    if st.truncated:
        result["warnings"].append(f"Only the first {MAX_PACKETS} packets were analysed.")
    if st.partial:
        result["warnings"].append("The capture ended unexpectedly (possibly truncated or "
                                  "corrupted); results are based on the packets read so far.")
    if st.malformed:
        result["warnings"].append(f"{st.malformed} packet(s) could not be fully parsed and were skipped.")
    result["notes"] = [
        "HTTPS payloads are encrypted. Only TLS handshake metadata (such as the SNI hostname) "
        "is visible; URLs, headers and status codes of HTTPS traffic cannot be read without decryption keys.",
        "This analysis describes only the uploaded capture. It is not proof of the current state of any network.",
        "DNS over TCP and TLS records split across several packets are not reassembled.",
    ]
    result["findings"] = _build_findings(st, result)
    result["success"] = True
    return result


def _build_findings(st, result):
    dns, tcp = result["dns_analysis"], result["tcp_analysis"]
    http, tls = result["http_analysis"], result["tls_analysis"]
    findings = []

    def add(severity, observation, evidence, explanation, recommendation):
        findings.append({"severity": severity, "observation": observation,
                         "evidence": evidence, "possible_explanation": explanation,
                         "recommendation": recommendation})

    if dns["unanswered_count"]:
        add("warning", "DNS queries without an observed response",
            f"{dns['unanswered_count']} distinct query(ies) had no matching response, e.g. "
            + ", ".join(dns["unanswered_queries"][:3]),
            "The DNS server may be unreachable, the reply may have been dropped, or the capture "
            "may have started or stopped before the reply arrived.",
            "Check connectivity to the DNS server and capture on the client side to confirm.")

    bad = {k: v for k, v in st.dns_rcodes.items() if k != "NOERROR"}
    if bad:
        examples = [n for (_r, n), _c in st.dns_error_names.most_common(5)]
        hints = " ".join(RCODE_HINTS[k] for k in bad if k in RCODE_HINTS)
        add("warning", "DNS error responses observed",
            ", ".join(f"{k}: {v}" for k, v in bad.items()) + ". Names: " + ", ".join(examples),
            hints or "The server returned a non-successful response code.",
            "Verify the queried names and the configured DNS server.")

    if tcp["rst_packets"]:
        top = tcp["resets"][0]
        add("warning", "TCP reset packets observed (possible connection reset)",
            f"{tcp['rst_packets']} RST packet(s) across {tcp['reset_flow_count']} flow(s); most frequent: "
            f"{top['src']}:{top['sport']} -> {top['dst']}:{top['dport']} x{top['count']}",
            "A peer may have refused or aborted connections (closed port, application abort, or a "
            "middlebox). Packets alone cannot show which one.",
            "Check whether the service listens on that port and review firewall or proxy logs.")

    repeated = [r for r in tcp["unanswered_attempts"] if r["count"] >= 2]
    if repeated:
        ex = repeated[0]
        add("warning", "Potential TCP connection establishment issue",
            f"{tcp['repeated_unanswered_count']} connection attempt(s) sent repeated SYN packets with no "
            f"observed SYN-ACK or RST, e.g. {ex['src']} -> {ex['dst']}:{ex['dport']} x{ex['count']}",
            "The destination may be unreachable or filtered, packets may be dropped on the path, or the "
            "reply direction was not captured.",
            "Test reachability to that address and port from another vantage point.")
    elif tcp["unanswered_attempt_count"]:
        add("info", "SYN packets without an observed reply",
            f"{tcp['unanswered_attempt_count']} connection attempt(s) have no SYN-ACK or RST in this capture",
            "The capture point may not see return traffic, or the capture ended before the reply.",
            "Capture on the client side for a complete view.")

    errors = [r for r in http["responses"] if r["status"] >= 400]
    if errors:
        add("warning", "HTTP error responses observed in cleartext traffic",
            ", ".join(f"{r['status']} {r['reason']} x{r['count']}" for r in errors),
            "4xx codes usually mean a client/request problem; 5xx codes point to a server-side failure.",
            "Check the requested hosts and paths in the HTTP section below.")

    if http["request_count"]:
        hosts = sorted({r["host"] for r in http["requests"] if r["host"]})[:5]
        add("info", "Unencrypted HTTP traffic observed",
            f"{http['request_count']} request(s)" + (f" to {', '.join(hosts)}" if hosts else ""),
            "Cleartext HTTP can be read by anyone on the network path.",
            "Prefer HTTPS where possible.")

    legacy = [v for v in tls["server_versions"] if v in LEGACY_TLS]
    if legacy:
        add("warning", "Legacy TLS/SSL version negotiated",
            "ServerHello version(s): " + ", ".join(legacy),
            "Older protocol versions are deprecated and weaker than TLS 1.2/1.3.",
            "Upgrade the server or client configuration.")

    if tls["client_hello_count"] and not tls["server_hello_count"]:
        add("info", "TLS ClientHello seen without a ServerHello",
            f"{tls['client_hello_count']} ClientHello message(s), 0 ServerHello message(s)",
            "The server reply may be blocked or missing, or the capture may be one-directional.",
            "Capture both directions and compare with the TCP findings.")

    if not findings:
        add("info", "No problematic patterns detected in this capture",
            "DNS, TCP, HTTP and TLS checks found nothing unusual",
            "This only describes the uploaded capture, not the current state of the network.",
            "No action required.")
    return findings


# ------------------------------------------------------------- public API
def analyze_pcap(path, display_name="capture.pcap"):
    """Analyse a .pcap/.pcapng file. Never raises for bad input; see result['errors']."""
    result = _empty_result(display_name)
    problem = validate_capture_file(path)
    if problem:
        result["errors"].append(problem)
        return result

    st = _State()
    reader = None
    try:
        reader = PcapReader(path)
        for pkt in reader:
            if st.total >= MAX_PACKETS:
                st.truncated = True
                break
            st.total += 1
            try:
                _process_packet(pkt, st.total, st)
            except Exception:
                st.malformed += 1
    except Exception as exc:  # corrupted or unsupported capture
        log.warning("PCAP read problem: %s", exc)
        if st.total == 0:
            result["errors"].append("The capture file could not be parsed. It may be corrupted "
                                    "or use an unsupported format.")
            return result
        st.partial = True
    finally:
        if reader is not None:
            try:
                reader.close()
            except Exception:
                pass

    if st.total == 0:
        result["errors"].append("The capture contains no packets.")
        return result
    return _build_result(st, result)