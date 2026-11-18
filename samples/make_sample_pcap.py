
"""Generates samples/sample.pcap for ConnectCheck testing."""

import os

from scapy.all import (
    Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw
)
from scapy.utils import PcapWriter


CLIENT = "192.168.1.10"
DNS_SRV = "8.8.8.8"
WEB = "93.184.216.34"
DEAD = "10.0.0.99"


def tls_client_hello(sni):
    name = sni.encode()

    sni_ext = (
        b"\x00\x00"
        + (len(name) + 5).to_bytes(2, "big")
        + (len(name) + 3).to_bytes(2, "big")
        + b"\x00"
        + len(name).to_bytes(2, "big")
        + name
    )

    exts = sni_ext + b"\x00\x2b\x00\x03\x02\x03\x04"

    body = (
        b"\x03\x03"
        + b"\x00" * 32
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + len(exts).to_bytes(2, "big")
        + exts
    )

    hs = b"\x01" + len(body).to_bytes(3, "big") + body

    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def tls_server_hello():
    exts = b"\x00\x2b\x00\x02\x03\x04"

    body = (
        b"\x03\x03"
        + b"\x00" * 32
        + b"\x00"
        + b"\x13\x01"
        + b"\x00"
        + len(exts).to_bytes(2, "big")
        + exts
    )

    hs = b"\x02" + len(body).to_bytes(3, "big") + body

    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


def tcp(src, dst, sport, dport, flags, payload=b""):
    pkt = (
        Ether()
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags=flags)
    )

    return pkt / Raw(payload) if payload else pkt


def build():
    packets = []

    # DNS: answered, unanswered and NXDOMAIN
    packets.append(
        Ether() / IP(src=CLIENT, dst=DNS_SRV)
        / UDP(sport=53001, dport=53)
        / DNS(
            id=0x1234,
            rd=1,
            qd=DNSQR(qname="example.com")
        )
    )

    packets.append(
        Ether() / IP(src=DNS_SRV, dst=CLIENT)
        / UDP(sport=53, dport=53001)
        / DNS(
            id=0x1234,
            qr=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname="example.com"),
            an=DNSRR(
                rrname="example.com",
                type="A",
                ttl=60,
                rdata=WEB
            )
        )
    )

    packets.append(
        Ether() / IP(src=CLIENT, dst=DNS_SRV)
        / UDP(sport=53002, dport=53)
        / DNS(
            id=0x2222,
            rd=1,
            qd=DNSQR(qname="missing.example")
        )
    )

    packets.append(
        Ether() / IP(src=CLIENT, dst=DNS_SRV)
        / UDP(sport=53003, dport=53)
        / DNS(
            id=0x3333,
            rd=1,
            qd=DNSQR(qname="nonexistent.invalid")
        )
    )

    packets.append(
        Ether() / IP(src=DNS_SRV, dst=CLIENT)
        / UDP(sport=53, dport=53003)
        / DNS(
            id=0x3333,
            qr=1,
            rd=1,
            ra=1,
            rcode=3,
            qd=DNSQR(qname="nonexistent.invalid")
        )
    )

    # HTTP on port 80 with a 404 response
    packets.append(tcp(CLIENT, WEB, 50010, 80, "S"))
    packets.append(tcp(WEB, CLIENT, 80, 50010, "SA"))
    packets.append(tcp(CLIENT, WEB, 50010, 80, "A"))

    packets.append(
        tcp(
            CLIENT, WEB, 50010, 80, "PA",
            b"GET /missing?token=secret HTTP/1.1\r\n"
            b"Host: example.com\r\n\r\n"
        )
    )

    packets.append(
        tcp(
            WEB, CLIENT, 80, 50010, "PA",
            b"HTTP/1.1 404 Not Found\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
    )

    packets.append(tcp(CLIENT, WEB, 50010, 80, "FA"))

    # TLS on port 443
    packets.append(tcp(CLIENT, WEB, 50020, 443, "S"))
    packets.append(tcp(WEB, CLIENT, 443, 50020, "SA"))
    packets.append(tcp(CLIENT, WEB, 50020, 443, "A"))

    packets.append(
        tcp(
            CLIENT, WEB, 50020, 443, "PA",
            tls_client_hello("example.com")
        )
    )

    packets.append(
        tcp(
            WEB, CLIENT, 443, 50020, "PA",
            tls_server_hello()
        )
    )

    # Repeated SYNs without replies
    for _ in range(3):
        packets.append(tcp(CLIENT, DEAD, 50030, 22, "S"))

    # Connection refused: SYN answered by RST
    packets.append(tcp(CLIENT, WEB, 50040, 8081, "S"))
    packets.append(tcp(WEB, CLIENT, 8081, 50040, "RA"))

    # Give packets deterministic timestamps
    for i, pkt in enumerate(packets):
        pkt.time = 1700000000 + i * 0.01

    return packets


if __name__ == "__main__":
    output_path = os.path.join(
        os.path.dirname(__file__),
        "sample.pcap"
    )

    packets = build()

    # Explicitly write Ethernet link-layer PCAP
    with PcapWriter(
        output_path,
        linktype=1,
        sync=True
    ) as writer:
        writer.write(packets)

    print(f"Wrote {len(packets)} packets to {output_path}")
