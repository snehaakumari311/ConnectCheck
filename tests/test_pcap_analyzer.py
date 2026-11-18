
from pathlib import Path

from analyzer.pcap_analyzer import analyze_pcap


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_PCAP = PROJECT_ROOT / "samples" / "sample.pcap"


def test_valid_sample_pcap():
    result = analyze_pcap(str(SAMPLE_PCAP), "sample.pcap")

    assert result["success"] is True
    assert result["summary"]["total_packets"] == 21
    assert result["protocol_statistics"]["distribution"]["TCP"] == 16
    assert result["protocol_statistics"]["distribution"]["UDP"] == 5


def test_empty_capture(tmp_path):
    empty_file = tmp_path / "empty.pcap"
    empty_file.write_bytes(b"")

    result = analyze_pcap(str(empty_file), "empty.pcap")

    assert result["success"] is False
    assert len(result["errors"]) > 0


def test_corrupted_capture(tmp_path):
    corrupted_file = tmp_path / "corrupted.pcap"
    corrupted_file.write_bytes(b"This is not a valid PCAP file")

    result = analyze_pcap(str(corrupted_file), "corrupted.pcap")

    assert result["success"] is False
    assert len(result["errors"]) > 0


def test_missing_capture():
    missing_file = PROJECT_ROOT / "samples" / "does_not_exist.pcap"

    result = analyze_pcap(str(missing_file), "missing.pcap")

    assert result["success"] is False
    assert len(result["errors"]) > 0
