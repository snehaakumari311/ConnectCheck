
from types import SimpleNamespace

import checks.ping_check as ping_module


# Test 1: Invalid target
def test_ping_invalid_target():
    result = ping_module.check_ping("invalid_domain")

    assert result["success"] is False
    assert result["error_type"] == "invalid_input"


# Test 2: Successful ping
def test_ping_success(monkeypatch):
    fake_output = """
    Reply from 8.8.8.8: bytes=32 time=10ms TTL=117
    Reply from 8.8.8.8: bytes=32 time=12ms TTL=117
    Reply from 8.8.8.8: bytes=32 time=8ms TTL=117
    Reply from 8.8.8.8: bytes=32 time=11ms TTL=117
    """

    monkeypatch.setattr(
        ping_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=fake_output)
    )

    result = ping_module.check_ping("8.8.8.8")

    assert result["success"] is True
    assert result["details"]["sent"] == 4
    assert result["details"]["received"] == 4
    assert result["details"]["packet_loss_percent"] == 0
    assert result["details"]["avg_ms"] == 10.2


# Test 3: Partial packet loss
def test_ping_partial_packet_loss(monkeypatch):
    fake_output = """
    Reply from 8.8.8.8: bytes=32 time=10ms TTL=117
    Reply from 8.8.8.8: bytes=32 time=12ms TTL=117
    Request timed out.
    Request timed out.
    """

    monkeypatch.setattr(
        ping_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=fake_output)
    )

    result = ping_module.check_ping("8.8.8.8")

    assert result["success"] is True
    assert result["details"]["received"] == 2
    assert result["details"]["packet_loss_percent"] == 50


# Test 4: Destination unreachable
def test_ping_unreachable(monkeypatch):
    fake_output = "Destination host unreachable."

    monkeypatch.setattr(
        ping_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=fake_output)
    )

    result = ping_module.check_ping("8.8.8.8")

    assert result["success"] is False
    assert result["error_type"] == "unreachable"


# Test 5: No ping replies
def test_ping_timeout(monkeypatch):
    fake_output = "Request timed out."

    monkeypatch.setattr(
        ping_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=fake_output)
    )

    result = ping_module.check_ping("8.8.8.8")

    assert result["success"] is False
    assert result["error_type"] == "timeout"


# Test 6: Ping command timeout
def test_ping_command_timeout(monkeypatch):
    def fake_run(*args, **kwargs):
        raise ping_module.subprocess.TimeoutExpired(
            cmd="ping", timeout=20
        )

    monkeypatch.setattr(
        ping_module.subprocess,
        "run",
        fake_run
    )

    result = ping_module.check_ping("8.8.8.8")

    assert result["success"] is False
    assert result["error_type"] == "timeout"


# Test 7: Ping command not installed
def test_ping_tool_missing(monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("ping command not found")

    monkeypatch.setattr(
        ping_module.subprocess,
        "run",
        fake_run
    )

    result = ping_module.check_ping("8.8.8.8")

    assert result["success"] is False
    assert result["error_type"] == "tool_missing"


# Test 8: Unexpected error
def test_ping_unexpected_error(monkeypatch):
    def fake_run(*args, **kwargs):
        raise RuntimeError("Unexpected test error")

    monkeypatch.setattr(
        ping_module.subprocess,
        "run",
        fake_run
    )

    result = ping_module.check_ping("8.8.8.8")

    assert result["success"] is False
    assert result["error_type"] == "unknown"
