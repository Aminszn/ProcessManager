
from io import StringIO

import pytest
from rich.console import Console
from rich.panel import Panel

from visualization.live_dashboard import LiveDashboard


def make_process():
    return {
        "pid": 1234,
        "name": "test-process.exe",
        "status": "running",
        "username": "test-user",
        "memory_rss_bytes": 1048576,
        "threads": 4,
        "network_connections": [
            {
                "pid": 1234,
                "family": "AF_INET",
                "type": "SOCK_STREAM",
                "local_address": {"ip": "127.0.0.1", "port": 5000},
                "remote_address": {"ip": "127.0.0.1", "port": 8000},
                "status": "ESTABLISHED",
            }
        ],
    }


def render_to_text(panel):
    output = StringIO()
    console = Console(
        file=output,
        force_terminal=False,
        width=120,
    )
    console.print(panel)
    return output.getvalue()


def test_formats_memory_in_megabytes():
    assert LiveDashboard.format_memory(1048576) == "1.00 MB"


def test_render_returns_rich_panel():
    dashboard = LiveDashboard()

    result = {
        "processes": [make_process()],
        "network_connections_collected": 1,
    }

    panel = dashboard.render(result)

    assert isinstance(panel, Panel)
    assert panel.title == "Process Monitor"


def test_render_displays_process_information():
    dashboard = LiveDashboard()

    result = {
        "processes": [make_process()],
        "network_connections_collected": 1,
    }

    panel = dashboard.render(result)
    output = render_to_text(panel)

    assert "1234" in output
    assert "test-process.exe" in output
    assert "running" in output
    assert "test-user" in output
    assert "1.00 MB" in output
    assert "4" in output
    assert "Connections" in output


def test_render_displays_recording_status():
    dashboard = LiveDashboard()

    result = {
        "processes": [make_process()],
        "network_connections_collected": 1,
    }

    recording_on = render_to_text(
        dashboard.render(result, recording_enabled=True)
    )

    recording_off = render_to_text(
        dashboard.render(result, recording_enabled=False)
    )

    assert "ON" in recording_on
    assert "OFF" in recording_off


def test_render_handles_empty_process_list():
    dashboard = LiveDashboard()

    result = {
        "processes": [],
        "network_connections_collected": 0,
    }

    panel = dashboard.render(result)
    output = render_to_text(panel)

    assert "No processes found" in output


def test_update_sends_rendered_panel_to_live_display(monkeypatch):
    dashboard = LiveDashboard()

    received = {}

    class FakeLive:
        def update(self, renderable, refresh=False):
            received["renderable"] = renderable
            received["refresh"] = refresh

    dashboard.live = FakeLive()

    result = {
        "processes": [make_process()],
        "network_connections_collected": 1,
    }

    dashboard.update(result, recording_enabled=True)

    assert isinstance(received["renderable"], Panel)
    assert received["refresh"] is True


def test_start_and_stop_control_live_display():
    dashboard = LiveDashboard()

    calls = []

    class FakeLive:
        def start(self):
            calls.append("start")

        def stop(self):
            calls.append("stop")

    dashboard.live = FakeLive()

    dashboard.start()
    dashboard.stop()

    assert calls == ["start", "stop"]


@pytest.mark.parametrize(
    "refresh_per_second",
    [0, -1, True, "4"],
)
def test_rejects_invalid_refresh_rate(refresh_per_second):
    with pytest.raises(ValueError):
        LiveDashboard(
            refresh_per_second=refresh_per_second,
        )

def test_format_memory_returns_na_when_memory_is_none():
    assert LiveDashboard.format_memory(None) == "N/A"


def test_format_memory_returns_zero_when_memory_is_zero():
    assert LiveDashboard.format_memory(0) == "0.00 MB"


def test_live_display_does_not_use_alternate_screen(monkeypatch):
    received = {}

    class FakeLive:
        def __init__(self, **kwargs):
            received.update(kwargs)

    monkeypatch.setattr(
        "visualization.live_dashboard.Live",
        FakeLive,
    )

    LiveDashboard()

    assert received["screen"] is False


def test_render_handles_missing_process_metadata():
    dashboard = LiveDashboard()

    result = {
        "processes": [
            {
                "name": None,
                "status": None,
                "username": None,
                "memory_rss_bytes": None,
                "threads": None,
                "network_connections": [],
            }
        ],
        "network_connections_collected": 0,
    }

    panel = dashboard.render(result)
    output = render_to_text(panel)

    assert "N/A" in output
    assert "Unknown" in output
