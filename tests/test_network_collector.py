
import socket
from types import SimpleNamespace

import psutil
import pytest

from collectors.network_collector import collect_process_network


def make_connection(
    family=socket.AF_INET,
    connection_type=socket.SOCK_STREAM,
    local_address=("127.0.0.1", 5000),
    remote_address=("127.0.0.1", 8000),
    status="ESTABLISHED",
):
    return SimpleNamespace(
        family=family,
        type=connection_type,
        laddr=local_address,
        raddr=remote_address,
        status=status,
    )


def mock_process(monkeypatch, connections):
    class FakeProcess:
        def __init__(self, pid):
            self.pid = pid

        def net_connections(self, kind=None):
            assert kind == "inet"
            return connections

    monkeypatch.setattr(psutil, "Process", FakeProcess)


def test_collects_process_network_connection(monkeypatch):
    connection = make_connection()

    mock_process(monkeypatch, [connection])

    results = collect_process_network(100)

    assert len(results) == 1
    assert results[0]["pid"] == 100
    assert results[0]["family"] == "AF_INET"
    assert results[0]["type"] == "SOCK_STREAM"
    assert results[0]["local_address"] == {
        "ip": "127.0.0.1",
        "port": 5000,
    }
    assert results[0]["remote_address"] == {
        "ip": "127.0.0.1",
        "port": 8000,
    }
    assert results[0]["status"] == "ESTABLISHED"


def test_collects_ipv6_connection(monkeypatch):
    connection = make_connection(
        family=socket.AF_INET6,
        local_address=("::1", 5000),
        remote_address=("::1", 8000),
    )

    mock_process(monkeypatch, [connection])

    results = collect_process_network(100)

    assert results[0]["family"] == "AF_INET6"
    assert results[0]["local_address"]["ip"] == "::1"


def test_handles_connection_without_remote_address(monkeypatch):
    connection = make_connection(
        remote_address=(),
        status="LISTEN",
    )

    mock_process(monkeypatch, [connection])

    results = collect_process_network(100)

    assert results[0]["remote_address"] is None
    assert results[0]["status"] == "LISTEN"


def test_collects_multiple_connections(monkeypatch):
    connections = [
        make_connection(),
        make_connection(
            local_address=("127.0.0.1", 6000),
            remote_address=(),
            status="LISTEN",
        ),
    ]

    mock_process(monkeypatch, connections)

    results = collect_process_network(100)

    assert len(results) == 2


def test_returns_empty_list_when_no_connections(monkeypatch):
    mock_process(monkeypatch, [])

    results = collect_process_network(100)

    assert results == []


@pytest.mark.parametrize("pid", [-1, True, "100"])
def test_rejects_invalid_pid(pid):
    with pytest.raises(ValueError):
        collect_process_network(pid)


def test_propagates_missing_process_error(monkeypatch):
    def mock_process(pid):
        raise psutil.NoSuchProcess(pid)

    monkeypatch.setattr(psutil, "Process", mock_process)

    with pytest.raises(psutil.NoSuchProcess):
        collect_process_network(999999)


def test_propagates_access_denied_error(monkeypatch):
    class FakeProcess:
        def __init__(self, pid):
            pass

        def net_connections(self, kind=None):
            raise psutil.AccessDenied(pid=100)

    monkeypatch.setattr(psutil, "Process", FakeProcess)

    with pytest.raises(psutil.AccessDenied):
        collect_process_network(100)

def test_rejects_linux_pid_zero(monkeypatch):
    from collectors import network_collector

    monkeypatch.setattr(
        network_collector,
        "detect_platform",
        lambda: "linux",
    )

    with pytest.raises(ValueError):
        collect_process_network(0)


def test_reports_windows_pid_zero_as_unsupported(monkeypatch):
    from collectors import network_collector

    monkeypatch.setattr(
        network_collector,
        "detect_platform",
        lambda: "windows",
    )

    with pytest.raises(
        network_collector.NetworkCollectionUnsupported,
        match="System Idle Process",
    ):
        collect_process_network(0)