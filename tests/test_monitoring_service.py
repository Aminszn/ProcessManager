
from datetime import datetime, timezone
from types import SimpleNamespace

import psutil
import pytest
import json

from database.connection import get_connection
from database.repository import ProcessRepository
from database.schema import initialize_database
from monitoring.monitoring_service import MonitoringService
from collectors.network_collector import NetworkCollectionUnsupported

@pytest.fixture
def service():
    connection = get_connection(":memory:")
    initialize_database(connection)

    repository = ProcessRepository(connection)
    monitoring_service = MonitoringService(repository)

    yield monitoring_service

    connection.close()


def make_process(pid=100, create_time=1000.0):
    return {
        "pid": pid,
        "name": "test-process",
        "status": "running",
        "username": "test-user",
        "create_time": create_time,
        "executable": "test.exe",
        "cmdline": ["test.exe"],
        "parent_pid": 1,
        "threads": 2,
        "memory_rss_bytes": 1024,
        "memory_vms_bytes": 2048,
        "platform": "windows",
        "platform_details": {},
    }


def make_connection():
    return {
        "pid": 100,
        "family": "AF_INET",
        "type": "SOCK_STREAM",
        "local_address": {
            "ip": "127.0.0.1",
            "port": 5000,
        },
        "remote_address": {
            "ip": "127.0.0.1",
            "port": 8000,
        },
        "status": "ESTABLISHED",
    }


def configure_collection(monkeypatch, processes, connections=None):
    if connections is None:
        connections = {}

    monkeypatch.setattr(
        "monitoring.monitoring_service.psutil.process_iter",
        lambda: [
            SimpleNamespace(pid=pid)
            for pid in processes
        ],
    )

    monkeypatch.setattr(
        "monitoring.monitoring_service.collect_process",
        lambda pid: processes[pid],
    )

    monkeypatch.setattr(
        "monitoring.monitoring_service.collect_process_network",
        lambda pid: connections.get(pid, []),
    )


def test_scan_collects_and_persists_process(service, monkeypatch):
    process = make_process()

    configure_collection(monkeypatch, {100: process})

    result = service.run_scan()

    assert result["processes_collected"] == 1
    assert result["events_detected"] == 1
    assert result["persisted"] is True
    assert result["scan_complete"] is True

    saved = service.repository.connection.execute(
        """
        SELECT po.*, pi.pid
        FROM process_observations po
        JOIN process_instances pi
            ON pi.id = po.process_instance_id
        """
    ).fetchall()

    assert len(saved) == 1
    assert saved[0]["pid"] == 100

def test_scan_persists_execution_information(service, monkeypatch):
    process = make_process()
    process["working_directory"] = "C:/Projects"
    process["executable_metadata"] = {
        "size_bytes": 4096,
        "created_at": 1700000000.0,
        "modified_at": 1700000100.0,
        "accessed_at": 1700000200.0,
    }

    configure_collection(monkeypatch, {100: process})

    result = service.run_scan()

    # Verify the returned process retains the execution information.
    returned_process = result["processes"][0]

    assert returned_process["working_directory"] == "C:/Projects"
    assert returned_process["executable_metadata"] == {
        "size_bytes": 4096,
        "created_at": 1700000000.0,
        "modified_at": 1700000100.0,
        "accessed_at": 1700000200.0,
    }

    # Verify the information was persisted to SQLite.
    saved = service.repository.connection.execute(
        """
        SELECT working_directory, executable_metadata
        FROM process_observations
        """
    ).fetchone()

    assert saved["working_directory"] == "C:/Projects"
    assert json.loads(saved["executable_metadata"]) == {
        "size_bytes": 4096,
        "created_at": 1700000000.0,
        "modified_at": 1700000100.0,
        "accessed_at": 1700000200.0,
    }

def test_scan_creates_monitoring_scan_record(service, monkeypatch):
    configure_collection(
        monkeypatch,
        {100: make_process()},
    )

    result = service.run_scan()

    scan = service.repository.connection.execute(
        "SELECT * FROM monitoring_scans WHERE id = ?",
        (result["scan_id"],),
    ).fetchone()

    assert scan is not None
    assert scan["enumeration_complete"] == 1
    assert scan["scan_complete"] == 1
    assert scan["processes_collected"] == 1
    assert scan["failures_count"] == 0


def test_scan_persists_network_connections(service, monkeypatch):
    process = make_process()
    connection = make_connection()

    configure_collection(
        monkeypatch,
        {100: process},
        {100: [connection]},
    )

    result = service.run_scan()

    assert result["network_connections_collected"] == 1

    saved = service.repository.connection.execute(
        "SELECT * FROM network_observations"
    ).fetchone()

    assert saved["local_port"] == 5000
    assert saved["remote_port"] == 8000


def test_repeated_scan_does_not_duplicate_first_seen_event(
    service,
    monkeypatch,
):
    process = make_process()

    configure_collection(monkeypatch, {100: process})

    service.run_scan()
    result = service.run_scan()

    assert result["events_detected"] == 0

    saved = service.repository.connection.execute(
        "SELECT COUNT(*) AS total FROM process_events"
    ).fetchone()

    assert saved["total"] == 1


def test_scan_detects_disappeared_process(service, monkeypatch):
    process = make_process()

    configure_collection(monkeypatch, {100: process})
    service.run_scan()

    configure_collection(monkeypatch, {})
    result = service.run_scan()

    assert result["events_detected"] == 1
    assert result["events"][0]["event_type"] == "process_disappeared"


def test_process_inspection_failure_is_recorded(
    service,
    monkeypatch,
):
    def denied(pid):
        raise psutil.AccessDenied(pid)

    monkeypatch.setattr(
        "monitoring.monitoring_service.psutil.process_iter",
        lambda: [SimpleNamespace(pid=100)],
    )

    monkeypatch.setattr(
        "monitoring.monitoring_service.collect_process",
        denied,
    )

    result = service.run_scan()

    assert result["processes_collected"] == 0
    assert result["scan_complete"] is False
    assert result["failures_count"] == 1

    failure = service.repository.connection.execute(
        "SELECT * FROM process_inspection_failures"
    ).fetchone()

    assert failure["pid"] == 100
    assert failure["stage"] == "process_inspection"
    assert failure["error_type"] == "AccessDenied"


def test_incomplete_scan_does_not_report_process_disappeared(
    service,
    monkeypatch,
):
    process = make_process()

    configure_collection(monkeypatch, {100: process})
    service.run_scan(persist=False)

    def denied(pid):
        raise psutil.AccessDenied(pid)

    monkeypatch.setattr(
        "monitoring.monitoring_service.psutil.process_iter",
        lambda: [SimpleNamespace(pid=100)],
    )

    monkeypatch.setattr(
        "monitoring.monitoring_service.collect_process",
        denied,
    )

    result = service.run_scan(persist=False)

    assert result["scan_complete"] is False
    assert result["events_detected"] == 0


def test_network_access_denied_is_recorded_without_incomplete_scan(
    service,
    monkeypatch,
):
    process = make_process()

    configure_collection(monkeypatch, {100: process})

    def denied(pid):
        raise psutil.AccessDenied(pid)

    monkeypatch.setattr(
        "monitoring.monitoring_service.collect_process_network",
        denied,
    )

    result = service.run_scan()

    assert result["processes_collected"] == 1
    assert result["network_connections_collected"] == 0
    assert result["scan_complete"] is True
    assert result["failures_count"] == 1

    failure = service.repository.connection.execute(
        "SELECT * FROM process_inspection_failures"
    ).fetchone()

    assert failure["stage"] == "network_collection"


def test_unsupported_network_collection_is_recorded_without_incomplete_scan(
    service,
    monkeypatch,
):
    process = make_process()

    configure_collection(monkeypatch, {100: process})

    def unsupported(pid):
        raise NetworkCollectionUnsupported(
            "Network inspection is unsupported for this process"
        )

    monkeypatch.setattr(
        "monitoring.monitoring_service.collect_process_network",
        unsupported,
    )

    result = service.run_scan()

    assert result["processes_collected"] == 1
    assert result["network_connections_collected"] == 0
    assert result["scan_complete"] is True
    assert result["failures_count"] == 1

    failure = service.repository.connection.execute(
        "SELECT * FROM process_inspection_failures"
    ).fetchone()

    assert failure["pid"] == 100
    assert failure["stage"] == "network_collection"
    assert failure["error_type"] == "NetworkCollectionUnsupported"


def test_process_disappearing_during_collection_is_recorded(
    service,
    monkeypatch,
):
    def disappeared(pid):
        raise psutil.NoSuchProcess(pid)

    monkeypatch.setattr(
        "monitoring.monitoring_service.psutil.process_iter",
        lambda: [SimpleNamespace(pid=100)],
    )

    monkeypatch.setattr(
        "monitoring.monitoring_service.collect_process",
        disappeared,
    )

    result = service.run_scan()

    assert result["processes_collected"] == 0
    assert result["scan_complete"] is False
    assert result["failures_count"] == 1


def test_enumeration_failure_marks_scan_incomplete(
    service,
    monkeypatch,
):
    def failing_iterator():
        yield SimpleNamespace(pid=100)
        raise psutil.AccessDenied()

    process = make_process()

    monkeypatch.setattr(
        "monitoring.monitoring_service.psutil.process_iter",
        failing_iterator,
    )

    monkeypatch.setattr(
        "monitoring.monitoring_service.collect_process",
        lambda pid: process,
    )

    monkeypatch.setattr(
        "monitoring.monitoring_service.collect_process_network",
        lambda pid: [],
    )

    result = service.run_scan()

    assert result["processes_collected"] == 1
    assert result["enumeration_complete"] is False
    assert result["scan_complete"] is False


def test_naive_timestamp_is_rejected(service):
    with pytest.raises(ValueError):
        service.run_scan(
            datetime(2026, 11, 10, 12, 0, 0)
        )


def test_failed_persistence_rolls_back_and_preserves_tracker(
    service,
    monkeypatch,
):
    process = make_process()

    configure_collection(monkeypatch, {100: process})

    original_save = service.repository.save_process_observation

    def fail_save(*args, **kwargs):
        raise RuntimeError("Simulated database failure")

    monkeypatch.setattr(
        service.repository,
        "save_process_observation",
        fail_save,
    )

    with pytest.raises(RuntimeError):
        service.run_scan()

    assert service.tracker._active_processes == {}

    connection = service.repository.connection

    assert connection.execute(
        "SELECT COUNT(*) FROM process_instances"
    ).fetchone()[0] == 0

    assert connection.execute(
        "SELECT COUNT(*) FROM monitoring_scans"
    ).fetchone()[0] == 0

    monkeypatch.setattr(
        service.repository,
        "save_process_observation",
        original_save,
    )

    result = service.run_scan()

    assert result["events_detected"] == 1


def test_run_scan_without_persistence_does_not_write_to_database(
    service,
    monkeypatch,
):
    process = make_process()

    configure_collection(monkeypatch, {100: process})

    result = service.run_scan(persist=False)

    assert result["persisted"] is False
    assert result["scan_id"] is None
    assert result["processes_collected"] == 1

    connection = service.repository.connection

    for table in (
        "process_instances",
        "process_observations",
        "process_events",
        "network_observations",
        "monitoring_scans",
        "process_inspection_failures",
    ):
        count = connection.execute(
            f"SELECT COUNT(*) FROM {table}"
        ).fetchone()[0]

        assert count == 0


def test_run_scan_without_persistence_still_updates_tracker(
    service,
    monkeypatch,
):
    process = make_process()

    configure_collection(monkeypatch, {100: process})

    result = service.run_scan(persist=False)

    assert result["events_detected"] == 1
    assert result["events"][0]["event_type"] == "process_first_seen"

    next_result = service.run_scan(persist=False)

    assert next_result["events_detected"] == 0


def test_starting_persistence_after_live_scan_saves_without_fake_events(
    service,
    monkeypatch,
):
    process = make_process()

    configure_collection(monkeypatch, {100: process})

    service.run_scan(persist=False)

    result = service.run_scan(persist=True)

    assert result["persisted"] is True
    assert result["processes_collected"] == 1
    assert result["events_detected"] == 0

    connection = service.repository.connection

    assert connection.execute(
        "SELECT COUNT(*) FROM process_instances"
    ).fetchone()[0] == 1

    assert connection.execute(
        "SELECT COUNT(*) FROM process_observations"
    ).fetchone()[0] == 1

    assert connection.execute(
        "SELECT COUNT(*) FROM process_events"
    ).fetchone()[0] == 0

    assert connection.execute(
        "SELECT COUNT(*) FROM monitoring_scans"
    ).fetchone()[0] == 1


def test_run_scan_returns_network_connections_with_process(
    service,
    monkeypatch,
):
    process = make_process()

    expected_connections = [
        {
            "pid": process["pid"],
            "family": "AF_INET",
            "type": "SOCK_STREAM",
            "local_address": {"ip": "127.0.0.1", "port": 5000},
            "remote_address": None,
            "status": "LISTEN",
        }
    ]

    configure_collection(
        monkeypatch,
        {process["pid"]: process},
        {process["pid"]: expected_connections},
    )

    result = service.run_scan(persist=False)

    assert result["processes_collected"] == 1
    assert result["processes"][0]["pid"] == process["pid"]
    assert (
        result["processes"][0]["network_connections"]
        == expected_connections
    )


def test_run_scan_does_not_skip_pid_zero(service, monkeypatch):
    process = make_process(pid=0)

    configure_collection(monkeypatch, {0: process})

    result = service.run_scan(persist=False)

    assert result["processes_collected"] == 1
    assert result["processes"][0]["pid"] == 0

def test_run_scan_persists_windows_system_process_identity(
    service,
    monkeypatch,
):
    process = make_process(pid=4, create_time=0.0)
    process.update(
        name="System",
        identity_type="platform_special",
        identity_key="windows:system:4",
    )

    configure_collection(monkeypatch, {4: process})

    result = service.run_scan(persist=True)

    assert result["processes_collected"] == 1

    instance = service.repository.connection.execute(
        """
        SELECT *
        FROM process_instances
        WHERE pid = 4
        """
    ).fetchone()

    assert instance is not None
    assert instance["identity_type"] == "platform_special"
    assert instance["identity_key"] == "windows:system:4"
    assert instance["create_time"] is None    

def test_run_scan_persists_platform_special_process_identity(
    service,
    monkeypatch,
):
    process = make_process(pid=0, create_time=None)
    process.update(
        name="System Idle Process",
        identity_type="platform_special",
        identity_key="windows:system_idle:0",
    )

    configure_collection(monkeypatch, {0: process})

    result = service.run_scan(persist=True)

    assert result["processes_collected"] == 1

    instance = service.repository.connection.execute(
        """
        SELECT *
        FROM process_instances
        WHERE pid = 0
        """
    ).fetchone()

    assert instance is not None
    assert instance["identity_type"] == "platform_special"
    assert instance["identity_key"] == "windows:system_idle:0"
    assert instance["create_time"] is None

def test_invalid_timestamp_type_is_rejected(service):
    with pytest.raises(ValueError, match="must be a datetime"):
        service.run_scan(observed_at="2026-11-11T12:00:00")