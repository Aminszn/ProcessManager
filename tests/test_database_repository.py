
import json
import sqlite3

import pytest

from database.connection import get_connection
from database.repository import ProcessRepository
from database.schema import initialize_database


@pytest.fixture
def repository():
    connection = get_connection(":memory:")
    initialize_database(connection)
    repo = ProcessRepository(connection)

    yield repo

    connection.close()


def make_process(
    pid=100,
    create_time=1000.0,
    platform="windows",
):
    return {
        "pid": pid,
        "create_time": create_time,
        "platform": platform,
        "name": "python.exe",
        "status": "running",
        "username": "user",
        "executable": "C:/Python/python.exe",
        "cmdline": ["python", "app.py"],
        "parent_pid": 50,
        "threads": 4,
        "memory_rss_bytes": 1024,
        "memory_vms_bytes": 2048,
        "platform_details": {"io_read_bytes": 100},
    }


def create_scan(repository, failures_count=0):
    return repository.create_monitoring_scan(
        observed_at="2026-11-11T00:00:00+00:00",
        enumeration_complete=True,
        scan_complete=True,
        processes_collected=1,
        failures_count=failures_count,
    )


def make_connection():
    return {
        "family": "AF_INET",
        "type": "SOCK_STREAM",
        "local_address": {"ip": "127.0.0.1", "port": 5000},
        "remote_address": {"ip": "127.0.0.1", "port": 8000},
        "status": "ESTABLISHED",
    }


def test_get_or_create_process_instance_creates_record(repository):
    process = make_process()

    instance_id = repository.get_or_create_process_instance(process)

    row = repository.connection.execute(
        "SELECT * FROM process_instances WHERE id = ?",
        (instance_id,),
    ).fetchone()

    assert row["pid"] == 100
    assert row["create_time"] == 1000.0
    assert row["identity_type"] == "strong"
    assert row["identity_key"] == "100:1000"


def test_get_or_create_process_instance_reuses_strong_identity(repository):
    process = make_process()

    first_id = repository.get_or_create_process_instance(process)
    second_id = repository.get_or_create_process_instance(process)

    assert first_id == second_id

    count = repository.connection.execute(
        "SELECT COUNT(*) FROM process_instances"
    ).fetchone()[0]

    assert count == 1


def test_different_creation_time_creates_new_instance(repository):
    first_id = repository.get_or_create_process_instance(
        make_process(create_time=1000.0)
    )
    second_id = repository.get_or_create_process_instance(
        make_process(create_time=2000.0)
    )

    assert first_id != second_id


def test_platform_special_identity_is_reused(repository):
    process = make_process(pid=4, create_time=None)
    process["identity_type"] = "platform_special"
    process["identity_key"] = "windows:System"

    first_id = repository.get_or_create_process_instance(process)
    second_id = repository.get_or_create_process_instance(process)

    assert first_id == second_id


def test_weak_identity_requires_scan_id(repository):
    process = make_process(create_time=None)

    with pytest.raises(ValueError, match="scan_id"):
        repository.get_or_create_process_instance(process)


def test_weak_identity_is_unique_per_scan(repository):
    process = make_process(create_time=None)

    first_scan_id = create_scan(repository)
    second_scan_id = create_scan(repository)

    first_id = repository.get_or_create_process_instance(
        process,
        scan_id=first_scan_id,
    )
    second_id = repository.get_or_create_process_instance(
        process,
        scan_id=second_scan_id,
    )

    assert first_id != second_id

def test_save_process_observation(repository):
    process = make_process()
    process["working_directory"] = "C:/Projects"
    process["executable_metadata"] = {
        "size_bytes": 4096,
        "created_at": 1700000000.0,
        "modified_at": 1700000100.0,
        "accessed_at": 1700000200.0,
    }

    instance_id = repository.get_or_create_process_instance(process)

    observation_id = repository.save_process_observation(
        instance_id,
        process,
        "2026-11-11T00:00:00+00:00",
    )

    row = repository.connection.execute(
        "SELECT * FROM process_observations WHERE id = ?",
        (observation_id,),
    ).fetchone()

    assert row["process_instance_id"] == instance_id
    assert row["create_time"] == 1000.0
    assert row["name"] == "python.exe"
    assert json.loads(row["cmdline"]) == ["python", "app.py"]
    assert json.loads(row["platform_details"]) == {"io_read_bytes": 100}
    assert row["working_directory"] == "C:/Projects"
    assert json.loads(row["executable_metadata"]) == {
        "size_bytes": 4096,
        "created_at": 1700000000.0,
        "modified_at": 1700000100.0,
        "accessed_at": 1700000200.0,
    }



@pytest.mark.parametrize("create_time", [0, None])
def test_save_process_observation_normalizes_invalid_create_time(
    repository,
    create_time,
):
    process = make_process(create_time=create_time)

    scan_id = create_scan(repository)

    process_instance_id = repository.get_or_create_process_instance(
        process,
        scan_id=scan_id,
    )

    repository.save_process_observation(
        process_instance_id,
        process,
        "2026-11-11T12:00:00+00:00",
    )

    row = repository.connection.execute(
        """
        SELECT create_time
        FROM process_observations
        WHERE process_instance_id = ?
        """,
        (process_instance_id,),
    ).fetchone()

    assert row["create_time"] is None


def test_save_process_observation_handles_missing_execution_information(
    repository,
):
    process = make_process()
    instance_id = repository.get_or_create_process_instance(process)

    observation_id = repository.save_process_observation(
        instance_id,
        process,
        "2026-11-11T00:00:00+00:00",
    )

    row = repository.connection.execute(
        "SELECT * FROM process_observations WHERE id = ?",
        (observation_id,),
    ).fetchone()

    assert row["working_directory"] is None
    assert row["executable_metadata"] is None

def test_save_process_event(repository):
    process = make_process()
    instance_id = repository.get_or_create_process_instance(process)

    event_id = repository.save_process_event(
        instance_id,
        {
            "event_type": "process_first_seen",
            "observed_at": "2026-11-11T00:00:00+00:00",
        },
    )

    row = repository.connection.execute(
        "SELECT * FROM process_events WHERE id = ?",
        (event_id,),
    ).fetchone()

    assert row["process_instance_id"] == instance_id
    assert row["event_type"] == "process_first_seen"


def test_save_network_observations(repository):
    process = make_process()
    instance_id = repository.get_or_create_process_instance(process)

    ids = repository.save_network_observations(
        instance_id,
        [make_connection()],
        "2026-11-11T00:00:00+00:00",
    )

    row = repository.connection.execute(
        "SELECT * FROM network_observations WHERE id = ?",
        (ids[0],),
    ).fetchone()

    assert row["local_ip"] == "127.0.0.1"
    assert row["local_port"] == 5000
    assert row["remote_port"] == 8000
    assert row["status"] == "ESTABLISHED"


def test_network_observation_handles_missing_remote_address(repository):
    process = make_process()
    instance_id = repository.get_or_create_process_instance(process)

    connection = make_connection()
    connection["remote_address"] = None

    ids = repository.save_network_observations(
        instance_id,
        [connection],
        "2026-11-11T00:00:00+00:00",
    )

    row = repository.connection.execute(
        "SELECT * FROM network_observations WHERE id = ?",
        (ids[0],),
    ).fetchone()

    assert row["remote_ip"] is None
    assert row["remote_port"] is None


def test_save_network_observations_handles_empty_list(repository):
    process = make_process()
    instance_id = repository.get_or_create_process_instance(process)

    ids = repository.save_network_observations(
        instance_id,
        [],
        "2026-11-11T00:00:00+00:00",
    )

    assert ids == []


def test_create_monitoring_scan(repository):
    scan_id = create_scan(repository, failures_count=2)

    row = repository.connection.execute(
        "SELECT * FROM monitoring_scans WHERE id = ?",
        (scan_id,),
    ).fetchone()

    assert row["enumeration_complete"] == 1
    assert row["scan_complete"] == 1
    assert row["processes_collected"] == 1
    assert row["failures_count"] == 2


def test_create_monitoring_scan_rejects_invalid_counts(repository):
    with pytest.raises(ValueError):
        repository.create_monitoring_scan(
            "2026-11-11T00:00:00+00:00",
            True,
            True,
            -1,
        )


def test_save_inspection_failure(repository):
    scan_id = create_scan(repository)

    failure_id = repository.save_inspection_failure(
        scan_id,
        {
            "pid": 100,
            "stage": "process_inspection",
            "error_type": "AccessDenied",
            "error_message": "Access denied",
        },
        "2026-11-11T00:00:00+00:00",
    )

    row = repository.connection.execute(
        "SELECT * FROM process_inspection_failures WHERE id = ?",
        (failure_id,),
    ).fetchone()

    assert row["scan_id"] == scan_id
    assert row["pid"] == 100
    assert row["stage"] == "process_inspection"
    assert row["error_type"] == "AccessDenied"


def test_save_inspection_failure_can_reference_process(repository):
    scan_id = create_scan(repository)
    process = make_process()
    instance_id = repository.get_or_create_process_instance(process)

    failure_id = repository.save_inspection_failure(
        scan_id,
        {
            "pid": 100,
            "stage": "network_collection",
            "error_type": "AccessDenied",
        },
        "2026-11-11T00:00:00+00:00",
        process_instance_id=instance_id,
    )

    row = repository.connection.execute(
        "SELECT * FROM process_inspection_failures WHERE id = ?",
        (failure_id,),
    ).fetchone()

    assert row["process_instance_id"] == instance_id


def test_repository_does_not_commit_implicitly(repository):
    process = make_process()
    repository.get_or_create_process_instance(process)

    assert repository.connection.in_transaction

    repository.connection.rollback()

    count = repository.connection.execute(
        "SELECT COUNT(*) FROM process_instances"
    ).fetchone()[0]

    assert count == 0


def test_repository_rejects_invalid_event_type(repository):
    process = make_process()
    instance_id = repository.get_or_create_process_instance(process)

    with pytest.raises(sqlite3.IntegrityError):
        repository.save_process_event(
            instance_id,
            {
                "event_type": "invalid_event",
                "observed_at": "2026-11-11T00:00:00+00:00",
            },
        )
