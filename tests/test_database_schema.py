
import sqlite3

import pytest

from database.connection import get_connection
from database.schema import initialize_database


@pytest.fixture
def connection():
    conn = get_connection(":memory:")
    initialize_database(conn)

    yield conn

    conn.close()


def insert_process_instance(
    connection,
    pid=100,
    create_time=1000.0,
    platform="windows",
    identity_type="strong",
    identity_key="100:1000",
):
    cursor = connection.execute(
        """
        INSERT INTO process_instances (
            pid,
            create_time,
            platform,
            identity_type,
            identity_key
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            pid,
            create_time,
            platform,
            identity_type,
            identity_key,
        ),
    )
    return cursor.lastrowid


def test_schema_creates_all_tables(connection):
    rows = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        """
    ).fetchall()

    table_names = {row["name"] for row in rows}

    assert {
        "process_instances",
        "process_observations",
        "process_events",
        "network_observations",
        "monitoring_scans",
        "process_inspection_failures",
    }.issubset(table_names)


def test_schema_creates_indexes(connection):
    rows = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'index'
        """
    ).fetchall()

    index_names = {row["name"] for row in rows}

    assert {
        "idx_process_observations_instance_time",
        "idx_process_events_instance_time",
        "idx_network_observations_instance_time",
        "idx_process_instances_pid",
        "idx_monitoring_scans_observed_at",
        "idx_inspection_failures_scan_time",
    }.issubset(index_names)


def test_process_instance_accepts_strong_identity(connection):
    instance_id = insert_process_instance(connection)

    row = connection.execute(
        """
        SELECT *
        FROM process_instances
        WHERE id = ?
        """,
        (instance_id,),
    ).fetchone()

    assert row["pid"] == 100
    assert row["create_time"] == 1000.0
    assert row["identity_type"] == "strong"


def test_process_instance_accepts_platform_special_identity(connection):
    instance_id = insert_process_instance(
        connection,
        pid=4,
        create_time=None,
        identity_type="platform_special",
        identity_key="windows:System",
    )

    row = connection.execute(
        "SELECT * FROM process_instances WHERE id = ?",
        (instance_id,),
    ).fetchone()

    assert row["pid"] == 4
    assert row["create_time"] is None
    assert row["identity_type"] == "platform_special"


def test_process_instance_accepts_weak_pid_identity(connection):
    instance_id = insert_process_instance(
        connection,
        pid=200,
        create_time=None,
        identity_type="weak_pid",
        identity_key="scan-1:pid-200",
    )

    row = connection.execute(
        "SELECT * FROM process_instances WHERE id = ?",
        (instance_id,),
    ).fetchone()

    assert row["identity_type"] == "weak_pid"
    assert row["create_time"] is None


def test_process_instance_rejects_duplicate_identity(connection):
    insert_process_instance(connection)

    with pytest.raises(sqlite3.IntegrityError):
        insert_process_instance(connection)


def test_process_instance_allows_pid_reuse_with_different_identity(connection):
    first_id = insert_process_instance(
        connection,
        pid=100,
        create_time=1000.0,
        identity_key="100:1000",
    )

    second_id = insert_process_instance(
        connection,
        pid=100,
        create_time=2000.0,
        identity_key="100:2000",
    )

    assert first_id != second_id


@pytest.mark.parametrize("platform", ["invalid", "", "macos"])
def test_process_instance_rejects_invalid_platform(connection, platform):
    with pytest.raises(sqlite3.IntegrityError):
        insert_process_instance(connection, platform=platform)


@pytest.mark.parametrize(
    "identity_type",
    ["invalid", "", "unknown"],
)
def test_process_instance_rejects_invalid_identity_type(
    connection,
    identity_type,
):
    with pytest.raises(sqlite3.IntegrityError):
        insert_process_instance(
            connection,
            identity_type=identity_type,
        )


def test_process_instance_rejects_invalid_pid(connection):
    with pytest.raises(sqlite3.IntegrityError):
        insert_process_instance(connection, pid=-1)


def test_process_instance_rejects_nonpositive_creation_time(connection):
    with pytest.raises(sqlite3.IntegrityError):
        insert_process_instance(connection, create_time=0)


def test_observation_requires_existing_process_instance(connection):
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            """
            INSERT INTO process_observations (
                process_instance_id,
                observed_at
            )
            VALUES (?, ?)
            """,
            (999, "2026-11-11T00:00:00+00:00"),
        )


def test_observation_stores_creation_time(connection):
    instance_id = insert_process_instance(connection)

    connection.execute(
        """
        INSERT INTO process_observations (
            process_instance_id,
            observed_at,
            create_time
        )
        VALUES (?, ?, ?)
        """,
        (instance_id, "2026-11-11T00:00:00+00:00", 1000.0),
    )

    row = connection.execute(
        "SELECT create_time FROM process_observations"
    ).fetchone()

    assert row["create_time"] == 1000.0


def test_process_event_rejects_invalid_event_type(connection):
    instance_id = insert_process_instance(connection)

    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            """
            INSERT INTO process_events (
                process_instance_id,
                event_type,
                observed_at
            )
            VALUES (?, ?, ?)
            """,
            (
                instance_id,
                "invalid_event",
                "2026-11-11T00:00:00+00:00",
            ),
        )


def test_monitoring_scan_accepts_valid_record(connection):
    cursor = connection.execute(
        """
        INSERT INTO monitoring_scans (
            observed_at,
            enumeration_complete,
            scan_complete,
            processes_collected,
            failures_count
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        ("2026-11-11T00:00:00+00:00", 1, 1, 10, 0),
    )

    row = connection.execute(
        "SELECT * FROM monitoring_scans WHERE id = ?",
        (cursor.lastrowid,),
    ).fetchone()

    assert row["enumeration_complete"] == 1
    assert row["scan_complete"] == 1
    assert row["processes_collected"] == 10


def test_monitoring_scan_rejects_invalid_completion_flag(connection):
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            """
            INSERT INTO monitoring_scans (
                observed_at,
                enumeration_complete,
                scan_complete
            )
            VALUES (?, ?, ?)
            """,
            ("2026-11-11T00:00:00+00:00", 2, 1),
        )


def test_inspection_failure_requires_existing_scan(connection):
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            """
            INSERT INTO process_inspection_failures (
                scan_id,
                pid,
                stage,
                error_type,
                observed_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                999,
                100,
                "process_inspection",
                "AccessDenied",
                "2026-11-11T00:00:00+00:00",
            ),
        )


def test_initialize_database_is_idempotent(connection):
    initialize_database(connection)
    initialize_database(connection)

    rows = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        """
    ).fetchall()

    table_names = {row["name"] for row in rows}

    assert "process_instances" in table_names
    assert "monitoring_scans" in table_names
    assert "process_inspection_failures" in table_names


def test_database_schema_version_is_three(connection):
    version = connection.execute(
        "PRAGMA user_version"
    ).fetchone()[0]

    assert version == 3


def test_foreign_keys_are_enabled(connection):
    enabled = connection.execute(
        "PRAGMA foreign_keys"
    ).fetchone()[0]

    assert enabled == 1


def test_process_observations_contains_execution_information_columns(
    connection,
):
    rows = connection.execute(
        "PRAGMA table_info(process_observations)"
    ).fetchall()

    column_names = {row["name"] for row in rows}

    assert "working_directory" in column_names
    assert "executable_metadata" in column_names


def test_initialize_database_migrates_version_two_database():
    connection = get_connection(":memory:")

    try:
        connection.execute(
            """
            CREATE TABLE process_instances (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pid INTEGER NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE process_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_instance_id INTEGER NOT NULL,
                observed_at TEXT NOT NULL,
                create_time REAL,
                name TEXT,
                status TEXT,
                username TEXT,
                executable TEXT,
                cmdline TEXT,
                parent_pid INTEGER,
                threads INTEGER,
                memory_rss_bytes INTEGER,
                memory_vms_bytes INTEGER,
                platform_details TEXT
            )
            """
        )

        connection.execute(
            "INSERT INTO process_instances (pid) VALUES (?)",
            (1234,),
        )

        connection.execute(
            """
            INSERT INTO process_observations (
                process_instance_id,
                observed_at,
                name
            )
            VALUES (?, ?, ?)
            """,
            (1, "2026-11-11T00:00:00+00:00", "existing-process"),
        )

        connection.execute("PRAGMA user_version = 2")

        initialize_database(connection)

        version = connection.execute(
            "PRAGMA user_version"
        ).fetchone()[0]

        row = connection.execute(
            """
            SELECT name, working_directory, executable_metadata
            FROM process_observations
            WHERE id = 1
            """
        ).fetchone()

        assert version == 3
        assert row["name"] == "existing-process"
        assert row["working_directory"] is None
        assert row["executable_metadata"] is None

    finally:
        connection.close()
