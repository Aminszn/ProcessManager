
import sqlite3

from database.connection import get_connection


def test_creates_database_file(tmp_path):
    database_path = tmp_path / "data" / "test.db"

    connection = get_connection(database_path)

    assert database_path.exists()

    connection.close()


def test_creates_missing_parent_directories(tmp_path):
    database_path = (
        tmp_path / "nested" / "data" / "test.db"
    )

    connection = get_connection(database_path)

    assert database_path.parent.exists()
    assert database_path.exists()

    connection.close()


def test_uses_sqlite_row_factory():
    connection = get_connection(":memory:")

    assert connection.row_factory is sqlite3.Row

    connection.close()


def test_enables_foreign_keys():
    connection = get_connection(":memory:")

    result = connection.execute(
        "PRAGMA foreign_keys"
    ).fetchone()[0]

    assert result == 1

    connection.close()


def test_configures_busy_timeout():
    connection = get_connection(":memory:")

    result = connection.execute(
        "PRAGMA busy_timeout"
    ).fetchone()[0]

    assert result == 5000

    connection.close()
