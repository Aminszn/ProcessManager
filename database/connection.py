
import sqlite3
from pathlib import Path

from config.settings import DATABASE_PATH


def get_connection(
    database_path: str | Path = DATABASE_PATH,
) -> sqlite3.Connection:
    """
    Create and configure a SQLite database connection.

    Args:
        database_path: Database file path or ':memory:'.

    Returns:
        A configured SQLite connection.
    """

    database_path = str(database_path)

    if database_path != ":memory:":
        Path(database_path).parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    connection = sqlite3.connect(
        database_path,
        timeout=5.0,
    )

    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")

    return connection
