
def initialize_database(connection):
    """Create the Process Monitor database schema."""

    statements = [
        """
        CREATE TABLE IF NOT EXISTS process_instances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pid INTEGER NOT NULL CHECK (pid >= 0),
            create_time REAL CHECK (
                create_time IS NULL OR create_time > 0
            ),
            platform TEXT NOT NULL CHECK (
                platform IN ('linux', 'windows')
            ),
            identity_type TEXT NOT NULL CHECK (
                identity_type IN (
                    'strong',
                    'platform_special',
                    'weak_pid'
                )
            ),
            identity_key TEXT NOT NULL,
            UNIQUE (platform, identity_type, identity_key)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS process_observations (
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
            platform_details TEXT,
            FOREIGN KEY (process_instance_id)
                REFERENCES process_instances(id)
                ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS process_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            process_instance_id INTEGER NOT NULL,
            event_type TEXT NOT NULL CHECK (
                event_type IN (
                    'process_first_seen',
                    'process_disappeared'
                )
            ),
            observed_at TEXT NOT NULL,
            FOREIGN KEY (process_instance_id)
                REFERENCES process_instances(id)
                ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS network_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            process_instance_id INTEGER NOT NULL,
            observed_at TEXT NOT NULL,
            family TEXT,
            type TEXT,
            local_ip TEXT,
            local_port INTEGER,
            remote_ip TEXT,
            remote_port INTEGER,
            status TEXT,
            FOREIGN KEY (process_instance_id)
                REFERENCES process_instances(id)
                ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS monitoring_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            observed_at TEXT NOT NULL,
            enumeration_complete INTEGER NOT NULL
                CHECK (enumeration_complete IN (0, 1)),
            scan_complete INTEGER NOT NULL
                CHECK (scan_complete IN (0, 1)),
            processes_collected INTEGER NOT NULL DEFAULT 0
                CHECK (processes_collected >= 0),
            failures_count INTEGER NOT NULL DEFAULT 0
                CHECK (failures_count >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS process_inspection_failures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            process_instance_id INTEGER,
            pid INTEGER CHECK (pid IS NULL OR pid >= 0),
            stage TEXT NOT NULL,
            error_type TEXT NOT NULL,
            error_message TEXT,
            observed_at TEXT NOT NULL,
            FOREIGN KEY (scan_id)
                REFERENCES monitoring_scans(id)
                ON DELETE CASCADE,
            FOREIGN KEY (process_instance_id)
                REFERENCES process_instances(id)
                ON DELETE SET NULL
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_process_observations_instance_time
        ON process_observations(process_instance_id, observed_at)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_process_events_instance_time
        ON process_events(process_instance_id, observed_at)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_network_observations_instance_time
        ON network_observations(process_instance_id, observed_at)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_process_instances_pid
        ON process_instances(pid)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_monitoring_scans_observed_at
        ON monitoring_scans(observed_at)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_inspection_failures_scan_time
        ON process_inspection_failures(scan_id, observed_at)
        """,
    ]

    for statement in statements:
        connection.execute(statement)

    current_version = connection.execute(
        "PRAGMA user_version"
    ).fetchone()[0]

    if current_version > 3:
        raise RuntimeError(
            f"Database version {current_version} is newer than "
            "the supported version 3."
        )

    if current_version < 3:
        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(process_observations)"
            ).fetchall()
        }

        if "working_directory" not in columns:
            connection.execute(
                """
                ALTER TABLE process_observations
                ADD COLUMN working_directory TEXT
                """
            )

        if "executable_metadata" not in columns:
            connection.execute(
                """
                ALTER TABLE process_observations
                ADD COLUMN executable_metadata TEXT
                """
            )

        connection.execute("PRAGMA user_version = 3")