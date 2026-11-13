
import json
import math


class ProcessRepository:
    def __init__(self, connection):
        self.connection = connection

    @staticmethod
    def _get_identity(process, scan_id=None):
        pid = process.get("pid")

        if isinstance(pid, bool) or not isinstance(pid, int) or pid < 0:
            raise ValueError("Process PID must be a non-negative integer")

        platform = process.get("platform")

        if not isinstance(platform, str) or not platform.strip():
            raise ValueError("Process platform is required")

        identity_type = process.get("identity_type")
        create_time = process.get("create_time")

        if identity_type == "platform_special":
            identity_key = process.get("identity_key")

            if not isinstance(identity_key, str) or not identity_key.strip():
                raise ValueError(
                    "Platform-special processes require an identity_key"
                )

            if (
                not isinstance(create_time, bool)
                and isinstance(create_time, (int, float))
                and math.isfinite(create_time)
                and create_time > 0
            ):
                normalized_create_time = float(create_time)
            else:
                normalized_create_time = None

            return {
                "pid": pid,
                "create_time": normalized_create_time,
                "platform": platform,
                "identity_type": "platform_special",
                "identity_key": identity_key,
            }

        if identity_type not in (None, "strong", "weak_pid"):
            raise ValueError(f"Unsupported identity type: {identity_type}")

        if (
            not isinstance(create_time, bool)
            and isinstance(create_time, (int, float))
            and math.isfinite(create_time)
            and create_time > 0
        ):
            return {
                "pid": pid,
                "create_time": float(create_time),
                "platform": platform,
                "identity_type": "strong",
                "identity_key": f"{pid}:{float(create_time):.17g}",
            }

        if (
            isinstance(scan_id, bool)
            or not isinstance(scan_id, int)
            or scan_id <= 0
        ):
            raise ValueError(
                "A valid scan_id is required for weak process identities"
            )

        return {
            "pid": pid,
            "create_time": None,
            "platform": platform,
            "identity_type": "weak_pid",
            "identity_key": f"scan:{scan_id}:pid:{pid}",
        }

    def get_or_create_process_instance(self, process, scan_id=None):
        identity = self._get_identity(process, scan_id=scan_id)

        self.connection.execute(
            """
            INSERT OR IGNORE INTO process_instances (
                pid,
                create_time,
                platform,
                identity_type,
                identity_key
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                identity["pid"],
                identity["create_time"],
                identity["platform"],
                identity["identity_type"],
                identity["identity_key"],
            ),
        )

        row = self.connection.execute(
            """
            SELECT id
            FROM process_instances
            WHERE platform = ?
              AND identity_type = ?
              AND identity_key = ?
            """,
            (
                identity["platform"],
                identity["identity_type"],
                identity["identity_key"],
            ),
        ).fetchone()

        return row["id"]
    
    def save_process_observation(
        self,
        process_instance_id,
        process,
        observed_at,
    ):
        executable_metadata = process.get("executable_metadata")

        if executable_metadata is not None:
            executable_metadata = json.dumps(executable_metadata)

        create_time = process.get("create_time")

        if (
            isinstance(create_time, bool)
            or not isinstance(create_time, (int, float))
            or not math.isfinite(create_time)
            or create_time <= 0
        ):
            create_time = None

        cursor = self.connection.execute(
            """
            INSERT INTO process_observations (
                process_instance_id,
                observed_at,
                create_time,
                name,
                status,
                username,
                executable,
                cmdline,
                parent_pid,
                threads,
                memory_rss_bytes,
                memory_vms_bytes,
                platform_details,
                working_directory,
                executable_metadata
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                process_instance_id,
                observed_at,
                create_time,
                process.get("name"),
                process.get("status"),
                process.get("username"),
                process.get("executable"),
                json.dumps(process.get("cmdline")),
                process.get("parent_pid"),
                process.get("threads"),
                process.get("memory_rss_bytes"),
                process.get("memory_vms_bytes"),
                json.dumps(process.get("platform_details", {})),
                process.get("working_directory"),
                executable_metadata,
            ),
        )

        return cursor.lastrowid

    def save_process_event(self, process_instance_id, event):
        cursor = self.connection.execute(
            """
            INSERT INTO process_events (
                process_instance_id,
                event_type,
                observed_at
            )
            VALUES (?, ?, ?)
            """,
            (
                process_instance_id,
                event["event_type"],
                event["observed_at"],
            ),
        )

        return cursor.lastrowid

    def save_network_observations(
        self,
        process_instance_id,
        connections,
        observed_at,
    ):
        inserted_ids = []

        for connection in connections:
            local_address = connection.get("local_address") or {}
            remote_address = connection.get("remote_address") or {}

            cursor = self.connection.execute(
                """
                INSERT INTO network_observations (
                    process_instance_id,
                    observed_at,
                    family,
                    type,
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    process_instance_id,
                    observed_at,
                    connection.get("family"),
                    connection.get("type"),
                    local_address.get("ip"),
                    local_address.get("port"),
                    remote_address.get("ip"),
                    remote_address.get("port"),
                    connection.get("status"),
                ),
            )

            inserted_ids.append(cursor.lastrowid)

        return inserted_ids

    def create_monitoring_scan(
        self,
        observed_at,
        enumeration_complete,
        scan_complete,
        processes_collected,
        failures_count=0,
    ):
        if not isinstance(enumeration_complete, bool):
            raise ValueError("enumeration_complete must be a boolean")

        if not isinstance(scan_complete, bool):
            raise ValueError("scan_complete must be a boolean")

        if (
            isinstance(processes_collected, bool)
            or not isinstance(processes_collected, int)
            or processes_collected < 0
        ):
            raise ValueError("processes_collected must be a non-negative integer")

        if (
            isinstance(failures_count, bool)
            or not isinstance(failures_count, int)
            or failures_count < 0
        ):
            raise ValueError("failures_count must be a non-negative integer")

        cursor = self.connection.execute(
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
            (
                observed_at,
                int(enumeration_complete),
                int(scan_complete),
                processes_collected,
                failures_count,
            ),
        )

        return cursor.lastrowid

    def save_inspection_failure(
        self,
        scan_id,
        failure,
        observed_at,
        process_instance_id=None,
    ):
        pid = failure.get("pid")

        if pid is not None and (
            isinstance(pid, bool)
            or not isinstance(pid, int)
            or pid < 0
        ):
            raise ValueError("Failure PID must be a non-negative integer or None")

        cursor = self.connection.execute(
            """
            INSERT INTO process_inspection_failures (
                scan_id,
                process_instance_id,
                pid,
                stage,
                error_type,
                error_message,
                observed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                process_instance_id,
                pid,
                failure["stage"],
                failure["error_type"],
                failure.get("error_message"),
                observed_at,
            ),
        )

        return cursor.lastrowid
