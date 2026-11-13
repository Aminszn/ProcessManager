
import math
from datetime import datetime, timezone


class ProcessTracker:
    """
    Track process appearances and disappearances across monitoring scans.

    Strong identity uses PID + creation time.
    Platform-special identity uses an explicit OS-defined identity key.
    Weak PID-only observations are accepted but do not generate lifecycle events.
    """

    def __init__(self):
        self._active_processes = {}

    @staticmethod
    def _get_identity(process):
        pid = process.get("pid")

        if isinstance(pid, bool) or not isinstance(pid, int) or pid < 0:
            raise ValueError("Process PID must be a non-negative integer")

        identity_type = process.get("identity_type")
        create_time = process.get("create_time")

        if identity_type == "platform_special":
            identity_key = process.get("identity_key")
            platform = process.get("platform")

            if not isinstance(identity_key, str) or not identity_key.strip():
                raise ValueError(
                    "Platform-special processes require an identity_key"
                )

            if not isinstance(platform, str) or not platform.strip():
                raise ValueError(
                    "Platform-special processes require a platform"
                )

            return (
                "platform_special",
                platform,
                identity_key,
            )

        if identity_type not in (None, "strong", "weak_pid"):
            raise ValueError(f"Unsupported identity type: {identity_type}")

        if (
            not isinstance(create_time, bool)
            and isinstance(create_time, (int, float))
            and math.isfinite(create_time)
            and create_time > 0
        ):
            return ("strong", pid, float(create_time))

        # PID-only identity is deliberately not used for lifecycle tracking.
        return ("weak_pid", pid)

    def update(
        self,
        processes: list[dict],
        observed_at: datetime | None = None,
        scan_complete: bool = True,
    ) -> list[dict]:
        """
        Compare the current scan with the previous scan.

        An incomplete scan cannot establish that an unobserved process
        has disappeared.

        Weak PID-only observations are accepted but do not produce
        first-seen or disappeared events.
        """

        if not isinstance(scan_complete, bool):
            raise ValueError("scan_complete must be a boolean")

        if observed_at is None:
            observed_at = datetime.now(timezone.utc)

        if observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")

        observed_at = observed_at.astimezone(timezone.utc)
        timestamp = observed_at.isoformat()

        current_processes = {}
        events = []

        for process in processes:
            if not isinstance(process, dict):
                raise ValueError("Each process must be a dictionary")

            identity = self._get_identity(process)

            if identity in current_processes:
                raise ValueError(f"Duplicate process identity: {identity}")

            current_processes[identity] = process.copy()

        # Weak identities are observations only, not lifecycle identities.
        trackable_processes = {
            identity: process
            for identity, process in current_processes.items()
            if identity[0] != "weak_pid"
        }

        for identity, process in trackable_processes.items():
            if identity not in self._active_processes:
                events.append({
                    "event_type": "process_first_seen",
                    "pid": process["pid"],
                    "create_time": process.get("create_time"),
                    "identity_type": identity[0],
                    "identity_key": (
                        identity[2]
                        if identity[0] == "platform_special"
                        else None
                    ),
                    "observed_at": timestamp,
                    "process": process,
                })

        if scan_complete:
            for identity, process in self._active_processes.items():
                if identity not in trackable_processes:
                    events.append({
                        "event_type": "process_disappeared",
                        "pid": process["pid"],
                        "create_time": process.get("create_time"),
                        "identity_type": identity[0],
                        "identity_key": (
                            identity[2]
                            if identity[0] == "platform_special"
                            else None
                        ),
                        "observed_at": timestamp,
                        "process": process,
                    })

            self._active_processes = trackable_processes
        else:
            # Retain previously active processes until a complete scan
            # can establish whether they have actually disappeared.
            self._active_processes.update(trackable_processes)

        return events
