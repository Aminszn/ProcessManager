
from copy import deepcopy
from datetime import datetime, timezone
from threading import Event

import psutil

from collectors.process_collector import collect_process
from collectors.network_collector import (
    NetworkCollectionUnsupported,
    collect_process_network,
)
from database.repository import ProcessRepository
from monitoring.process_tracker import ProcessTracker


class MonitoringService:
    """Coordinate process monitoring and optional database persistence."""

    def __init__(
        self,
        repository: ProcessRepository,
        tracker: ProcessTracker | None = None,
    ):
        self.repository = repository
        self.tracker = tracker or ProcessTracker()

    @staticmethod
    def _make_failure(pid, stage, error):
        return {
            "pid": pid,
            "stage": stage,
            "error_type": type(error).__name__,
            "error_message": str(error),
        }

    def run_scan(
        self,
        observed_at: datetime | None = None,
        persist: bool = True,
        stop_event: Event | None = None,
    ) -> dict:
        if not isinstance(persist, bool):
            raise ValueError("persist must be a boolean")

        if observed_at is None:
            observed_at = datetime.now(timezone.utc)

        if not isinstance(observed_at, datetime):
            raise ValueError("observed_at must be a datetime")

        if (
            observed_at.tzinfo is None
            or observed_at.utcoffset() is None
        ):
            raise ValueError("observed_at must be timezone-aware")

        observed_at = observed_at.astimezone(timezone.utc)
        timestamp = observed_at.isoformat()

        processes = []
        network_data = {}
        failures = []

        enumeration_complete = True
        process_inspection_complete = True

        # Enumerate processes using psutil's process iterator.
        try:
            for process_handle in psutil.process_iter():

                if stop_event is not None and stop_event.is_set():
                    enumeration_complete = False
                    break
                
                try:
                    pid = process_handle.pid

                except (psutil.NoSuchProcess, psutil.AccessDenied) as error:
                    process_inspection_complete = False
                    failures.append(
                        self._make_failure(
                            None,
                            "process_enumeration",
                            error,
                        )
                    )
                    continue

                if (
                    isinstance(pid, bool)
                    or not isinstance(pid, int)
                    or pid < 0
                ):
                    process_inspection_complete = False
                    failures.append(
                        {
                            "pid": None,
                            "stage": "process_enumeration",
                            "error_type": "InvalidPID",
                            "error_message": f"Invalid process PID: {pid!r}",
                        }
                    )
                    continue

                # Collect process metadata.
                try:
                    process = collect_process(pid)

                except (psutil.NoSuchProcess, psutil.AccessDenied) as error:
                    process_inspection_complete = False
                    failures.append(
                        self._make_failure(
                            pid,
                            "process_inspection",
                            error,
                        )
                    )
                    continue

                processes.append(process)

                # Collect network information independently.
                try:
                    connections = collect_process_network(pid)

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    NetworkCollectionUnsupported,
                ) as error:
                    connections = []
                    failures.append(
                        self._make_failure(
                            pid,
                            "network_collection",
                            error,
                        )
                    )

                network_data[pid] = connections

        except (psutil.NoSuchProcess, psutil.AccessDenied) as error:
            enumeration_complete = False
            failures.append(
                self._make_failure(
                    None,
                    "process_enumeration",
                    error,
                )
            )

        scan_complete = (
            enumeration_complete and process_inspection_complete
        )

        # Work on a copy so failed persistence does not advance tracker state.
        next_tracker = deepcopy(self.tracker)

        events = next_tracker.update(
            processes,
            observed_at=observed_at,
            scan_complete=scan_complete,
        )

        scan_id = None

        # Persist only when database recording is enabled.
        if persist:
            connection = self.repository.connection

            try:
                scan_id = self.repository.create_monitoring_scan(
                    observed_at=timestamp,
                    enumeration_complete=enumeration_complete,
                    scan_complete=scan_complete,
                    processes_collected=len(processes),
                    failures_count=len(failures),
                )

                for process in processes:
                    instance_id = (
                        self.repository.get_or_create_process_instance(
                            process,
                            scan_id=scan_id,
                        )
                    )

                    self.repository.save_process_observation(
                        instance_id,
                        process,
                        timestamp,
                    )

                    self.repository.save_network_observations(
                        instance_id,
                        network_data.get(process["pid"], []),
                        timestamp,
                    )

                for event in events:
                    process = event["process"]

                    instance_id = (
                        self.repository.get_or_create_process_instance(
                            process,
                            scan_id=scan_id,
                        )
                    )

                    self.repository.save_process_event(
                        instance_id,
                        event,
                    )

                for failure in failures:
                    self.repository.save_inspection_failure(
                        scan_id,
                        failure,
                        timestamp,
                    )

                connection.commit()

            except Exception:
                connection.rollback()
                raise

        # Advance tracker state after successful collection and persistence.
        self.tracker = next_tracker

        process_views = [
            {
                **process,
                "network_connections": network_data.get(
                    process["pid"],
                    [],
                ),
            }
            for process in processes
        ]

        return {
            "scan_id": scan_id,
            "observed_at": timestamp,
            "persisted": persist,
            "enumeration_complete": enumeration_complete,
            "scan_complete": scan_complete,
            "processes_collected": len(processes),
            "network_connections_collected": sum(
                len(connections)
                for connections in network_data.values()
            ),
            "failures_count": len(failures),
            "inspection_failures": failures,
            "events_detected": len(events),
            "events": events,
            "processes": process_views,
        }
