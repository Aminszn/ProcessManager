
import time
from collections.abc import Callable
from threading import Event

from config.settings import DEFAULT_POLL_INTERVAL
from monitoring.monitoring_service import MonitoringService


class MonitoringLoop:
    """Run continuous process monitoring at a fixed polling interval."""

    def __init__(
        self,
        service: MonitoringService,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
    ):
        if (
            isinstance(poll_interval, bool)
            or not isinstance(poll_interval, (int, float))
            or poll_interval <= 0
        ):
            raise ValueError("poll_interval must be a positive number")

        self.service = service
        self.poll_interval = float(poll_interval)

    def run(
        self,
        stop_event: Event,
        is_recording: Callable[[], bool],
        on_scan: Callable[[dict], None] | None = None,
    ) -> None:
        """Continuously scan until stop_event is set."""

        next_scan_at = time.monotonic()

        while not stop_event.is_set():
            result = self.service.run_scan(
                persist=is_recording(),
                stop_event=stop_event,
            )

            if on_scan is not None:
                on_scan(result)

            if stop_event.is_set():
                break

            next_scan_at += self.poll_interval

            delay = next_scan_at - time.monotonic()

            if delay > 0:
                stop_event.wait(delay)
            else:
                # Avoid back-to-back scans if collection takes too long.
                next_scan_at = time.monotonic()
