
from threading import Event

import pytest

from monitoring.monitor import MonitoringLoop


class FakeMonitoringService:
    def __init__(self):
        self.scan_calls = []

    def run_scan(self, persist=True, stop_event=None):
        self.scan_calls.append(persist)

        return {
            "persisted": persist,
            "processes_collected": 2,
            "events_detected": 0,
        }


def test_monitoring_loop_runs_repeated_scans():
    service = FakeMonitoringService()
    loop = MonitoringLoop(service, poll_interval=0.001)
    stop_event = Event()

    def on_scan(result):
        if len(service.scan_calls) == 3:
            stop_event.set()

    loop.run(
        stop_event=stop_event,
        is_recording=lambda: False,
        on_scan=on_scan,
    )

    assert len(service.scan_calls) == 3
    assert service.scan_calls == [False, False, False]


def test_monitoring_loop_checks_recording_state_each_scan():
    service = FakeMonitoringService()
    loop = MonitoringLoop(service, poll_interval=0.001)
    stop_event = Event()

    recording_states = iter([False, True, False])

    def on_scan(result):
        if len(service.scan_calls) == 3:
            stop_event.set()

    loop.run(
        stop_event=stop_event,
        is_recording=lambda: next(recording_states),
        on_scan=on_scan,
    )

    assert service.scan_calls == [False, True, False]


def test_monitoring_loop_sends_results_to_callback():
    service = FakeMonitoringService()
    loop = MonitoringLoop(service, poll_interval=0.001)
    stop_event = Event()

    received_results = []

    def on_scan(result):
        received_results.append(result)
        stop_event.set()

    loop.run(
        stop_event=stop_event,
        is_recording=lambda: True,
        on_scan=on_scan,
    )

    assert len(received_results) == 1
    assert received_results[0]["persisted"] is True
    assert received_results[0]["processes_collected"] == 2


def test_monitoring_loop_stops_before_scanning():
    service = FakeMonitoringService()
    loop = MonitoringLoop(service, poll_interval=0.001)
    stop_event = Event()

    stop_event.set()

    loop.run(
        stop_event=stop_event,
        is_recording=lambda: False,
    )

    assert service.scan_calls == []


@pytest.mark.parametrize(
    "poll_interval",
    [0, -1, True, "1"],
)
def test_monitoring_loop_rejects_invalid_poll_interval(
    poll_interval,
):
    service = FakeMonitoringService()

    with pytest.raises(ValueError):
        MonitoringLoop(
            service,
            poll_interval=poll_interval,
        )

def test_monitoring_loop_interrupts_wait_when_stopped():
    service = FakeMonitoringService()
    loop = MonitoringLoop(service, poll_interval=60)
    stop_event = Event()

    def on_scan(result):
        stop_event.set()

    loop.run(
        stop_event=stop_event,
        is_recording=lambda: False,
        on_scan=on_scan,
    )

    assert len(service.scan_calls) == 1
    assert stop_event.is_set()


def test_monitoring_loop_propagates_callback_errors():
    service = FakeMonitoringService()
    loop = MonitoringLoop(service, poll_interval=0.001)
    stop_event = Event()

    def on_scan(result):
        raise RuntimeError("Callback failed")

    with pytest.raises(RuntimeError, match="Callback failed"):
        loop.run(
            stop_event=stop_event,
            is_recording=lambda: False,
            on_scan=on_scan,
        )

    assert len(service.scan_calls) == 1
