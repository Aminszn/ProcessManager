
from datetime import datetime, timezone

import pytest

from monitoring.process_tracker import ProcessTracker


def make_process(pid=100, create_time=1000.0):
    return {
        "pid": pid,
        "name": "test-process",
        "status": "running",
        "username": "test-user",
        "create_time": create_time,
        "executable": "test.exe",
        "cmdline": ["test.exe"],
        "parent_pid": 1,
        "threads": 2,
        "memory_rss_bytes": 1024,
        "memory_vms_bytes": 2048,
        "platform": "windows",
        "platform_details": {},
    }


def make_special_process(pid, identity_key, name="System"):
    process = make_process(pid=pid, create_time=0.0)
    process.update({
        "name": name,
        "identity_type": "platform_special",
        "identity_key": identity_key,
    })
    return process


def test_first_scan_detects_new_process():
    tracker = ProcessTracker()
    events = tracker.update([make_process()])

    assert len(events) == 1
    assert events[0]["event_type"] == "process_first_seen"
    assert events[0]["pid"] == 100


def test_second_scan_does_not_duplicate_process_event():
    tracker = ProcessTracker()
    process = make_process()

    tracker.update([process])
    events = tracker.update([process])

    assert events == []


def test_disappeared_process_is_detected():
    tracker = ProcessTracker()
    process = make_process()

    tracker.update([process])
    events = tracker.update([])

    assert len(events) == 1
    assert events[0]["event_type"] == "process_disappeared"
    assert events[0]["pid"] == 100


def test_new_process_is_detected_after_disappearance():
    tracker = ProcessTracker()
    process = make_process()

    tracker.update([process])
    tracker.update([])
    events = tracker.update([process])

    assert len(events) == 1
    assert events[0]["event_type"] == "process_first_seen"


def test_pid_reuse_is_treated_as_a_new_process():
    tracker = ProcessTracker()

    original = make_process(pid=100, create_time=1000.0)
    replacement = make_process(pid=100, create_time=2000.0)

    tracker.update([original])
    events = tracker.update([replacement])

    assert len(events) == 2
    assert {event["event_type"] for event in events} == {
        "process_first_seen",
        "process_disappeared",
    }


def test_multiple_processes_are_tracked():
    tracker = ProcessTracker()

    processes = [
        make_process(pid=100),
        make_process(pid=200, create_time=2000.0),
    ]

    events = tracker.update(processes)

    assert len(events) == 2
    assert {event["pid"] for event in events} == {100, 200}


def test_observation_timestamp_is_utc():
    tracker = ProcessTracker()
    timestamp = datetime(
        2026, 11, 10, 12, 0, 0,
        tzinfo=timezone.utc,
    )

    events = tracker.update(
        [make_process()],
        observed_at=timestamp,
    )

    assert events[0]["observed_at"] == timestamp.isoformat()


def test_naive_timestamp_is_rejected():
    tracker = ProcessTracker()
    timestamp = datetime(2026, 11, 10, 12, 0, 0)

    with pytest.raises(ValueError):
        tracker.update([make_process()], observed_at=timestamp)


def test_invalid_pid_is_rejected():
    tracker = ProcessTracker()

    with pytest.raises(ValueError):
        tracker.update([make_process(pid=-1)])


def test_duplicate_process_identity_is_rejected():
    tracker = ProcessTracker()
    process = make_process()

    with pytest.raises(ValueError):
        tracker.update([process, process])


@pytest.mark.parametrize("create_time", [None, 0.0, -1.0, float("nan"), float("inf")])
def test_missing_or_invalid_creation_time_is_accepted_as_weak_identity(
    create_time,
):
    tracker = ProcessTracker()
    process = make_process(create_time=create_time)

    events = tracker.update([process])

    assert events == []


def test_weak_identity_does_not_generate_lifecycle_events():
    tracker = ProcessTracker()
    process = make_process(create_time=0.0)

    assert tracker.update([process]) == []
    assert tracker.update([process]) == []
    assert tracker.update([]) == []


@pytest.mark.parametrize(
    ("pid", "identity_key"),
    [
        (0, "windows:idle:0"),
        (4, "windows:system:4"),
    ],
)
def test_platform_special_process_is_tracked(pid, identity_key):
    tracker = ProcessTracker()
    process = make_special_process(pid, identity_key)

    events = tracker.update([process])

    assert len(events) == 1
    assert events[0]["event_type"] == "process_first_seen"
    assert events[0]["identity_type"] == "platform_special"
    assert events[0]["identity_key"] == identity_key


def test_platform_special_process_does_not_generate_duplicate_events():
    tracker = ProcessTracker()
    process = make_special_process(4, "windows:system:4")

    tracker.update([process])
    events = tracker.update([process])

    assert events == []


def test_platform_special_process_requires_identity_key():
    tracker = ProcessTracker()
    process = make_process(pid=4, create_time=0.0)
    process["identity_type"] = "platform_special"

    with pytest.raises(ValueError):
        tracker.update([process])


def test_incomplete_scan_does_not_report_disappearance():
    tracker = ProcessTracker()
    process = make_process()

    tracker.update([process])
    events = tracker.update([], scan_complete=False)

    assert events == []


def test_process_missing_from_incomplete_scan_remains_active():
    tracker = ProcessTracker()
    process = make_process()

    tracker.update([process])
    tracker.update([], scan_complete=False)

    events = tracker.update([process])

    assert events == []


def test_complete_scan_can_confirm_disappearance_after_incomplete_scan():
    tracker = ProcessTracker()
    process = make_process()

    tracker.update([process])
    tracker.update([], scan_complete=False)
    events = tracker.update([])

    assert len(events) == 1
    assert events[0]["event_type"] == "process_disappeared"


def test_scan_complete_must_be_boolean():
    tracker = ProcessTracker()

    with pytest.raises(ValueError):
        tracker.update([], scan_complete=1)
