
from queue import Empty, Queue
from threading import Condition
from pathlib import Path

import cli.monitoring_controller as monitoring_controller_module

import pytest

from cli.monitoring_controller import MonitoringController


class FakeKeyboard:
    def __init__(self):
        self.keys = Queue()
        self.started = False
        self.stopped = False
        self.read_count = 0
        self.condition = Condition()

    def start(self):
        self.started = True

    def read_key(self):
        try:
            key = self.keys.get_nowait()
        except Empty:
            return None

        with self.condition:
            self.read_count += 1
            self.condition.notify_all()

        return key

    def press_key(self, key):
        self.keys.put(key)

    def wait_for_reads(self, count):
        with self.condition:
            return self.condition.wait_for(
                lambda: self.read_count >= count,
                timeout=2,
            )

    def stop(self):
        self.stopped = True



class FakeDashboard:
    def __init__(self):
        self.started = False
        self.stopped = False
        self.updates = []
        self.messages = []

    def start(self):
        self.started = True

    def update(self, result, recording_enabled=False):
        self.updates.append((result, recording_enabled))

    def display_message(self, message):
        self.messages.append(message)

    def stop(self):
        self.stopped = True



class FakeMonitoringLoop:
    def __init__(
        self,
        keyboard,
        keys=None,
        scan_count=1,
        fail=False,
    ):
        self.keyboard = keyboard
        self.keys = list(keys or [])
        self.scan_count = scan_count
        self.fail = fail
        self.recording_states = []

    def run(self, stop_event, is_recording, on_scan=None):
        expected_reads = 0

        for index in range(self.scan_count):
            if stop_event.is_set():
                break

            self.recording_states.append(is_recording())

            if on_scan:
                on_scan({"scan": index + 1})

            # Simulate a user pressing a key between scans.
            if self.keys:
                key = self.keys.pop(0)
                expected_reads += 1

                self.keyboard.press_key(key)

                if not self.keyboard.wait_for_reads(expected_reads):
                    raise AssertionError(
                        "Keyboard input was not processed in time"
                    )

        if self.fail:
            raise RuntimeError("Monitoring failed")


class FakeExecutableAcquirer:
    def __init__(self, result=None, error=None):
        self.result = result or {
            "status": "success",
            "executable_path": "evidence/acquisitions/test.exe",
            "manifest_path": "evidence/acquisitions/manifest.json",
            "sha256": "test-hash",
        }
        self.error = error
        self.acquired_processes = []

    def acquire(self, process):
        self.acquired_processes.append(process)

        if self.error:
            raise self.error

        return self.result

class FakeMemoryAcquirer:
    def __init__(self, result=None, error=None):
        self.result = result or {
            "success": True,
            "dump_path": "test.dmp",
            "sha256": "test-memory-hash",
            "manifest_path": "test-manifest.json",
        }
        self.error = error
        self.requests = []

    def execute(self, action, **parameters):
        self.requests.append({
            "action": action,
            **parameters,
        })

        if self.error:
            raise self.error

        return self.result


class FakeRegionMemoryAcquirer:
    def __init__(self, regions):
        self.regions = regions
        self.requests = []

    def execute(self, action, **parameters):
        self.requests.append({
            "action": action,
            **parameters,
        })

        if action == "list_memory_regions":
            return {
                "success": True,
                "action": action,
                "memory_region_details": self.regions,
            }

        if action == "inspect_memory":
            return {
                "success": True,
                "action": action,
                "message": "Memory inspection successful",
            }

        return {
            "success": False,
            "message": f"Unsupported action: {action}",
        }


def make_controller(keys=None, scan_count=1, fail=False):
    keyboard = FakeKeyboard()

    loop = FakeMonitoringLoop(
        keyboard=keyboard,
        keys=keys,
        scan_count=scan_count,
        fail=fail,
    )

    dashboard = FakeDashboard()

    controller = MonitoringController(
        monitoring_loop=loop,
        dashboard=dashboard,
        keyboard=keyboard,
    )

    return controller, loop, dashboard, keyboard


def test_run_starts_dashboard_and_keyboard():
    controller, loop, dashboard, keyboard = make_controller()

    controller.run()

    assert dashboard.started is True
    assert keyboard.started is True


def test_run_updates_dashboard_for_each_scan():
    controller, loop, dashboard, keyboard = make_controller(
        scan_count=3
    )

    controller.run()

    assert len(dashboard.updates) == 3


def test_recording_can_be_toggled_on_and_off():
    controller, loop, dashboard, keyboard = make_controller(
        keys=["r", "r"],
        scan_count=3,
    )

    controller.run()

    assert loop.recording_states == [False, True, False]

    statuses = [
        status
        for _, status in dashboard.updates
    ]

    assert statuses[0] is False
    assert True in statuses
    assert statuses[-1] is False


def test_q_stops_monitoring():
    controller, loop, dashboard, keyboard = make_controller(
        keys=["q"],
        scan_count=5,
    )

    controller.run()

    assert controller.stop_event.is_set()
    assert len(dashboard.updates) == 1

def test_interrupted_scan_does_not_replace_last_complete_dashboard():
    controller, loop, dashboard, keyboard = make_controller()

    class InterruptedMonitoringLoop:
        def run(self, stop_event, is_recording, on_scan=None):
            # First scan completes normally with 200 processes.
            on_scan({
                "processes": [{"pid": pid} for pid in range(200)]
            })

            # Simulate the user pressing Q during the next scan.
            keyboard.press_key("q")

            if not stop_event.wait(timeout=2):
                raise AssertionError("Quit command was not processed")

            # The interrupted scan returns only 148 processes.
            on_scan({
                "processes": [{"pid": pid} for pid in range(148)]
            })

    controller.monitoring_loop = InterruptedMonitoringLoop()

    controller.run()

    assert len(dashboard.updates) == 1

    displayed_result, recording_status = dashboard.updates[0]

    assert len(displayed_result["processes"]) == 200
    assert recording_status is False

def test_run_stops_dashboard_and_restores_keyboard():
    controller, loop, dashboard, keyboard = make_controller()

    controller.run()

    assert dashboard.stopped is True
    assert keyboard.stopped is True


def test_cleanup_runs_when_monitoring_fails():
    controller, loop, dashboard, keyboard = make_controller(
        fail=True
    )

    with pytest.raises(RuntimeError, match="Monitoring failed"):
        controller.run()

    assert dashboard.stopped is True
    assert keyboard.stopped is True


def test_keyboard_cleanup_runs_when_dashboard_start_fails():
    controller, loop, dashboard, keyboard = make_controller()

    def fail_to_start():
        raise RuntimeError("Dashboard startup failed")

    dashboard.start = fail_to_start

    with pytest.raises(RuntimeError, match="Dashboard startup failed"):
        controller.run()

    assert keyboard.started is True
    assert keyboard.stopped is True
    assert dashboard.stopped is True


def run_snapshot_workflow(
    processes,
    keys,
    acquirer=None,
    memory_acquirer=None,
):
    keyboard = FakeKeyboard()
    dashboard = FakeDashboard()

    class SnapshotMonitoringLoop:
        def run(self, stop_event, is_recording, on_scan=None):
            if on_scan:
                on_scan({"processes": processes})

            # Freeze the snapshot, then send the requested inputs.
            for key in ["s", *keys]:
                keyboard.press_key(key)

            if not stop_event.wait(timeout=2):
                raise AssertionError("Snapshot was not frozen")

    controller = MonitoringController(
        monitoring_loop=SnapshotMonitoringLoop(),
        dashboard=dashboard,
        keyboard=keyboard,
        executable_acquirer=acquirer,
        memory_acquirer=memory_acquirer,
    )

    controller.run()

    return controller, dashboard, keyboard


def make_snapshot_process(
    pid=1234,
    identity_type="strong",
):
    return {
        "pid": pid,
        "name": "test.exe",
        "executable": r"C:\test\test.exe",
        "create_time": 1000.0,
        "identity_type": identity_type,
        "identity_key": "pid:1000",
    }


def test_acquisition_uses_confirmed_snapshot_process():
    process = make_snapshot_process()
    acquirer = FakeExecutableAcquirer()

    controller, dashboard, keyboard = run_snapshot_workflow(
        processes=[process],
        keys=["a", "1", "2", "3", "4", "\r", "y", "q"],
        acquirer=acquirer,
    )

    assert acquirer.acquired_processes == [process]
    assert any(
        "acquired successfully" in message
        for message in dashboard.messages
    )
    assert any(
        "test-hash" in message
        for message in dashboard.messages
    )


def test_acquisition_rejects_pid_not_in_snapshot():
    acquirer = FakeExecutableAcquirer()

    controller, dashboard, keyboard = run_snapshot_workflow(
        processes=[make_snapshot_process(pid=1234)],
        keys=["a", "9", "9", "9", "9", "\r", "q"],
        acquirer=acquirer,
    )

    assert acquirer.acquired_processes == []
    assert any(
        "PID not found" in message
        for message in dashboard.messages
    )


def test_acquisition_rejects_weak_process_identity():
    process = make_snapshot_process(identity_type="weak_pid")
    acquirer = FakeExecutableAcquirer()

    controller, dashboard, keyboard = run_snapshot_workflow(
        processes=[process],
        keys=["a", "1", "2", "3", "4", "\r", "q"],
        acquirer=acquirer,
    )

    assert acquirer.acquired_processes == []
    assert any(
        "strong process identity" in message
        for message in dashboard.messages
    )


def test_acquisition_can_be_cancelled_with_n():
    process = make_snapshot_process()
    acquirer = FakeExecutableAcquirer()

    controller, dashboard, keyboard = run_snapshot_workflow(
        processes=[process],
        keys=["a", "1", "2", "3", "4", "\r", "n", "q"],
        acquirer=acquirer,
    )

    assert acquirer.acquired_processes == []
    assert any(
        "cancelled" in message
        for message in dashboard.messages
    )


def test_acquisition_pid_entry_can_be_cancelled_with_escape():
    process = make_snapshot_process()
    acquirer = FakeExecutableAcquirer()

    controller, dashboard, keyboard = run_snapshot_workflow(
        processes=[process],
        keys=["a", "1", "2", "\x1b", "q"],
        acquirer=acquirer,
    )

    assert acquirer.acquired_processes == []
    assert any(
        "cancelled" in message
        for message in dashboard.messages
    )


def test_acquisition_failure_is_displayed_without_crashing():
    process = make_snapshot_process()
    acquirer = FakeExecutableAcquirer(
        error=RuntimeError("Simulated acquisition failure")
    )

    controller, dashboard, keyboard = run_snapshot_workflow(
        processes=[process],
        keys=["a", "1", "2", "3", "4", "\r", "y", "q"],
        acquirer=acquirer,
    )

    assert acquirer.acquired_processes == [process]
    assert any(
        "Acquisition failed" in message
        and "Simulated acquisition failure" in message
        for message in dashboard.messages
    )


def test_acquisition_key_is_ignored_during_live_monitoring():
    process = make_snapshot_process()
    acquirer = FakeExecutableAcquirer()

    keyboard = FakeKeyboard()
    dashboard = FakeDashboard()

    class LiveMonitoringLoop:
        def run(self, stop_event, is_recording, on_scan=None):
            if on_scan:
                on_scan({"processes": [process]})

            keyboard.press_key("a")
            if not keyboard.wait_for_reads(1):
                raise AssertionError("Keyboard input was not processed")

            keyboard.press_key("q")
            if not stop_event.wait(timeout=2):
                raise AssertionError("Quit command was not processed")

    controller = MonitoringController(
        monitoring_loop=LiveMonitoringLoop(),
        dashboard=dashboard,
        keyboard=keyboard,
        executable_acquirer=acquirer,
    )

    controller.run()

    assert acquirer.acquired_processes == []
def test_memory_acquisition_uses_confirmed_snapshot_process(
    tmp_path,
    monkeypatch,
):
    process = make_snapshot_process()
    acquirer = FakeMemoryAcquirer()

    evidence_dir = tmp_path / "evidence"

    monkeypatch.setattr(
        monitoring_controller_module,
        "EVIDENCE_DIR",
        evidence_dir,
    )

    controller, dashboard, keyboard = run_snapshot_workflow(
        processes=[process],
        keys=["m", "1", "2", "3", "4", "\r", "y", "q"],
        memory_acquirer=acquirer,
    )

    assert len(acquirer.requests) == 1

    request = acquirer.requests[0]

    assert request["action"] == "acquire_memory"
    assert request["pid"] == 1234

    destination = Path(request["destination"])

    assert destination.parent == evidence_dir / "memory"
    assert destination.name.startswith("process_1234_")
    assert destination.suffix == ".dmp"
    assert destination.parent.is_dir()

    assert any(
        "acquired successfully" in message
        for message in dashboard.messages
    )

    assert any(
        "test-memory-hash" in message
        for message in dashboard.messages
    )

def test_memory_acquisition_can_be_cancelled_with_n():
    process = make_snapshot_process()
    acquirer = FakeMemoryAcquirer()

    controller, dashboard, keyboard = run_snapshot_workflow(
        processes=[process],
        keys=["m", "1", "2", "3", "4", "\r", "n", "q"],
        memory_acquirer=acquirer,
    )

    assert acquirer.requests == []
    assert any(
        "cancelled" in message
        for message in dashboard.messages
    )

def test_memory_acquisition_failure_is_displayed_without_crashing(
    tmp_path,
    monkeypatch,
):
    process = make_snapshot_process()

    acquirer = FakeMemoryAcquirer(
        error=RuntimeError("Simulated memory acquisition failure")
    )

    monkeypatch.setattr(
        monitoring_controller_module,
        "EVIDENCE_DIR",
        tmp_path / "evidence",
    )

    controller, dashboard, keyboard = run_snapshot_workflow(
        processes=[process],
        keys=["m", "1", "2", "3", "4", "\r", "y", "q"],
        memory_acquirer=acquirer,
    )

    assert len(acquirer.requests) == 1

    assert any(
        "Memory acquisition failed" in message
        and "Simulated memory acquisition failure" in message
        for message in dashboard.messages
    )

def test_memory_inspection_forwards_parameters_and_displays_result():
    process = make_snapshot_process()

    acquirer = FakeMemoryAcquirer(
        result={
            "success": True,
            "action": "inspect_memory",
            "message": "Memory inspection successful\nText Editor",
        }
    )

    controller = MonitoringController(
        monitoring_loop=None,
        dashboard=FakeDashboard(),
        keyboard=FakeKeyboard(),
        memory_acquirer=acquirer,
    )

    controller._inspect_memory(
        dump_path="evidence/memory/test.dmp",
        address=0x0BE9001C,
        length=64,
    )

    assert len(acquirer.requests) == 1

    request = acquirer.requests[0]

    assert request["action"] == "inspect_memory"
    assert request["destination"] == "evidence/memory/test.dmp"
    assert request["address"] == 0x0BE9001C
    assert request["length"] == 64
    assert request["bytes_per_line"] == 16

    assert any(
        "Memory inspection successful" in message
        for message in controller.dashboard.messages
    )


def test_memory_inspection_failure_is_displayed_without_crashing():
    acquirer = FakeMemoryAcquirer(
        error=RuntimeError("Simulated inspection failure")
    )

    dashboard = FakeDashboard()

    controller = MonitoringController(
        monitoring_loop=None,
        dashboard=dashboard,
        keyboard=FakeKeyboard(),
        memory_acquirer=acquirer,
    )

    controller._inspect_memory(
        dump_path="test.dmp",
        address=0x1000,
        length=64,
    )

    assert len(acquirer.requests) == 1

    assert any(
        "Memory inspection failed" in message
        and "Simulated inspection failure" in message
        for message in dashboard.messages
    )


def test_list_memory_regions_returns_region_details():
    regions = [
        {
            "start_address": 4096,
            "size": 8192,
            "address_space": "virtual",
            "permissions": None,
        },
        {
            "start_address": 12288,
            "size": 4096,
            "address_space": "virtual",
            "permissions": None,
        },
    ]

    acquirer = FakeMemoryAcquirer(
        result={
            "success": True,
            "action": "list_memory_regions",
            "memory_region_details": regions,
        }
    )

    dashboard = FakeDashboard()

    controller = MonitoringController(
        monitoring_loop=None,
        dashboard=dashboard,
        keyboard=FakeKeyboard(),
        memory_acquirer=acquirer,
    )

    result = controller._list_memory_regions("test.dmp")

    assert result == regions
    assert len(acquirer.requests) == 1
    assert acquirer.requests[0] == {
        "action": "list_memory_regions",
        "destination": "test.dmp",
    }

    assert any(
        "Found 2 memory regions" in message
        for message in dashboard.messages
    )


def test_list_memory_regions_handles_failed_response():
    acquirer = FakeMemoryAcquirer(
        result={
            "success": False,
            "message": "Invalid minidump",
        }
    )

    dashboard = FakeDashboard()

    controller = MonitoringController(
        monitoring_loop=None,
        dashboard=dashboard,
        keyboard=FakeKeyboard(),
        memory_acquirer=acquirer,
    )

    result = controller._list_memory_regions("test.dmp")

    assert result == []

    assert any(
        "Memory region listing failed" in message
        and "Invalid minidump" in message
        for message in dashboard.messages
    )


def test_list_memory_regions_handles_exceptions():
    acquirer = FakeMemoryAcquirer(
        error=RuntimeError("Simulated region listing failure")
    )

    dashboard = FakeDashboard()

    controller = MonitoringController(
        monitoring_loop=None,
        dashboard=dashboard,
        keyboard=FakeKeyboard(),
        memory_acquirer=acquirer,
    )

    result = controller._list_memory_regions("test.dmp")

    assert result == []

    assert any(
        "Memory region listing failed" in message
        and "Simulated region listing failure" in message
        for message in dashboard.messages
    )


def test_find_memory_dumps_returns_matching_pid_newest_first(
    tmp_path,
    monkeypatch,
):
    evidence_dir = tmp_path / "evidence"
    memory_dir = evidence_dir / "memory"
    memory_dir.mkdir(parents=True)

    older_dump = memory_dir / "process_1234_20261110_120000_aaaaaaaa.dmp"
    newer_dump = memory_dir / "process_1234_20261112_120000_bbbbbbbb.dmp"
    other_dump = memory_dir / "process_5678_20261112_130000_cccccccc.dmp"

    for dump in (older_dump, newer_dump, other_dump):
        dump.touch()

    monkeypatch.setattr(
        monitoring_controller_module,
        "EVIDENCE_DIR",
        evidence_dir,
    )

    controller, _, _, _ = make_controller()

    results = controller._find_memory_dumps(1234)

    assert results == [newer_dump, older_dump]


def test_find_memory_dumps_returns_empty_when_no_matching_dumps(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        monitoring_controller_module,
        "EVIDENCE_DIR",
        tmp_path / "missing_evidence",
    )

    controller, _, _, _ = make_controller()

    assert controller._find_memory_dumps(1234) == []

def test_memory_inspection_selects_region_and_uses_default_length(
    tmp_path,
    monkeypatch,
):
    process = make_snapshot_process()

    regions = [
        {
            "start_address": 0x1000,
            "size": 4096,
            "address_space": "virtual",
            "permissions": None,
        },
        {
            "start_address": 0x5000,
            "size": 8192,
            "address_space": "virtual",
            "permissions": None,
        },
    ]

    memory_dir = tmp_path / "evidence" / "memory"
    memory_dir.mkdir(parents=True)

    dump_path = (
        memory_dir
        / "process_1234_20261112_120000_aaaaaaaa.dmp"
    )
    dump_path.touch()

    monkeypatch.setattr(
        monitoring_controller_module,
        "EVIDENCE_DIR",
        tmp_path / "evidence",
    )

    acquirer = FakeRegionMemoryAcquirer(regions)

    controller, dashboard, keyboard = run_snapshot_workflow(
        processes=[process],
        keys=["i", "1", "2", "3", "4", "\r", "2", "\r", "q"],        memory_acquirer=acquirer,
    )

    assert len(acquirer.requests) == 2

    assert acquirer.requests[0] == {
        "action": "list_memory_regions",
        "destination": str(dump_path),
    }

    assert acquirer.requests[1] == {
        "action": "inspect_memory",
        "destination": str(dump_path),
        "address": 0x5000,
        "length": 256,
        "bytes_per_line": 16,
    }

    assert any(
        "Memory inspection successful" in message
        for message in dashboard.messages
    )

def test_memory_inspection_recovers_from_invalid_region_selection(
    tmp_path,
    monkeypatch,
):
    process = make_snapshot_process()

    regions = [
        {
            "start_address": 0x1000,
            "size": 4096,
            "address_space": "virtual",
            "permissions": None,
        },
        {
            "start_address": 0x5000,
            "size": 8192,
            "address_space": "virtual",
            "permissions": None,
        },
    ]

    memory_dir = tmp_path / "evidence" / "memory"
    memory_dir.mkdir(parents=True)

    dump_path = (
        memory_dir
        / "process_1234_20261112_120000_aaaaaaaa.dmp"
    )
    dump_path.touch()

    monkeypatch.setattr(
        monitoring_controller_module,
        "EVIDENCE_DIR",
        tmp_path / "evidence",
    )

    acquirer = FakeRegionMemoryAcquirer(regions)

    controller, dashboard, keyboard = run_snapshot_workflow(
        processes=[process],
        keys=[
            "i", "1", "2", "3", "4", "\r",
            "9", "\r",
            "2", "\r",
            "q",
        ],
        memory_acquirer=acquirer,
    )

    # Region listing followed by successful inspection.
    assert len(acquirer.requests) == 2

    assert acquirer.requests[0] == {
        "action": "list_memory_regions",
        "destination": str(dump_path),
    }

    assert acquirer.requests[1] == {
        "action": "inspect_memory",
        "destination": str(dump_path),
        "address": 0x5000,
        "length": 256,
        "bytes_per_line": 16,
    }

    assert any(
        "Invalid region selection" in message
        for message in dashboard.messages
    )

    assert any(
        "Memory inspection successful" in message
        for message in dashboard.messages
    )


def test_memory_inspection_limits_length_to_region_size(
    tmp_path,
    monkeypatch,
):
    process = make_snapshot_process()

    regions = [
        {
            "start_address": 0x1000,
            "size": 128,
            "address_space": "virtual",
            "permissions": None,
        },
    ]

    memory_dir = tmp_path / "evidence" / "memory"
    memory_dir.mkdir(parents=True)

    dump_path = (
        memory_dir
        / "process_1234_20261112_120000_aaaaaaaa.dmp"
    )
    dump_path.touch()

    monkeypatch.setattr(
        monitoring_controller_module,
        "EVIDENCE_DIR",
        tmp_path / "evidence",
    )

    acquirer = FakeRegionMemoryAcquirer(regions)

    controller, dashboard, keyboard = run_snapshot_workflow(
        processes=[process],
        keys=["i", "1", "2", "3", "4", "\r", "1", "\r", "q"],
        memory_acquirer=acquirer,
    )

    assert len(acquirer.requests) == 2

    assert acquirer.requests[1] == {
        "action": "inspect_memory",
        "destination": str(dump_path),
        "address": 0x1000,
        "length": 128,
        "bytes_per_line": 16,
    }

    assert any(
        "Memory inspection successful" in message
        for message in dashboard.messages
    )
