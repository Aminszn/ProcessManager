
import pytest

from rich.console import Console

from acquisition.evidence_repository import EvidenceRepository
from cli.evidence_controller import EvidenceController
from visualization.evidence_browser import EvidenceBrowser


class FakeKeyboard:
    def __init__(self, keys=None):
        self.keys = list(keys or [])
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def read_key(self):
        if self.keys:
            return self.keys.pop(0)

        return None


class FakeLive:
    def __init__(self, **kwargs):
        self.started = False
        self.stopped = False
        self.updates = []

    def start(self):
        self.started = True
        self.stopped = False

    def stop(self):
        self.stopped = True

    def update(self, renderable, refresh=False):
        self.updates.append(renderable)


class FakeRepository:
    def __init__(self, records=None):
        self.records = list(records or [])
        self.clear_calls = []

    def list_acquisitions(self):
        return self.records

    def clear_executables(self, confirmation):
        self.clear_calls.append(confirmation)

        deleted_count = 0

        for record in self.records:
            if record["manifest_valid"] and record["executable_available"]:
                record["executable_available"] = False
                deleted_count += 1

        return deleted_count


def make_record(
    acquisition_id="test-1",
    executable_available=True,
    manifest_valid=True,
):
    return {
        "manifest_valid": manifest_valid,
        "manifest_error": None,
        "manifest_path": f"C:/evidence/{acquisition_id}/manifest.json",
        "executable_path": f"C:/evidence/{acquisition_id}/example.exe",
        "executable_available": executable_available,
        "acquisition_id": acquisition_id,
        "status": "success",
        "acquired_at": "2026-11-11T10:00:00+00:00",
        "pid": 1234,
        "process_name": "example.exe",
        "file_name": "example.exe",
        "size_bytes": 2048,
        "sha256": "abcdef123456",
    }


@pytest.fixture
def controller(monkeypatch):
    monkeypatch.setattr(
        "cli.evidence_controller.Live",
        FakeLive,
    )

    repository = FakeRepository([make_record()])
    browser = EvidenceBrowser(
        console=Console(
            width=120,
            height=20,
            record=True,
            force_terminal=True,
        )
    )
    keyboard = FakeKeyboard()

    instance = EvidenceController(
        repository=repository,
        browser=browser,
        keyboard=keyboard,
    )

    return instance, repository, browser, keyboard


def test_run_loads_records_and_starts_keyboard_and_live(
    controller,
):
    instance, repository, browser, keyboard = controller
    keyboard.keys = ["q"]

    instance.run()

    assert browser._records == repository.records
    assert keyboard.started is True
    assert keyboard.stopped is True


def test_run_returns_when_q_is_pressed(controller):
    instance, _, _, keyboard = controller
    keyboard.keys = ["q"]

    instance.run()

    assert keyboard.stopped is True


def test_next_page_key_advances_browser_page(controller):
    instance, _, browser, keyboard = controller

    instance.repository.records = [
        make_record(str(index))
        for index in range(30)
    ]
    keyboard.keys = ["n", "q"]

    instance.run()

    assert browser._current_page == 1


def test_previous_page_key_moves_to_previous_page(controller):
    instance, _, browser, keyboard = controller

    instance.repository.records = [
        make_record(str(index))
        for index in range(30)
    ]
    keyboard.keys = ["n", "p", "q"]

    instance.run()

    assert browser._current_page == 0



def test_enter_displays_selected_record_details(controller):
    instance, _, browser, keyboard = controller

    keyboard.keys = ["\r", "1", "\r", "q", "q"]

    instance.run()

    output = browser.console.export_text()

    assert "Acquisition Details" in output
    assert "abcdef123456" in output



def test_copy_key_copies_selected_executable_path(
    controller,
    monkeypatch,
):
    instance, _, _, keyboard = controller
    copied_paths = []

    monkeypatch.setattr(
        "cli.evidence_controller.pyperclip.copy",
        copied_paths.append,
    )

    keyboard.keys = ["c", "1", "\r", "q"]

    instance.run()

    assert copied_paths == [
        "C:/evidence/test-1/example.exe"
    ]
    assert "path copied" in instance._status_message


def test_copy_rejects_missing_executable(controller, monkeypatch):
    instance, repository, _, _ = controller
    repository.records[0]["executable_available"] = False

    copied_paths = []

    monkeypatch.setattr(
        "cli.evidence_controller.pyperclip.copy",
        copied_paths.append,
    )

    instance._copy_executable_path(repository.records[0])

    assert copied_paths == []
    assert "unavailable" in instance._status_message


def test_copy_rejects_invalid_manifest(controller, monkeypatch):
    instance, repository, _, _ = controller
    repository.records[0]["manifest_valid"] = False

    copied_paths = []

    monkeypatch.setattr(
        "cli.evidence_controller.pyperclip.copy",
        copied_paths.append,
    )

    instance._copy_executable_path(repository.records[0])

    assert copied_paths == []
    assert "invalid manifest" in instance._status_message


def test_copy_reports_clipboard_failure(controller, monkeypatch):
    instance, repository, _, _ = controller

    def fail_copy(path):
        raise RuntimeError("Clipboard unavailable")

    monkeypatch.setattr(
        "cli.evidence_controller.pyperclip.copy",
        fail_copy,
    )

    instance._copy_executable_path(repository.records[0])

    assert "Clipboard copy failed" in instance._status_message


def test_delete_requires_exact_confirmation(controller):
    instance, repository, _, keyboard = controller
    keyboard.keys = ["d", "D", "E", "L", "E", "T", "X", "\r", "q"]

    instance.run()

    assert repository.clear_calls == []
    assert repository.records[0]["executable_available"] is True
    assert "No files were deleted" in instance._status_message


def test_delete_with_confirmation_preserves_manifest_records(
    controller,
):
    instance, repository, browser, keyboard = controller
    keyboard.keys = [
        "d",
        "D", "E", "L", "E", "T", "E",
        "\r",
        "q",
    ]

    instance.run()

    assert repository.clear_calls == ["DELETE"]
    assert repository.records[0]["executable_available"] is False
    assert repository.records[0]["manifest_valid"] is True
    assert "Deleted 1 executable file" in instance._status_message
    assert browser._records[0]["executable_available"] is False


def test_delete_can_be_cancelled_with_escape(controller):
    instance, repository, _, keyboard = controller
    keyboard.keys = ["d", "\x1b", "q"]

    instance.run()

    assert repository.clear_calls == []
    assert repository.records[0]["executable_available"] is True
    assert "cancelled" in instance._status_message


def test_delete_refreshes_records_after_cleanup(controller):
    instance, repository, browser, keyboard = controller
    keyboard.keys = [
        "d",
        "D", "E", "L", "E", "T", "E",
        "\r",
        "q",
    ]

    instance.run()

    assert browser._records == repository.records


def test_record_input_can_be_cancelled(controller):
    instance, _, _, keyboard = controller
    keyboard.keys = ["c", "\x1b", "q"]

    instance.run()

    assert "cancelled" in instance._status_message


def test_invalid_record_number_is_rejected(controller):
    instance, _, _, keyboard = controller
    keyboard.keys = ["c", "9", "\r", "q"]

    instance.run()

    assert "Invalid record number" in instance._status_message
