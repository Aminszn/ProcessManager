
import pytest

from rich.console import Console

from visualization.evidence_browser import EvidenceBrowser


@pytest.fixture
def browser():
    console = Console(
        width=120,
        height=20,
        force_terminal=True,
        record=True,
    )
    return EvidenceBrowser(console=console)


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


def test_initial_browser_has_no_records(browser):
    assert browser._records == []
    assert browser._current_page == 0


def test_update_stores_records_and_resets_page(browser):
    records = [
        make_record("first"),
        make_record("second"),
    ]

    browser._current_page = 2
    browser.update(records)

    assert browser._records == records
    assert browser._current_page == 0


def test_render_returns_rich_panel(browser):
    browser.update([make_record()])

    result = browser.render()

    assert result.title == "Process Monitor - Evidence Browser"


def test_render_displays_executable_information(browser):
    browser.update([make_record()])

    browser.console.print(browser.render())

    output = browser.console.export_text()

    assert "example.exe" in output
    assert "1234" in output
    assert "Available" in output
    assert "2.00 KB" in output


def test_render_displays_empty_state(browser):
    browser.update([])

    browser.console.print(browser.render())

    output = browser.console.export_text()

    assert "No acquisitions found" in output
    assert "Total records: 0" in output


def test_render_displays_manifest_only_status(browser):
    browser.update([
        make_record(executable_available=False),
    ])

    browser.console.print(browser.render())

    output = browser.console.export_text()

    assert "Manifest only" in output


def test_render_displays_invalid_manifest_status(browser):
    browser.update([
        make_record(manifest_valid=False),
    ])

    browser.console.print(browser.render())

    output = browser.console.export_text()

    assert "Invalid manifest" in output


def test_next_page_advances_when_another_page_exists(browser):
    browser.update([
        make_record(str(index))
        for index in range(30)
    ])

    browser.next_page()

    assert browser._current_page == 1


def test_next_page_does_not_exceed_last_page(browser):
    browser.update([make_record()])

    browser.next_page()

    assert browser._current_page == 0


def test_previous_page_moves_back(browser):
    browser.update([
        make_record(str(index))
        for index in range(30)
    ])

    browser.next_page()
    browser.previous_page()

    assert browser._current_page == 0


def test_previous_page_does_not_go_below_zero(browser):
    browser.update([make_record()])

    browser.previous_page()

    assert browser._current_page == 0


def test_get_selected_record_returns_correct_record(browser):
    first = make_record("first")
    second = make_record("second")

    browser.update([first, second])

    assert browser.get_selected_record(2) == second


@pytest.mark.parametrize("index", [0, -1, 3, True, "1", None])
def test_get_selected_record_rejects_invalid_index(browser, index):
    browser.update([
        make_record("first"),
        make_record("second"),
    ])

    assert browser.get_selected_record(index) is None


def test_format_size_formats_bytes():
    assert EvidenceBrowser._format_size(500) == "500 B"


def test_format_size_formats_kilobytes():
    assert EvidenceBrowser._format_size(2048) == "2.00 KB"


def test_format_size_formats_megabytes():
    assert EvidenceBrowser._format_size(2 * 1024**2) == "2.00 MB"


def test_format_size_formats_gigabytes():
    assert EvidenceBrowser._format_size(2 * 1024**3) == "2.00 GB"


@pytest.mark.parametrize("size", [None, "invalid", -1])
def test_format_size_handles_invalid_values(size):
    assert EvidenceBrowser._format_size(size) == "Unknown"


def test_display_details_shows_acquisition_information(browser):
    record = make_record()

    browser.display_details(record)

    output = browser.console.export_text()

    assert "Acquisition Details" in output
    assert "example.exe" in output
    assert "1234" in output
    assert "abcdef123456" in output
    assert "manifest.json" in output
    assert "C:/evidence/test-1/example.exe" in output


def test_display_details_handles_missing_information(browser):
    record = {
        "manifest_valid": False,
        "executable_available": False,
    }

    browser.display_details(record)

    output = browser.console.export_text()

    assert "Unknown" in output
    assert "Unavailable" in output
    assert "Invalid manifest" in output


def test_page_count_is_at_least_one(browser):
    browser.update([])

    assert browser._get_page_count() == 1



def test_page_records_respect_current_page(browser):
    records = [
        make_record(str(index))
        for index in range(30)
    ]

    browser.update(records)
    browser.next_page()

    page_records = browser._get_page_records()

    assert len(page_records) == browser._get_page_size()
    assert page_records[0]["acquisition_id"] == "12"
    assert page_records[-1]["acquisition_id"] == "23"

