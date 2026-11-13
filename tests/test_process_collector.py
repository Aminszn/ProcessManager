
import pytest

from collectors import process_collector


COMMON_PROCESS_INFO = {
    "pid": 1234,
    "name": "test-process",
    "status": "running",
    "username": "test-user",
    "create_time": 1000.0,
    "executable": "/test/process",
    "cmdline": ["test-process"],
    "parent_pid": 100,
    "threads": 2,
    "memory_rss_bytes": 1024,
    "memory_vms_bytes": 2048,
    "identity_type": "strong",
    "identity_key": "1234:1000",
    "working_directory": "/test",
    "executable_metadata": {
        "size_bytes": 4096,
        "modified_at": 1700000100.0,
        "accessed_at": 1700000200.0,
        "changed_at": 1700000000.0,
    },
}


def test_collect_process_uses_linux_inspector(monkeypatch):
    linux_info = {
        **COMMON_PROCESS_INFO,
        "procfs": {"uid": 1000},
    }

    monkeypatch.setattr(
        process_collector,
        "detect_platform",
        lambda: "linux",
    )

    monkeypatch.setattr(
        process_collector,
        "inspect_linux_process",
        lambda pid: linux_info,
    )

    result = process_collector.collect_process(1234)

    assert result["platform"] == "linux"
    assert result["pid"] == 1234
    assert result["platform_details"] == {
        "procfs": {"uid": 1000}
    }


def test_collect_process_uses_windows_inspector(monkeypatch):
    windows_info = {
        **COMMON_PROCESS_INFO,
        "io_read_bytes": 500,
        "io_write_bytes": 250,
    }

    monkeypatch.setattr(
        process_collector,
        "detect_platform",
        lambda: "windows",
    )

    monkeypatch.setattr(
        process_collector,
        "inspect_windows_process",
        lambda pid: windows_info,
    )

    result = process_collector.collect_process(1234)

    assert result["platform"] == "windows"
    assert result["pid"] == 1234
    assert result["platform_details"] == {
        "io_read_bytes": 500,
        "io_write_bytes": 250,
    }


def test_collect_process_rejects_unsupported_platform(monkeypatch):
    monkeypatch.setattr(
        process_collector,
        "detect_platform",
        lambda: "darwin",
    )

    with pytest.raises(RuntimeError, match="Unsupported operating system"):
        process_collector.collect_process(1234)


def test_collect_process_preserves_common_fields(monkeypatch):
    monkeypatch.setattr(
        process_collector,
        "detect_platform",
        lambda: "windows",
    )

    monkeypatch.setattr(
        process_collector,
        "inspect_windows_process",
        lambda pid: COMMON_PROCESS_INFO,
    )

    result = process_collector.collect_process(1234)

    for field in COMMON_PROCESS_INFO:
        assert result[field] == COMMON_PROCESS_INFO[field]

    assert result["platform_details"] == {}

def test_collect_process_preserves_identity_fields(monkeypatch):
    process_info = {
        **COMMON_PROCESS_INFO,
        "identity_type": "platform_special",
        "identity_key": "windows:system:4",
        "io_read_bytes": 500,
    }

    monkeypatch.setattr(
        process_collector,
        "detect_platform",
        lambda: "windows",
    )

    monkeypatch.setattr(
        process_collector,
        "inspect_windows_process",
        lambda pid: process_info,
    )

    result = process_collector.collect_process(4)

    assert result["identity_type"] == "platform_special"
    assert result["identity_key"] == "windows:system:4"
    assert result["platform_details"] == {
        "io_read_bytes": 500,
    }