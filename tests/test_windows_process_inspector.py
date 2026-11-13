
import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import psutil
import pytest

from platform_support.windows.process_inspector import inspect_process


def create_mock_process(pid, create_time=1000.0):
    process = MagicMock()

    process.__enter__ = MagicMock(return_value=process)
    process.__exit__ = MagicMock(return_value=False)

    process.as_dict.return_value = {
        "pid": pid,
        "name": "test-process",
        "status": "running",
        "username": "test-user",
        "create_time": create_time,
        "exe": "C:\\test\\process.exe",
        "cmdline": ["process.exe"],
        "ppid": 100,
        "num_threads": 2,
    }

    process.memory_info.return_value = SimpleNamespace(
        rss=1024,
        vms=2048,
    )

    process.io_counters.return_value = SimpleNamespace(
        read_bytes=500,
        write_bytes=250,
    )

    process.cwd.return_value = "C:\\test"

    return process


def test_inspect_current_process():
    pid = os.getpid()

    result = inspect_process(pid)

    assert result["pid"] == pid
    assert result["name"] is not None
    assert result["create_time"] > 0
    assert result["threads"] > 0
    assert result["memory_rss_bytes"] >= 0
    assert result["memory_vms_bytes"] >= 0
    assert result["io_read_bytes"] >= 0
    assert result["io_write_bytes"] >= 0
    assert result["identity_type"] == "strong"
    assert result["identity_key"].startswith(f"{pid}:")


def test_inspect_system_idle_process():
    result = inspect_process(0)

    assert result["pid"] == 0
    assert result["name"] == "System Idle Process"
    assert result["identity_type"] == "platform_special"
    assert result["identity_key"] == "windows:system_idle:0"
    assert result["create_time"] is None


def test_inspect_system_process(monkeypatch):
    mock_process = create_mock_process(4, create_time=0.0)

    monkeypatch.setattr(
        psutil,
        "Process",
        lambda pid: mock_process,
    )

    result = inspect_process(4)

    assert result["pid"] == 4
    assert result["identity_type"] == "platform_special"
    assert result["identity_key"] == "windows:system:4"


def test_inspect_process_uses_strong_identity(monkeypatch):
    mock_process = create_mock_process(1234, create_time=1000.0)

    monkeypatch.setattr(
        psutil,
        "Process",
        lambda pid: mock_process,
    )

    result = inspect_process(1234)

    assert result["identity_type"] == "strong"
    assert result["identity_key"] == "1234:1000"


@pytest.mark.parametrize("create_time", [None, 0.0, -1.0, float("nan"), float("inf")])
def test_inspect_process_uses_weak_identity_for_invalid_creation_time(
    monkeypatch,
    create_time,
):
    mock_process = create_mock_process(1234, create_time=create_time)

    monkeypatch.setattr(
        psutil,
        "Process",
        lambda pid: mock_process,
    )

    result = inspect_process(1234)

    assert result["identity_type"] == "weak_pid"
    assert result["identity_key"] == "windows:weak_pid:1234"


@pytest.mark.parametrize("pid", [-1, True, "123"])
def test_inspect_process_rejects_invalid_pid(pid):
    with pytest.raises(ValueError):
        inspect_process(pid)


def test_inspect_process_rejects_missing_process(monkeypatch):
    def mock_process(pid):
        raise psutil.NoSuchProcess(pid)

    monkeypatch.setattr(psutil, "Process", mock_process)

    with pytest.raises(psutil.NoSuchProcess):
        inspect_process(999999)
        
def test_inspect_process_collects_working_directory_and_executable_metadata(
    monkeypatch,
):
    mock_process = create_mock_process(1234)

    executable_stat = SimpleNamespace(
        st_size=4096,
        st_ctime=1700000000.0,
        st_mtime=1700000100.0,
        st_atime=1700000200.0,
    )

    monkeypatch.setattr(
        psutil,
        "Process",
        lambda pid: mock_process,
    )

    def mock_stat(path, *args, **kwargs):
        return executable_stat
        
    monkeypatch.setattr(os, "stat", mock_stat)
    
    result = inspect_process(1234)

    assert result["working_directory"] == "C:\\test"

    assert result["executable_metadata"] == {
        "size_bytes": 4096,
        "created_at": 1700000000.0,
        "modified_at": 1700000100.0,
        "accessed_at": 1700000200.0,
    }


def test_inspect_process_handles_unavailable_executable_metadata(
    monkeypatch,
):
    mock_process = create_mock_process(1234)

    monkeypatch.setattr(
        psutil,
        "Process",
        lambda pid: mock_process,
    )

    def inaccessible_file(path, *args, **kwargs):
        raise PermissionError("Access denied")

    monkeypatch.setattr(os, "stat", inaccessible_file)

    result = inspect_process(1234)

    assert result["pid"] == 1234
    assert result["working_directory"] == "C:\\test"
    assert result["executable_metadata"] is None
