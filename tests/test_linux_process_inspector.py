
import os

import psutil
import pytest

from platform_support.linux.process_inspector import inspect_process
from types import SimpleNamespace


def create_proc_status(tmp_path, pid):
    process_dir = tmp_path / str(pid)
    process_dir.mkdir()

    status_file = process_dir / "status"

    status_file.write_text(
        "Name:\ttest-process\n"
        "State:\tR (running)\n"
        "PPid:\t100\n"
        "Uid:\t1000\t1000\t1000\t1000\n"
        "VmRSS:\t2048 kB\n"
        "Threads:\t4\n",
        encoding="utf-8",
    )


def test_inspect_process_returns_metadata(tmp_path):
    pid = os.getpid()
    create_proc_status(tmp_path, pid)

    result = inspect_process(pid, proc_root=tmp_path)

    assert result["pid"] == pid
    assert result["name"] is not None
    assert result["create_time"] > 0
    assert result["memory_rss_bytes"] >= 0
    assert result["procfs"]["name"] == "test-process"
    assert result["procfs"]["state"] == "R (running)"
    assert result["procfs"]["parent_pid"] == 100
    assert result["procfs"]["uid"] == 1000
    assert result["procfs"]["memory_rss_kb"] == 2048
    assert result["procfs"]["threads"] == 4
    assert result["identity_type"] == "strong"
    assert result["identity_key"].startswith(f"{pid}:")

@pytest.mark.parametrize("pid", [0, -1, True, "123"])
def test_inspect_process_rejects_invalid_pid(pid):
    with pytest.raises(ValueError):
        inspect_process(pid)


def test_inspect_process_rejects_missing_proc_status(tmp_path):
    pid = os.getpid()

    with pytest.raises(psutil.NoSuchProcess):
        inspect_process(pid, proc_root=tmp_path)


def test_inspect_process_uses_weak_identity_for_invalid_creation_time(
    tmp_path,
    monkeypatch,
):
    pid = os.getpid()
    create_proc_status(tmp_path, pid)

    class MockProcess:
        def as_dict(self, attrs):
            return {
                "pid": pid,
                "name": "test-process",
                "status": "running",
                "username": "test-user",
                "create_time": 0.0,
                "exe": "/test/process",
                "cmdline": ["test-process"],
                "ppid": 100,
                "num_threads": 2,
            }

        def memory_info(self):
            return type(
                "MemoryInfo",
                (),
                {"rss": 1024, "vms": 2048},
            )()
        
        def cwd(self):
            return "/test"

    monkeypatch.setattr(
        psutil,
        "Process",
        lambda process_id: MockProcess(),
    )

    result = inspect_process(pid, proc_root=tmp_path)

    assert result["identity_type"] == "weak_pid"
    assert result["identity_key"] == f"linux:weak_pid:{pid}"


def test_inspect_process_collects_working_directory_and_executable_metadata(
    tmp_path,
    monkeypatch,
):
    pid = os.getpid()
    create_proc_status(tmp_path, pid)

    class MockProcess:
        def as_dict(self, attrs):
            return {
                "pid": pid,
                "name": "test-process",
                "status": "running",
                "username": "test-user",
                "create_time": 1000.0,
                "exe": "/test/process",
                "cmdline": ["test-process"],
                "ppid": 100,
                "num_threads": 2,
            }

        def memory_info(self):
            return SimpleNamespace(rss=1024, vms=2048)

        def cwd(self):
            return "/test"

    executable_stat = SimpleNamespace(
        st_size=4096,
        st_ctime=1700000000.0,
        st_mtime=1700000100.0,
        st_atime=1700000200.0,
    )

    monkeypatch.setattr(
        psutil,
        "Process",
        lambda process_id: MockProcess(),
    )

    def mock_stat(path, *args, **kwargs):
        return executable_stat

    monkeypatch.setattr(os, "stat", mock_stat)

    result = inspect_process(pid, proc_root=tmp_path)

    assert result["working_directory"] == "/test"
    assert result["executable_metadata"] == {
        "size_bytes": 4096,
        "changed_at": 1700000000.0,
        "modified_at": 1700000100.0,
        "accessed_at": 1700000200.0,
    }


def test_inspect_process_handles_unavailable_executable_metadata(
    tmp_path,
    monkeypatch,
):
    pid = os.getpid()
    create_proc_status(tmp_path, pid)

    class MockProcess:
        def as_dict(self, attrs):
            return {
                "pid": pid,
                "name": "test-process",
                "status": "running",
                "username": "test-user",
                "create_time": 1000.0,
                "exe": "/test/process",
                "cmdline": ["test-process"],
                "ppid": 100,
                "num_threads": 2,
            }

        def memory_info(self):
            return SimpleNamespace(rss=1024, vms=2048)

        def cwd(self):
            return "/test"

    monkeypatch.setattr(
        psutil,
        "Process",
        lambda process_id: MockProcess(),
    )

    def inaccessible_file(path, *args, **kwargs):
        raise PermissionError("Access denied")

    monkeypatch.setattr(os, "stat", inaccessible_file)

    result = inspect_process(pid, proc_root=tmp_path)

    assert result["pid"] == pid
    assert result["working_directory"] == "/test"
    assert result["executable_metadata"] is None


def test_inspect_process_handles_unavailable_working_directory(
    tmp_path,
    monkeypatch,
):
    pid = os.getpid()
    create_proc_status(tmp_path, pid)

    class MockProcess:
        def as_dict(self, attrs):
            return {
                "pid": pid,
                "name": "test-process",
                "status": "running",
                "username": "test-user",
                "create_time": 1000.0,
                "exe": None,
                "cmdline": ["test-process"],
                "ppid": 100,
                "num_threads": 2,
            }

        def memory_info(self):
            return SimpleNamespace(rss=1024, vms=2048)

        def cwd(self):
            raise psutil.AccessDenied(pid)

    monkeypatch.setattr(
        psutil,
        "Process",
        lambda process_id: MockProcess(),
    )

    result = inspect_process(pid, proc_root=tmp_path)

    assert result["pid"] == pid
    assert result["working_directory"] is None
    assert result["executable_metadata"] is None
