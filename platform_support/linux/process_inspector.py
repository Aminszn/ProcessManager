
import math
import os
from pathlib import Path

import psutil


def _read_proc_status(status_path: Path) -> dict:
    """Read selected fields from a Linux procfs status file."""

    status = {}

    for line in status_path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition(":")

        if not separator:
            continue

        if key == "Name":
            status["name"] = value.strip()

        elif key == "State":
            status["state"] = value.strip()

        elif key == "PPid":
            status["parent_pid"] = int(value.strip())

        elif key == "Uid":
            status["uid"] = int(value.split()[0])

        elif key == "VmRSS":
            status["memory_rss_kb"] = int(value.split()[0])

        elif key == "Threads":
            status["threads"] = int(value.strip())

    return status


def _get_identity(pid: int, create_time: float | None) -> tuple[str, str]:
    """Determine whether a Linux process has a strong or weak identity."""

    if (
        isinstance(create_time, (int, float))
        and not isinstance(create_time, bool)
        and math.isfinite(create_time)
        and create_time > 0
    ):
        return "strong", f"{pid}:{float(create_time):.17g}"

    return "weak_pid", f"linux:weak_pid:{pid}"


def _get_executable_metadata(executable: str | None) -> dict | None:
    """Collect metadata for an executable file when accessible."""

    if not executable:
        return None

    try:
        file_stat = os.stat(executable)
    except OSError:
        return None

    return {
        "size_bytes": file_stat.st_size,
        "changed_at": file_stat.st_ctime,
        "modified_at": file_stat.st_mtime,
        "accessed_at": file_stat.st_atime,
    }


def inspect_process(pid: int, proc_root: Path = Path("/proc")) -> dict:
    """
    Inspect a Linux process using psutil and procfs.

    Raises:
        ValueError: If PID is invalid.
        psutil.NoSuchProcess: If the process no longer exists.
        psutil.AccessDenied: If required process inspection is denied.
    """

    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ValueError("PID must be a positive integer")

    process = psutil.Process(pid)

    try:
        process_info = process.as_dict(
            attrs=[
                "pid",
                "name",
                "status",
                "username",
                "create_time",
                "exe",
                "cmdline",
                "ppid",
                "num_threads",
            ]
        )

        memory_info = process.memory_info()

        proc_status = _read_proc_status(
            proc_root / str(pid) / "status"
        )

        try:
            working_directory = process.cwd()
        except (psutil.Error, OSError):
            working_directory = None

    except FileNotFoundError as exc:
        raise psutil.NoSuchProcess(pid) from exc

    executable_metadata = _get_executable_metadata(
        process_info["exe"]
    )

    identity_type, identity_key = _get_identity(
        process_info["pid"],
        process_info["create_time"],
    )

    return {
        "pid": process_info["pid"],
        "name": process_info["name"],
        "status": process_info["status"],
        "username": process_info["username"],
        "create_time": process_info["create_time"],
        "executable": process_info["exe"],
        "cmdline": process_info["cmdline"],
        "parent_pid": process_info["ppid"],
        "threads": process_info["num_threads"],
        "memory_rss_bytes": memory_info.rss,
        "memory_vms_bytes": memory_info.vms,
        "working_directory": working_directory,
        "executable_metadata": executable_metadata,
        "procfs": proc_status,
        "identity_type": identity_type,
        "identity_key": identity_key,
    }
