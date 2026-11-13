
import math
import os

import psutil


def _get_identity(pid: int, create_time: float | None) -> tuple[str, str]:
    if pid == 0:
        return "platform_special", "windows:system_idle:0"

    if pid == 4:
        return "platform_special", "windows:system:4"

    if (
        isinstance(create_time, (int, float))
        and not isinstance(create_time, bool)
        and math.isfinite(create_time)
        and create_time > 0
    ):
        return "strong", f"{pid}:{float(create_time):.17g}"

    return "weak_pid", f"windows:weak_pid:{pid}"


def _get_executable_metadata(executable: str | None) -> dict | None:
    if not executable:
        return None

    try:
        file_stat = os.stat(executable)
    except OSError:
        return None

    return {
        "size_bytes": file_stat.st_size,
        "created_at": file_stat.st_ctime,
        "modified_at": file_stat.st_mtime,
        "accessed_at": file_stat.st_atime,
    }


def inspect_process(pid: int) -> dict:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid < 0:
        raise ValueError("PID must be a non-negative integer")

    if pid == 0:
        identity_type, identity_key = _get_identity(0, None)

        return {
            "pid": 0,
            "name": "System Idle Process",
            "status": "running",
            "username": None,
            "create_time": None,
            "executable": None,
            "cmdline": [],
            "parent_pid": None,
            "threads": None,
            "memory_rss_bytes": None,
            "memory_vms_bytes": None,
            "io_read_bytes": None,
            "io_write_bytes": None,
            "working_directory": None,
            "executable_metadata": None,
            "identity_type": identity_type,
            "identity_key": identity_key,
        }

    process = psutil.Process(pid)

    with process.oneshot():
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
        io_counters = process.io_counters()

        try:
            working_directory = process.cwd()
        except (psutil.Error, OSError):
            working_directory = None

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
        "io_read_bytes": io_counters.read_bytes,
        "io_write_bytes": io_counters.write_bytes,
        "working_directory": working_directory,
        "executable_metadata": executable_metadata,
        "identity_type": identity_type,
        "identity_key": identity_key,
    }
