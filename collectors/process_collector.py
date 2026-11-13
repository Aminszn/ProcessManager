
from platform_support.detector import detect_platform
from platform_support.linux.process_inspector import (
    inspect_process as inspect_linux_process,
)
from platform_support.windows.process_inspector import (
    inspect_process as inspect_windows_process,
)


COMMON_FIELDS = {
    "pid",
    "name",
    "status",
    "username",
    "create_time",
    "executable",
    "cmdline",
    "parent_pid",
    "threads",
    "memory_rss_bytes",
    "memory_vms_bytes",
    "working_directory",
    "executable_metadata",
    "identity_type",
    "identity_key",
}


def collect_process(pid: int) -> dict:
    """
    Collect process information using the appropriate OS inspector.

    Returns common process fields alongside platform-specific details.
    Identity fields are shared and remain at the top level.
    """

    operating_system = detect_platform()

    if operating_system == "linux":
        process_info = inspect_linux_process(pid)

    elif operating_system == "windows":
        process_info = inspect_windows_process(pid)

    else:
        raise RuntimeError(
            f"Unsupported operating system: {operating_system}"
        )

    common_info = {
        key: process_info[key]
        for key in COMMON_FIELDS
    }

    platform_details = {
        key: value
        for key, value in process_info.items()
        if key not in COMMON_FIELDS
    }

    return {
        **common_info,
        "platform": operating_system,
        "platform_details": platform_details,
    }
