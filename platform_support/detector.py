
import platform


def detect_platform() -> str:
    """
    Identify the operating system.

    Returns:
        str: 'linux' or 'windows'.

    Raises:
        RuntimeError: If the operating system is unsupported.
    """
    operating_system = platform.system().lower()

    if operating_system == "linux":
        return "linux"

    if operating_system == "windows":
        return "windows"

    raise RuntimeError(
        f"Unsupported operating system: {operating_system}"
    )
