
import select
import sys


class KeyboardController:
    """Read keyboard input without blocking the monitoring loop."""

    def __init__(self):
        self._original_terminal_settings = None
        self._terminal_fd = None

    def start(self) -> None:
        """Enable single-key input on supported POSIX terminals."""
        if sys.platform == "win32":
            return

        if not sys.stdin.isatty():
            return

        if self._original_terminal_settings is not None:
            return

        import termios
        import tty

        self._terminal_fd = sys.stdin.fileno()
        self._original_terminal_settings = termios.tcgetattr(
            self._terminal_fd
        )

        try:
            tty.setcbreak(self._terminal_fd)
        except Exception:
            self._original_terminal_settings = None
            self._terminal_fd = None
            raise

    def read_key(self) -> str | None:
        """Return one available key, or None if no key is available."""
        if sys.platform == "win32":
            return self._read_windows_key()

        return self._read_posix_key()

    @staticmethod
    def _read_windows_key() -> str | None:
        import msvcrt

        if not msvcrt.kbhit():
            return None

        key = msvcrt.getwch()

        # Ignore the prefix of Windows special keys.
        if key in ("\x00", "\xe0"):
            msvcrt.getwch()
            return None

        return key

    @staticmethod
    def _read_posix_key() -> str | None:
        readable, _, _ = select.select(
            [sys.stdin],
            [],
            [],
            0,
        )

        if not readable:
            return None

        return sys.stdin.read(1)

    def stop(self) -> None:
        """Restore the terminal's original settings."""
        if self._original_terminal_settings is None:
            return

        import termios

        termios.tcsetattr(
            self._terminal_fd,
            termios.TCSADRAIN,
            self._original_terminal_settings,
        )

        self._original_terminal_settings = None
        self._terminal_fd = None
