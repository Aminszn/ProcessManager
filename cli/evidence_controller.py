
from threading import Event

import pyperclip

from rich.console import Group
from rich.live import Live
from rich.text import Text

from acquisition.evidence_repository import EvidenceRepository
from cli.keyboard import KeyboardController
from visualization.evidence_browser import EvidenceBrowser


class EvidenceController:
    """Control browsing and management of acquired executable evidence."""

    def __init__(
        self,
        repository: EvidenceRepository,
        browser: EvidenceBrowser,
        keyboard: KeyboardController,
    ):
        self.repository = repository
        self.browser = browser
        self.keyboard = keyboard

        self.console = browser.console
        self._status_message = "N: Next | P: Previous | Enter: Details | C: Copy path | D: Clear executables | Q: Back"

    def _load_records(self) -> None:
        """Load acquisition records into the browser."""
        records = self.repository.list_acquisitions()
        self.browser.update(records)

    def _render(self):
        """Build the browser display with its current status message."""
        return Group(
            self.browser.render(),
            Text(self._status_message, style="bold cyan"),
        )

    def _set_status(self, message: str) -> None:
        self._status_message = message

    def _copy_executable_path(self, record: dict) -> None:
        """Copy an available executable's absolute path."""
        if not record.get("manifest_valid"):
            self._set_status("Cannot copy: invalid manifest.")
            return

        if not record.get("executable_available"):
            self._set_status("Cannot copy: executable is unavailable.")
            return

        executable_path = record.get("executable_path")

        if not executable_path:
            self._set_status("Cannot copy: executable path is unavailable.")
            return

        try:
            pyperclip.copy(executable_path)
        except Exception as exc:
            self._set_status(f"Clipboard copy failed: {exc}")
            return

        self._set_status(
            f"Executable path copied: {record['file_name']}"
        )

    def _show_details(self, record: dict, live: Live) -> None:
        """Temporarily display acquisition details."""
        live.stop()

        try:
            self.browser.display_details(record)
            self.console.print("\nPress Q to return to the evidence browser.")

            while True:
                key = self.keyboard.read_key()

                if key and key.lower() == "q":
                    break

        finally:
            live.start()

    def _clear_executables(self) -> None:
        """Delete executable copies after exact confirmation."""
        try:
            deleted_count = self.repository.clear_executables("DELETE")
        except Exception as exc:
            self._set_status(f"Evidence cleanup failed: {exc}")
            return

        self._load_records()

        self._set_status(
            f"Deleted {deleted_count} executable file(s). "
            "Acquisition manifests were preserved."
        )

    def run(self) -> None:
        """Run the interactive evidence browser."""
        self._load_records()

        input_mode = None
        input_buffer = ""
        selected_action = None

        live = Live(
            console=self.console,
            refresh_per_second=4,
            screen=True,
            vertical_overflow="crop",
        )

        try:
            self.keyboard.start()
            live.start()
            live.update(self._render(), refresh=True)

            running = True

            while running:
                key = self.keyboard.read_key()

                if key:
                    if input_mode == "record":
                        if key.isdigit():
                            input_buffer += key
                            self._set_status(
                                f"Enter record number: {input_buffer}"
                            )

                        elif key in ("\b", "\x7f"):
                            input_buffer = input_buffer[:-1]
                            self._set_status(
                                f"Enter record number: {input_buffer}"
                            )

                        elif key in ("\r", "\n"):
                            if not input_buffer:
                                self._set_status("No record number entered.")
                            else:
                                record = self.browser.get_selected_record(
                                    int(input_buffer)
                                )

                                if record is None:
                                    self._set_status(
                                        "Invalid record number."
                                    )

                                elif selected_action == "details":
                                    self._show_details(record, live)
                                    self._set_status(
                                        "Returned to evidence browser."
                                    )

                                elif selected_action == "copy":
                                    self._copy_executable_path(record)

                            input_mode = None
                            input_buffer = ""
                            selected_action = None

                        elif key == "\x1b":
                            input_mode = None
                            input_buffer = ""
                            selected_action = None
                            self._set_status("Operation cancelled.")

                    elif input_mode == "delete":
                        if key.isalpha():
                            input_buffer += key.upper()
                            self._set_status(
                                f"Type DELETE to confirm: {input_buffer}"
                            )

                        elif key in ("\b", "\x7f"):
                            input_buffer = input_buffer[:-1]
                            self._set_status(
                                f"Type DELETE to confirm: {input_buffer}"
                            )

                        elif key in ("\r", "\n"):
                            if input_buffer == "DELETE":
                                self._clear_executables()
                            else:
                                self._set_status(
                                    "Confirmation did not match. "
                                    "No files were deleted."
                                )

                            input_mode = None
                            input_buffer = ""

                        elif key == "\x1b":
                            input_mode = None
                            input_buffer = ""
                            self._set_status("Cleanup cancelled.")

                    else:
                        key = key.lower()

                        if key == "n":
                            self.browser.next_page()

                        elif key == "p":
                            self.browser.previous_page()

                        elif key in ("\r", "\n"):
                            input_mode = "record"
                            selected_action = "details"
                            input_buffer = ""
                            self._set_status(
                                "Enter record number for details. "
                                "Press Escape to cancel."
                            )

                        elif key == "c":
                            input_mode = "record"
                            selected_action = "copy"
                            input_buffer = ""
                            self._set_status(
                                "Enter record number to copy its executable "
                                "path. Press Escape to cancel."
                            )

                        elif key == "d":
                            input_mode = "delete"
                            input_buffer = ""
                            self._set_status(
                                "Type DELETE and press Enter to remove "
                                "executable copies. Manifests will be kept. "
                                "Press Escape to cancel."
                            )

                        elif key == "q":
                            running = False

                    live.update(self._render(), refresh=True)

                Event().wait(0.05)

        finally:
            try:
                live.stop()
            finally:
                self.keyboard.stop()
