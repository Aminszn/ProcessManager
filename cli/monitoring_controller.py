import uuid
from datetime import datetime, timezone
from pathlib import Path

from acquisition.memory_acquirer import MemoryAcquirer
from config.settings import EVIDENCE_DIR

from threading import Event, Lock, Thread

from acquisition.executable_acquirer import ExecutableAcquirer
from cli.keyboard import KeyboardController
from monitoring.monitor import MonitoringLoop
from visualization.live_dashboard import LiveDashboard


class MonitoringController:
    def __init__(
        self,
        monitoring_loop: MonitoringLoop,
        dashboard: LiveDashboard,
        keyboard: KeyboardController,
        executable_acquirer: ExecutableAcquirer | None = None,
        memory_acquirer: MemoryAcquirer | None = None,
    ):
        self.monitoring_loop = monitoring_loop
        self.dashboard = dashboard
        self.keyboard = keyboard
        self.executable_acquirer = (
            executable_acquirer or ExecutableAcquirer()
        )
        self.memory_acquirer = memory_acquirer or MemoryAcquirer()

        self.stop_event = Event()
        self.keyboard_stop_event = Event()
        self.snapshot_requested = Event()
        self.snapshot_exit_event = Event()

        self.recording_enabled = False

        self._state_lock = Lock()
        self._last_result = None

    def _display_message(self, message: str) -> None:
        """Display a message through the dashboard."""
        display_message = getattr(
            self.dashboard,
            "display_message",
            None,
        )

        if callable(display_message):
            display_message(message)

    def _get_snapshot_process(self, pid: int) -> dict | None:
        """Find a process in the frozen snapshot."""
        with self._state_lock:
            if self._last_result is None:
                return None

            processes = self._last_result.get("processes", [])

            return next(
                (
                    process
                    for process in processes
                    if process.get("pid") == pid
                ),
                None,
            )

    def _acquire_executable(self, process: dict) -> None:
        """Acquire the executable after explicit user confirmation."""
        try:
            result = self.executable_acquirer.acquire(process)

        except Exception as exc:
            self._display_message(
                f"[red]Acquisition failed:[/red] {exc}"
            )
            return

        self._display_message(
            "[green]Executable acquired successfully.[/green]"
        )
        self._display_message(
            f"Executable: {result['executable_path']}"
        )
        self._display_message(
            f"Manifest: {result['manifest_path']}"
        )
        self._display_message(
            f"SHA-256: {result['sha256']}"
        )

    def _acquire_memory(self, process: dict) -> None:
        """Acquire a full process memory dump after confirmation."""
        try:
            memory_dir = EVIDENCE_DIR / "memory"
            memory_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now(timezone.utc).strftime(
                "%Y%m%d_%H%M%S"
            )
            unique_id = uuid.uuid4().hex[:8]

            destination = memory_dir / (
                f"process_{process['pid']}_{timestamp}_{unique_id}.dmp"
            )

            result = self.memory_acquirer.execute(
                "acquire_memory",
                pid=process["pid"],
                destination=str(destination),
            )

            if not result.get("success"):
                raise RuntimeError(result.get("message", "Memory acquisition failed"))

        except Exception as exc:
            self._display_message(
                f"[red]Memory acquisition failed:[/red] {exc}"
            )
            return

        self._display_message(
            "[green]Process memory acquired successfully.[/green]"
        )
        self._display_message(
            f"Memory dump: {result['dump_path']}"
        )
        self._display_message(
            f"SHA-256: {result['sha256']}"
        )
        self._display_message(
            f"Manifest: {result['manifest_path']}"
        )

    
    def _find_memory_dumps(self, pid: int) -> list[Path]:
        """Find memory dumps belonging to a specific process."""
        memory_dir = EVIDENCE_DIR / "memory"

        if not memory_dir.is_dir():
            return []

        return sorted(
            memory_dir.glob(f"process_{pid}_*.dmp"),
            key=lambda path: path.name,
            reverse=True,
        )


    def _list_memory_regions(self, dump_path: str) -> list[dict]:
        """Retrieve memory region metadata from an existing minidump."""
        try:
            result = self.memory_acquirer.execute(
                "list_memory_regions",
                destination=dump_path,
            )

            if not result.get("success"):
                raise RuntimeError(
                    result.get("message", "Memory region listing failed")
                )

            regions = result.get("memory_region_details", [])

            self._display_message(
                f"[green]Found {len(regions)} memory regions.[/green]"
            )

            return regions

        except Exception as exc:
            self._display_message(
                f"[red]Memory region listing failed:[/red] {exc}"
            )
            return []


    def _inspect_memory(
        self,
        dump_path: str,
        address: int,
        length: int,
    ) -> None:
        """Inspect a virtual memory range in an existing minidump."""
        try:
            result = self.memory_acquirer.execute(
                "inspect_memory",
                destination=dump_path,
                address=address,
                length=length,
                bytes_per_line=16,
            )

            if not result.get("success"):
                raise RuntimeError(
                    result.get("message", "Memory inspection failed")
                )

        except Exception as exc:
            self._display_message(
                f"[red]Memory inspection failed:[/red] {exc}"
            )
            return

        self._display_message(
            "[green]Memory inspection successful.[/green]"
        )
        self._display_message(result.get("message", ""))
   

    def _read_keyboard(self) -> None:
        """Read keyboard input independently of process scanning."""
        input_state = "snapshot"
        pid_buffer = ""
        selected_process = None
        selected_acquisition = "executable"
        input_buffer = ""
        inspection_path = ""
        inspection_address = 0

        while not self.keyboard_stop_event.is_set():
            key = self.keyboard.read_key()

            if key:
                if input_state == "pid":
                    if key.isdigit():
                        pid_buffer += key
                        self._display_message(
                            f"Enter process PID: {pid_buffer}"
                        )

                    elif key in ("\r", "\n"):
                        if not pid_buffer:
                            self._display_message(
                                "[yellow]No PID entered.[/yellow]"
                            )
                            input_state = "snapshot"
                            selected_acquisition = "executable"
                        else:
                            process = self._get_snapshot_process(
                                int(pid_buffer)
                            )

                            if process is None:
                                self._display_message(
                                    "[red]PID not found in the frozen snapshot.[/red]"
                                )
                                input_state = "snapshot"
                                selected_acquisition = "executable"

                           
                            elif selected_acquisition == "inspection":
                                dumps = self._find_memory_dumps(process["pid"])

                                if not dumps:
                                    self._display_message(
                                        f"[yellow]No memory dumps found for PID "
                                        f"{process['pid']}.[/yellow]"
                                    )
                                    input_state = "snapshot"
                                else:
                                    inspection_path = str(dumps[0])

                                    self._display_message(
                                        f"[green]Found {len(dumps)} memory "
                                        f"dump(s) for PID {process['pid']}.[/green]"
                                    )
                                    self._display_message(
                                        f"Selected newest dump: {inspection_path}"
                                    )

                                    regions = self._list_memory_regions(inspection_path)

                                    if not regions:
                                        self._display_message(
                                            "[yellow]No memory regions available for inspection.[/yellow]"
                                        )
                                        input_state = "snapshot"
                                    else:
                                        input_buffer = ""
                                        input_state = "inspect_region"

                                        self._display_message(
                                            "Available memory regions:"
                                        )

                                        for index, region in enumerate(regions, start=1):
                                            permissions = region.get("permissions") or "unknown"

                                            self._display_message(
                                                f"{index}. Start: 0x{region['start_address']:X} | "
                                                f"Size: {region['size']} bytes | "
                                                f"Permissions: {permissions}"
                                            )

                                        self._display_message(
                                            f"Enter a region number (1-{len(regions)}), "
                                            "then press Enter. Press Escape to cancel."
                                        )

                                selected_acquisition = "executable"

                            elif process.get("identity_type") != "strong":
                                self._display_message(
                                    "[red]Acquisition requires a strong process identity.[/red]"
                                )
                                input_state = "snapshot"
                                selected_acquisition = "executable"

                            elif not process.get("executable"):
                                self._display_message(
                                    "[red]Executable path is unavailable.[/red]"
                                )
                                input_state = "snapshot"
                                selected_acquisition = "executable"

                            else:
                                selected_process = process
                                input_state = "confirmation"

                                if selected_acquisition == "memory":
                                    self._display_message(
                                        "WARNING: This will capture the process's full memory, "
                                        "which may contain sensitive data."
                                    )
                                    self._display_message(
                                        "Acquire this process memory? Press Y to confirm or N to cancel."
                                    )
                                else:
                                    self._display_message(
                                        f"Process: {process.get('name', 'Unknown')}"
                                    )
                                    self._display_message(
                                        f"Executable: {process['executable']}"
                                    )
                                    self._display_message(
                                        "Acquire this executable? Press Y to confirm or N to cancel."
                                    )

                    elif key in ("\b", "\x7f"):
                        pid_buffer = pid_buffer[:-1]
                        self._display_message(
                            f"Enter process PID: {pid_buffer}"
                        )

                    elif key == "\x1b":
                        self._display_message(
                            "[yellow]Operation cancelled.[/yellow]"
                        )
                        input_state = "snapshot"
                        selected_acquisition = "executable"

                    elif key.lower() == "q":
                        self.snapshot_exit_event.set()
                        break

                
                elif input_state == "inspect_region":
                    if key in ("\r", "\n"):
                        try:
                            region_number = int(input_buffer.strip())

                            if not 1 <= region_number <= len(regions):
                                raise ValueError

                            selected_region = regions[region_number - 1]
                            region_address = selected_region["start_address"]
                            region_size = selected_region["size"]

                            if region_size <= 0:
                                raise ValueError

                            inspection_length = min(256, region_size)

                            self._display_message(
                                f"Inspecting region at 0x{region_address:X} "
                                f"for {inspection_length} bytes."
                            )

                            self._inspect_memory(
                                dump_path=inspection_path,
                                address=region_address,
                                length=inspection_length,
                            )

                            input_buffer = ""
                            inspection_path = ""
                            input_state = "snapshot"

                        except (ValueError, KeyError, TypeError):
                            self._display_message(
                                "[red]Invalid region selection.[/red]"
                            )
                            input_buffer = ""

                    elif key in ("\b", "\x7f"):
                        input_buffer = input_buffer[:-1]
                        self._display_message(
                            f"Region number: {input_buffer}"
                        )

                    elif key == "\x1b":
                        self._display_message(
                            "[yellow]Memory inspection cancelled.[/yellow]"
                        )
                        input_buffer = ""
                        inspection_path = ""
                        input_state = "snapshot"

                    elif key.lower() == "q":
                        self._display_message(
                            "[yellow]Memory inspection cancelled.[/yellow]"
                        )
                        input_buffer = ""
                        inspection_path = ""
                        input_state = "snapshot"

                    elif key.isdigit():
                        input_buffer += key
                        self._display_message(
                            f"Region number: {input_buffer}"
                        )


                elif input_state in (
                        "inspect_path",
                        "inspect_address",
                        "inspect_length",
                ):
                        if key in ("\r", "\n"):
                            if input_state == "inspect_path":
                                path = Path(input_buffer.strip().strip('"'))

                                if not input_buffer.strip():
                                    self._display_message(
                                        "[red]Dump path is required.[/red]"
                                    )
                                elif not path.is_file():
                                    self._display_message(
                                        "[red]Dump file does not exist.[/red]"
                                    )
                                else:
                                    inspection_path = str(path)
                                    input_buffer = ""
                                    input_state = "inspect_address"
                                    self._display_message(
                                        "Enter the virtual memory address in hexadecimal:"
                                    )

                            elif input_state == "inspect_address":
                                try:
                                    address = int(input_buffer.strip(), 16)

                                    if not 0 <= address <= 0xFFFFFFFFFFFFFFFF:
                                        raise ValueError

                                    inspection_address = address
                                    input_buffer = ""
                                    input_state = "inspect_length"

                                    self._display_message(
                                        "Enter the number of bytes to inspect (1-4096):"
                                    )

                                except ValueError:
                                    self._display_message(
                                        "[red]Invalid hexadecimal address.[/red]"
                                    )

                            elif input_state == "inspect_length":
                                try:
                                    length = int(input_buffer.strip())

                                    if not 1 <= length <= 4096:
                                        raise ValueError

                                    self._inspect_memory(
                                        dump_path=inspection_path,
                                        address=inspection_address,
                                        length=length,
                                    )

                                    input_buffer = ""
                                    inspection_path = ""
                                    inspection_address = 0
                                    input_state = "snapshot"

                                except ValueError:
                                    self._display_message(
                                        "[red]Length must be between 1 and 4096.[/red]"
                                    )

                        elif key in ("\b", "\x7f"):
                            input_buffer = input_buffer[:-1]
                            self._display_message(input_buffer)

                        elif key == "\x1b":
                            self._display_message(
                                "[yellow]Memory inspection cancelled.[/yellow]"
                            )
                            input_buffer = ""
                            inspection_path = ""
                            inspection_address = 0
                            input_state = "snapshot"

                        else:
                            input_buffer += key
                            self._display_message(input_buffer)

                elif input_state == "confirmation":
                        if key.lower() == "y":
                            if selected_acquisition == "memory":
                                self._acquire_memory(selected_process)
                            else:
                                self._acquire_executable(selected_process)

                            selected_process = None
                            selected_acquisition = "executable"
                            input_state = "snapshot"

                        elif key.lower() == "n" or key == "\x1b":
                            self._display_message(
                                "[yellow]Acquisition cancelled.[/yellow]"
                            )
                            selected_process = None
                            selected_acquisition = "executable"
                            input_state = "snapshot"

                        elif key.lower() == "q":
                            self.snapshot_exit_event.set()
                            break

                else:
                        key = key.lower()

                        if key == "r" and not self.stop_event.is_set():
                            with self._state_lock:
                                self.recording_enabled = (
                                    not self.recording_enabled
                                )

                                if self._last_result is not None:
                                    self.dashboard.update(
                                        self._last_result,
                                        recording_enabled=self.recording_enabled,
                                    )

                        elif key == "n":
                            with self._state_lock:
                                self.dashboard.next_page()

                        elif key == "p":
                            with self._state_lock:
                                self.dashboard.previous_page()

                        elif key == "s":
                            if not self.stop_event.is_set():
                                self.snapshot_requested.set()
                                self.stop_event.set()

                        elif key in ("a", "m") and self.snapshot_requested.is_set():
                            selected_acquisition = (
                                "memory" if key == "m" else "executable"
                            )
                            pid_buffer = ""
                            input_state = "pid"

                            operation = (
                                "memory acquisition"
                                if selected_acquisition == "memory"
                                else "executable acquisition"
                            )

                            self._display_message(
                                f"Enter the PID for {operation}. "
                                "Press Enter to continue or Escape to cancel."
                            )

                        elif key == "i" and self.snapshot_requested.is_set():
                            pid_buffer = ""
                            inspection_path = ""
                            selected_acquisition = "inspection"
                            input_state = "pid"

                            self._display_message(
                                "Enter the PID whose memory dump you want to inspect. "
                                "Press Enter to continue or Escape to cancel."
                            )

                        elif key == "q":
                            self.stop_event.set()
                            self.snapshot_exit_event.set()
                            break

            self.keyboard_stop_event.wait(0.05)

    def run(self) -> None:
        self.stop_event.clear()
        self.keyboard_stop_event.clear()
        self.snapshot_requested.clear()
        self.snapshot_exit_event.clear()

        with self._state_lock:
            self.recording_enabled = False
            self._last_result = None

        def is_recording() -> bool:
            with self._state_lock:
                return self.recording_enabled

        def on_scan(result: dict) -> None:
            # Preserve the last complete snapshot when scanning is stopped.
            if self.stop_event.is_set():
                return

            with self._state_lock:
                self._last_result = result

                self.dashboard.update(
                    result,
                    recording_enabled=self.recording_enabled,
                )

        keyboard_thread = None

        try:
            self.keyboard.start()
            self.dashboard.start()

            keyboard_thread = Thread(
                target=self._read_keyboard,
                name="KeyboardMonitor",
                daemon=True,
            )
            keyboard_thread.start()

            self.monitoring_loop.run(
                stop_event=self.stop_event,
                is_recording=is_recording,
                on_scan=on_scan,
            )

            # S stops scanning but leaves the snapshot visible.
            # Wait until Q is pressed before returning to the menu.
            if self.snapshot_requested.is_set():
                self.snapshot_exit_event.wait()

        finally:
            self.keyboard_stop_event.set()

            if keyboard_thread is not None:
                keyboard_thread.join(timeout=1.0)

            try:
                self.dashboard.stop()
            finally:
                self.keyboard.stop()
