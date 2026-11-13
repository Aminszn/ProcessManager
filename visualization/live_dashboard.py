
from math import ceil

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table


class LiveDashboard:
    """Display live process monitoring results in the terminal."""

    def __init__(self, refresh_per_second: int = 4):
        if (
            isinstance(refresh_per_second, bool)
            or not isinstance(refresh_per_second, int)
            or refresh_per_second <= 0
        ):
            raise ValueError(
                "refresh_per_second must be a positive integer"
            )

        self.console = Console()
        self.live = Live(
            console=self.console,
            refresh_per_second=refresh_per_second,
            screen=False,
            vertical_overflow="crop",
        )

        self._current_page = 0
        self._last_result = None
        self._recording_enabled = False
        self._status_message = None

    @staticmethod
    def format_memory(memory_bytes: int | float | None) -> str:
        if memory_bytes is None:
            return "N/A"

        if (
            isinstance(memory_bytes, bool)
            or not isinstance(memory_bytes, (int, float))
            or memory_bytes < 0
        ):
            return "N/A"

        memory_mb = memory_bytes / (1024 * 1024)
        return f"{memory_mb:.2f} MB"

    def _get_page_size(self) -> int:
        return max(1, self.console.height - 8)

    def render(
        self,
        result: dict,
        recording_enabled: bool = False,
    ) -> Panel:
        processes = sorted(
            result.get("processes", []),
            key=lambda item: item.get("pid", -1),
        )

        total_processes = len(processes)
        page_size = self._get_page_size()

        total_pages = max(1, ceil(total_processes / page_size))
        self._current_page = min(
            self._current_page,
            total_pages - 1,
        )

        start_index = self._current_page * page_size
        end_index = start_index + page_size

        displayed_processes = processes[start_index:end_index]

        # Select columns based on available terminal width.
        if self.console.width >= 140:
            columns = [
                "PID",
                "Process",
                "Status",
                "Username",
                "Memory",
                "Threads",
                "Connections",
            ]
        elif self.console.width >= 100:
            columns = [
                "PID",
                "Process",
                "Status",
                "Memory",
                "Connections",
            ]
        else:
            columns = [
                "PID",
                "Process",
                "Status",
                "Username",
                "Memory",
            ]

        table = Table(title="Current Processes")

        for column in columns:
            table.add_column(
                column,
                justify="right"
                if column in ("PID", "Threads", "Connections")
                else "left",
                no_wrap=True,
                overflow="ellipsis",
            )

        for process in displayed_processes:
            connections = process.get("network_connections", [])

            values = {
                "PID": str(process.get("pid", "N/A")),
                "Process": process.get("name") or "Unknown",
                "Status": process.get("status") or "Unknown",
                "Username": process.get("username") or "Unknown",
                "Memory": self.format_memory(
                    process.get("memory_rss_bytes", 0)
                ),
                "Threads": str(process.get("threads", 0)),
                "Connections": str(len(connections)),
            }

            table.add_row(*(values[column] for column in columns))

        if not displayed_processes:
            values = {
                "PID": "-",
                "Process": "No processes found",
                "Status": "-",
                "Username": "-",
                "Memory": "-",
                "Threads": "-",
                "Connections": "-",
            }

            table.add_row(*(values[column] for column in columns))

        recording_status = (
            "[bold green]ON[/bold green]"
            if recording_enabled
            else "[bold yellow]OFF[/bold yellow]"
        )

        summary_text = (
            f"Processes: [bold]{total_processes}[/bold] "
            f"(showing {len(displayed_processes)})"
            f" | Page: [bold]{self._current_page + 1}"
            f"/{total_pages}[/bold]"
            f" | Connections: [bold]"
            f"{result.get('network_connections_collected', 0)}[/bold]"
            f" | Recording: {recording_status}"
            f" | Failures: [bold]"
            f"{result.get('failures_count', 0)}[/bold]"
        )

        summary = Table.grid(expand=True)
        summary.add_column(no_wrap=True, overflow="ellipsis")
        summary.add_row(summary_text)

        layout = Table.grid(expand=True)
        layout.add_row(summary)
        layout.add_row(table)
        if self._status_message:
            layout.add_row(self._status_message)

        return Panel(
            layout,
            title="Process Monitor",
            border_style="blue",
        )

    def start(self) -> None:
        self.live.start()

    def update(
        self,
        result: dict,
        recording_enabled: bool = False,
    ) -> None:
        self._last_result = result
        self._recording_enabled = recording_enabled

        self.live.update(
            self.render(result, recording_enabled),
            refresh=True,
        )

    def next_page(self) -> None:
        if self._last_result is None:
            return

        processes = self._last_result.get("processes", [])
        total_pages = max(
            1,
            ceil(len(processes) / self._get_page_size()),
        )

        if self._current_page < total_pages - 1:
            self._current_page += 1
            self._refresh_page()

    def previous_page(self) -> None:
        if self._last_result is None:
            return

        if self._current_page > 0:
            self._current_page -= 1
            self._refresh_page()

    def _refresh_page(self) -> None:
        self.live.update(
            self.render(
                self._last_result,
                self._recording_enabled,
            ),
            refresh=True,
        )

    def display_message(self, message: str) -> None:
        """Display a persistent message inside the live dashboard."""
        self._status_message = message

        if self._last_result is not None:
            self.live.update(
                self.render(
                    self._last_result,
                    self._recording_enabled,
                ),
                refresh=True,
            )
        else:
            self.console.print(message)

    def stop(self) -> None:
        self.live.stop()
