
from math import ceil

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


class EvidenceBrowser:
    """Display acquired executable evidence in the terminal."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()
        self._records = []
        self._current_page = 0

    def _get_page_size(self) -> int:
        return max(1, self.console.height - 8)

    def _get_page_count(self) -> int:
        page_size = self._get_page_size()

        return max(1, ceil(len(self._records) / page_size))

    def _get_page_records(self) -> list[dict]:
        page_size = self._get_page_size()
        start = self._current_page * page_size
        end = start + page_size

        return self._records[start:end]

    @staticmethod
    def _get_status(record: dict) -> str:
        if not record.get("manifest_valid"):
            return "[red]Invalid manifest[/red]"

        if record.get("executable_available"):
            return "[green]Available[/green]"

        return "[yellow]Manifest only[/yellow]"

    @staticmethod
    def _format_size(size_bytes) -> str:
        if not isinstance(size_bytes, (int, float)):
            return "Unknown"

        if size_bytes < 0:
            return "Unknown"

        if size_bytes < 1024:
            return f"{size_bytes} B"

        if size_bytes < 1024**2:
            return f"{size_bytes / 1024:.2f} KB"

        if size_bytes < 1024**3:
            return f"{size_bytes / (1024**2):.2f} MB"

        return f"{size_bytes / (1024**3):.2f} GB"

    def render(self) -> Panel:
        """Build the acquisition records table."""

        table = Table(
            title="Acquired Executable Evidence",
            expand=True,
        )

        table.add_column("#", justify="right", width=4)
        table.add_column("Executable", min_width=15)
        table.add_column("PID", justify="right", width=8)
        table.add_column("Acquired", min_width=20)
        table.add_column("Size", justify="right", width=12)
        table.add_column("Status", min_width=16)

        page_records = self._get_page_records()
        page_size = self._get_page_size()

        for index, record in enumerate(page_records):
            record_number = (
                self._current_page * page_size + index + 1
            )

            acquired_at = record.get("acquired_at") or "Unknown"

            if len(acquired_at) > 25:
                acquired_at = acquired_at[:25]

            table.add_row(
                str(record_number),
                record.get("file_name") or "Unknown",
                str(record.get("pid") or "Unknown"),
                acquired_at,
                self._format_size(record.get("size_bytes")),
                self._get_status(record),
            )

        if not self._records:
            table.add_row(
                "-",
                "No acquisitions found",
                "-",
                "-",
                "-",
                "-",
            )

        page_count = self._get_page_count()

        footer = (
            f"Page {self._current_page + 1}/{page_count}"
            f" | Total records: {len(self._records)}"
        )

        return Panel(
            table,
            title="Process Monitor - Evidence Browser",
            subtitle=footer,
        )

    def update(self, records: list[dict]) -> None:
        """Replace the displayed acquisition records."""

        self._records = list(records)
        self._current_page = 0

    def next_page(self) -> None:
        """Move to the next page."""

        if self._current_page < self._get_page_count() - 1:
            self._current_page += 1

    def previous_page(self) -> None:
        """Move to the previous page."""

        if self._current_page > 0:
            self._current_page -= 1

    def get_selected_record(self, index: int) -> dict | None:
        """Return a record by its overall displayed number (1-based)."""

        if isinstance(index, bool) or not isinstance(index, int):
            return None

        if index < 1 or index > len(self._records):
            return None

        return self._records[index - 1]

    def display_details(self, record: dict) -> None:
        """Display detailed information about one acquisition."""

        details = Table.grid(padding=(0, 2))
        details.add_column(style="bold cyan")
        details.add_column()

        details.add_row("Executable", record.get("file_name") or "Unknown")
        details.add_row("Process", record.get("process_name") or "Unknown")
        details.add_row("PID", str(record.get("pid") or "Unknown"))
        details.add_row("Acquired", record.get("acquired_at") or "Unknown")
        details.add_row("Status", self._get_status(record))
        details.add_row(
            "Size",
            self._format_size(record.get("size_bytes")),
        )
        details.add_row("SHA-256", record.get("sha256") or "Unknown")
        details.add_row(
            "Executable path",
            record.get("executable_path") or "Unavailable",
        )
        details.add_row(
            "Manifest path",
            record.get("manifest_path") or "Unavailable",
        )

        self.console.print(
            Panel(
                details,
                title="Acquisition Details",
                expand=True,
            )
        )
