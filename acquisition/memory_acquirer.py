
import json
import subprocess

from pathlib import Path

from config.settings import RUST_MEMORY_EXECUTABLE


class MemoryAcquirer:
    """Interface to the Rust memory acquisition service."""

    def __init__(
        self,
        executable_path: str | Path = RUST_MEMORY_EXECUTABLE,
        timeout_seconds: int = 300,
    ):
        self.executable_path = Path(executable_path)

        if timeout_seconds <= 0:
            raise ValueError("Timeout must be greater than zero")

        self.timeout_seconds = timeout_seconds

    def execute(self, action: str, **parameters) -> dict:
        """Send a JSON request to the Rust memory service."""

        if not action:
            raise ValueError("Action is required")

        if not self.executable_path.is_file():
            raise FileNotFoundError(
                f"Rust memory executable not found: {self.executable_path}"
            )

        request = {
            "action": action,
            **parameters,
        }

        try:
            result = subprocess.run(
                [str(self.executable_path)],
                input=json.dumps(request),
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )

        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                "Rust memory service execution timed out"
            ) from exc

        except OSError as exc:
            raise RuntimeError(
                f"Could not execute Rust memory service: {exc}"
            ) from exc

        if result.returncode != 0:
            raise RuntimeError(
                f"Rust memory service failed: {result.stderr.strip()}"
            )

        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Rust memory service returned invalid JSON"
            ) from exc

        if not isinstance(response, dict):
            raise RuntimeError(
                "Rust memory service returned an invalid response"
            )

        return response
