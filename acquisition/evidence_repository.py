
import json
from pathlib import Path

from config.settings import EVIDENCE_DIR


class EvidenceRepository:
    """Discover and manage acquired executable evidence."""

    def __init__(self, evidence_dir: str | Path = EVIDENCE_DIR):
        self.acquisitions_dir = Path(evidence_dir) / "acquisitions"

    def _read_manifest(self, manifest_path: Path) -> dict:
        """Read and validate one acquisition manifest."""

        try:
            if manifest_path.is_symlink():
                raise ValueError("Manifest must not be a symbolic link")

            with manifest_path.open("r", encoding="utf-8") as file:
                manifest = json.load(file)

            if not isinstance(manifest, dict):
                raise ValueError("Manifest must contain a JSON object")

            process = manifest.get("process")
            artifact = manifest.get("artifact")

            if not isinstance(process, dict):
                raise ValueError("Invalid process information")

            if not isinstance(artifact, dict):
                raise ValueError("Invalid artifact information")

            file_name = artifact.get("file_name")

            if (
                not isinstance(file_name, str)
                or not file_name
                or file_name in (".", "..")
                or "/" in file_name
                or "\\" in file_name
            ):
                raise ValueError("Invalid executable filename")

            executable_path = manifest_path.parent / file_name

            if executable_path.is_symlink():
                raise ValueError("Executable must not be a symbolic link")

            return {
                "manifest_valid": True,
                "manifest_error": None,
                "manifest_path": str(manifest_path.resolve()),
                "executable_path": str(executable_path.resolve()),
                "executable_available": executable_path.is_file(),
                "acquisition_id": manifest.get("acquisition_id"),
                "status": manifest.get("status"),
                "acquired_at": manifest.get("acquired_at"),
                "pid": process.get("pid"),
                "process_name": process.get("name"),
                "file_name": file_name,
                "size_bytes": artifact.get("size_bytes"),
                "sha256": artifact.get("sha256"),
            }

        except (OSError, json.JSONDecodeError, ValueError) as exc:
            return {
                "manifest_valid": False,
                "manifest_error": str(exc),
                "manifest_path": str(manifest_path),
                "executable_path": None,
                "executable_available": False,
                "acquisition_id": None,
                "status": "invalid",
                "acquired_at": None,
                "pid": None,
                "process_name": None,
                "file_name": None,
                "size_bytes": None,
                "sha256": None,
            }

    def list_acquisitions(self) -> list[dict]:
        """Return acquisition records, newest first."""

        if not self.acquisitions_dir.is_dir():
            return []

        records = [
            self._read_manifest(manifest_path)
            for manifest_path in self.acquisitions_dir.rglob("manifest.json")
            if manifest_path.is_file()
        ]

        return sorted(
            records,
            key=lambda record: record.get("acquired_at") or "",
            reverse=True,
        )

    def clear_executables(self, confirmation: str) -> int:
        """Delete acquired executable files while preserving manifests."""

        if confirmation != "DELETE":
            raise ValueError(
                'Confirmation must be exactly "DELETE"'
            )

        deleted_count = 0

        for record in self.list_acquisitions():
            if (
                not record["manifest_valid"]
                or not record["executable_available"]
            ):
                continue

            executable_path = Path(record["executable_path"])

            # Recheck before deletion to avoid following a replaced symlink.
            if executable_path.is_symlink() or not executable_path.is_file():
                continue

            executable_path.unlink()
            deleted_count += 1

        return deleted_count
