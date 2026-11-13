
import hashlib
import json
import math
import os
import shutil
import tempfile
import uuid

from datetime import datetime, timezone
from pathlib import Path

import psutil

from config.settings import APP_NAME, APP_VERSION, EVIDENCE_DIR


class ExecutableAcquirer:
    """Acquire an executable file for authorized forensic analysis."""

    def __init__(
        self,
        evidence_dir: str | Path = EVIDENCE_DIR,
    ):
        self.evidence_dir = Path(evidence_dir)

    @staticmethod
    def _verify_process_identity(process: dict) -> None:
        """Verify that the PID still belongs to the snapshotted process."""

        pid = process.get("pid")
        create_time = process.get("create_time")
        identity_type = process.get("identity_type")

        if (
            isinstance(pid, bool)
            or not isinstance(pid, int)
            or pid <= 0
        ):
            raise ValueError("Invalid process PID")

        if identity_type != "strong":
            raise ValueError(
                "Executable acquisition requires a strong process identity"
            )

        if (
            isinstance(create_time, bool)
            or not isinstance(create_time, (int, float))
            or not math.isfinite(create_time)
            or create_time <= 0
        ):
            raise ValueError("Invalid process creation time")

        try:
            current_process = psutil.Process(pid)

            current_create_time = current_process.create_time()
            current_executable = current_process.exe()

        except psutil.Error as exc:
            raise RuntimeError(
                f"Unable to verify process identity: {exc}"
            ) from exc

        if not math.isclose(
            float(create_time),
            current_create_time,
            rel_tol=0,
            abs_tol=0.001,
        ):
            raise RuntimeError(
                "Process identity changed. The PID may have been reused."
            )

        expected_executable = process.get("executable")

        if not expected_executable:
            raise ValueError("Process executable path is unavailable")

        if (
            os.path.normcase(os.path.realpath(expected_executable))
            != os.path.normcase(os.path.realpath(current_executable))
        ):
            raise RuntimeError(
                "The process executable path no longer matches the snapshot"
            )

    @staticmethod
    def _get_file_signature(file_stat) -> tuple:
        return (
            file_stat.st_dev,
            file_stat.st_ino,
            file_stat.st_size,
            file_stat.st_mtime_ns,
        )

    @staticmethod
    def _copy_and_hash(
        source: Path,
        destination: Path,
    ) -> tuple[str, int]:
        """Copy a file while calculating its SHA-256 hash."""

        file_hash = hashlib.sha256()
        bytes_copied = 0

        with source.open("rb") as source_file:
            initial_stat = os.fstat(source_file.fileno())

            if not os.path.isfile(source):
                raise ValueError("Source is not a regular file")

            with destination.open("wb") as destination_file:
                while chunk := source_file.read(1024 * 1024):
                    destination_file.write(chunk)
                    file_hash.update(chunk)
                    bytes_copied += len(chunk)

                destination_file.flush()
                os.fsync(destination_file.fileno())

            final_stat = os.fstat(source_file.fileno())

        if (
            ExecutableAcquirer._get_file_signature(initial_stat)
            != ExecutableAcquirer._get_file_signature(final_stat)
        ):
            raise RuntimeError(
                "Source executable changed during acquisition"
            )

        if bytes_copied != initial_stat.st_size:
            raise RuntimeError(
                "Acquired file size does not match source file size"
            )

        shutil.copystat(source, destination)

        return file_hash.hexdigest(), bytes_copied

    def acquire(self, process: dict) -> dict:
        """Acquire the executable belonging to a snapshotted process."""

        if not isinstance(process, dict):
            raise ValueError("Process must be a dictionary")

        self._verify_process_identity(process)

        source = Path(process["executable"])

        if not source.is_file():
            raise FileNotFoundError(
                f"Executable file not found: {source}"
            )

        acquired_at = datetime.now(timezone.utc)

        acquisition_id = str(uuid.uuid4())

        acquisition_dir = (
            self.evidence_dir
            / "acquisitions"
            / acquired_at.strftime("%Y-%m-%d")
            / f"process_{process['pid']}_{acquisition_id[:8]}"
        )

        acquisition_dir.mkdir(parents=True, exist_ok=False)

        destination = acquisition_dir / source.name

        temporary_path = None

        try:
            file_descriptor, temporary_name = tempfile.mkstemp(
                prefix=".acquiring_",
                dir=acquisition_dir,
            )

            os.close(file_descriptor)
            temporary_path = Path(temporary_name)

            source_stat = source.stat()

            sha256, size_bytes = self._copy_and_hash(
                source,
                temporary_path,
            )

            if (
                self._get_file_signature(source_stat)
                != self._get_file_signature(source.stat())
            ):
                raise RuntimeError(
                    "Source executable changed during acquisition"
                )

            os.replace(temporary_path, destination)
            temporary_path = None

            manifest = {
                "schema_version": 1,
                "acquisition_id": acquisition_id,
                "status": "success",
                "acquired_at": acquired_at.isoformat(),
                "tool": {
                    "name": APP_NAME,
                    "version": APP_VERSION,
                },
                "process": {
                    "pid": process["pid"],
                    "name": process.get("name"),
                    "create_time": process["create_time"],
                    "identity_type": process["identity_type"],
                    "identity_key": process.get("identity_key"),
                },
                "source": {
                    "path": str(source.resolve()),
                    "size_bytes": source_stat.st_size,
                    "modified_at": datetime.fromtimestamp(
                        source_stat.st_mtime,
                        timezone.utc,
                    ).isoformat(),
                },
                "artifact": {
                    "file_name": destination.name,
                    "size_bytes": size_bytes,
                    "sha256": sha256,
                },
            }

            manifest_path = acquisition_dir / "manifest.json"
            temporary_manifest = acquisition_dir / ".manifest.tmp"

            try:
                with temporary_manifest.open(
                    "w",
                    encoding="utf-8",
                ) as manifest_file:
                    json.dump(
                        manifest,
                        manifest_file,
                        indent=4,
                    )
                    manifest_file.write("\n")
                    manifest_file.flush()
                    os.fsync(manifest_file.fileno())

                os.replace(temporary_manifest, manifest_path)

            finally:
                temporary_manifest.unlink(missing_ok=True)

            return {
                "status": "success",
                "acquisition_id": acquisition_id,
                "executable_path": str(destination),
                "manifest_path": str(manifest_path),
                "sha256": sha256,
                "size_bytes": size_bytes,
            }

        except Exception:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

            destination.unlink(missing_ok=True)

            try:
                acquisition_dir.rmdir()
            except OSError:
                pass

            raise
