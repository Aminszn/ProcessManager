
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import psutil
import pytest

from acquisition.executable_acquirer import ExecutableAcquirer


@pytest.fixture
def executable_file(tmp_path):
    source = tmp_path / "sample.exe"
    source.write_bytes(b"sample executable content")
    return source


@pytest.fixture
def process_snapshot(executable_file):
    return {
        "pid": 1234,
        "name": "sample.exe",
        "create_time": 1000.0,
        "executable": str(executable_file),
        "identity_type": "strong",
        "identity_key": "1234:1000",
    }


@pytest.fixture
def acquirer(tmp_path):
    return ExecutableAcquirer(
        evidence_dir=tmp_path / "evidence"
    )


def mock_process_identity(mock_process):
    mock_process.create_time.return_value = 1000.0
    mock_process.exe.return_value = str(mock_process._executable_path)


def test_acquire_copies_executable(
    acquirer,
    process_snapshot,
    executable_file,
):
    with patch(
        "acquisition.executable_acquirer.psutil.Process"
    ) as mock_process:
        mock_process.return_value.create_time.return_value = 1000.0
        mock_process.return_value.exe.return_value = str(
            executable_file
        )

        result = acquirer.acquire(process_snapshot)

    acquired_file = Path(result["executable_path"])

    assert result["status"] == "success"
    assert acquired_file.exists()
    assert acquired_file.read_bytes() == executable_file.read_bytes()


def test_acquire_generates_correct_sha256(
    acquirer,
    process_snapshot,
    executable_file,
):
    expected_hash = hashlib.sha256(
        executable_file.read_bytes()
    ).hexdigest()

    with patch(
        "acquisition.executable_acquirer.psutil.Process"
    ) as mock_process:
        mock_process.return_value.create_time.return_value = 1000.0
        mock_process.return_value.exe.return_value = str(
            executable_file
        )

        result = acquirer.acquire(process_snapshot)

    assert result["sha256"] == expected_hash


def test_acquire_generates_manifest(
    acquirer,
    process_snapshot,
    executable_file,
):
    with patch(
        "acquisition.executable_acquirer.psutil.Process"
    ) as mock_process:
        mock_process.return_value.create_time.return_value = 1000.0
        mock_process.return_value.exe.return_value = str(
            executable_file
        )

        result = acquirer.acquire(process_snapshot)

    manifest_path = Path(result["manifest_path"])

    assert manifest_path.exists()

    manifest = json.loads(
        manifest_path.read_text(encoding="utf-8")
    )

    assert manifest["status"] == "success"
    assert manifest["process"]["pid"] == 1234
    assert manifest["process"]["name"] == "sample.exe"
    assert manifest["process"]["identity_key"] == "1234:1000"
    assert manifest["source"]["path"] == str(
        executable_file.resolve()
    )
    assert manifest["artifact"]["sha256"] == result["sha256"]
    assert manifest["artifact"]["size_bytes"] == len(
        executable_file.read_bytes()
    )


def test_acquire_rejects_weak_process_identity(
    acquirer,
    process_snapshot,
):
    process_snapshot["identity_type"] = "weak_pid"

    with pytest.raises(ValueError, match="strong process identity"):
        acquirer.acquire(process_snapshot)


def test_acquire_raises_when_executable_is_missing(
    acquirer,
    process_snapshot,
    tmp_path,
):
    missing_file = tmp_path / "missing.exe"
    process_snapshot["executable"] = str(missing_file)

    with patch(
        "acquisition.executable_acquirer.psutil.Process"
    ) as mock_process:
        mock_process.return_value.create_time.return_value = 1000.0
        mock_process.return_value.exe.return_value = str(missing_file)

        with pytest.raises(FileNotFoundError):
            acquirer.acquire(process_snapshot)


def test_acquire_rejects_changed_process_identity(
    acquirer,
    process_snapshot,
    executable_file,
):
    with patch(
        "acquisition.executable_acquirer.psutil.Process"
    ) as mock_process:
        mock_process.return_value.create_time.return_value = 2000.0
        mock_process.return_value.exe.return_value = str(
            executable_file
        )

        with pytest.raises(RuntimeError, match="identity changed"):
            acquirer.acquire(process_snapshot)


def test_acquire_rejects_changed_executable_path(
    acquirer,
    process_snapshot,
    executable_file,
    tmp_path,
):
    different_executable = tmp_path / "different.exe"
    different_executable.write_bytes(b"different executable")

    with patch(
        "acquisition.executable_acquirer.psutil.Process"
    ) as mock_process:
        mock_process.return_value.create_time.return_value = 1000.0
        mock_process.return_value.exe.return_value = str(
            different_executable
        )

        with pytest.raises(RuntimeError, match="path no longer matches"):
            acquirer.acquire(process_snapshot)


def test_failed_acquisition_leaves_no_artifact(
    acquirer,
    process_snapshot,
    executable_file,
):
    with patch(
        "acquisition.executable_acquirer.psutil.Process"
    ) as mock_process:
        mock_process.return_value.create_time.return_value = 2000.0
        mock_process.return_value.exe.return_value = str(
            executable_file
        )

        with pytest.raises(RuntimeError):
            acquirer.acquire(process_snapshot)

    acquisition_root = (
        acquirer.evidence_dir / "acquisitions"
    )

    assert not acquisition_root.exists()
