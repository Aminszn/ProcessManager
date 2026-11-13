
import json

import pytest

from acquisition.evidence_repository import EvidenceRepository


def create_acquisition(
    root,
    folder_name="process_123_test",
    acquired_at="2026-11-11T10:00:00+00:00",
    file_name="example.exe",
    executable_exists=True,
):
    acquisition_dir = root / "acquisitions" / "2026-11-11" / folder_name
    acquisition_dir.mkdir(parents=True)

    executable_path = acquisition_dir / file_name

    if executable_exists:
        executable_path.write_bytes(b"test executable content")

    manifest = {
        "schema_version": 1,
        "acquisition_id": folder_name,
        "status": "success",
        "acquired_at": acquired_at,
        "process": {
            "pid": 123,
            "name": "example.exe",
        },
        "artifact": {
            "file_name": file_name,
            "size_bytes": 23,
            "sha256": "test-hash",
        },
    }

    manifest_path = acquisition_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    return manifest_path, executable_path


def test_list_acquisitions_returns_empty_when_directory_does_not_exist(
    tmp_path,
):
    repository = EvidenceRepository(tmp_path)

    assert repository.list_acquisitions() == []


def test_list_acquisitions_returns_manifest_information(tmp_path):
    manifest_path, executable_path = create_acquisition(tmp_path)

    repository = EvidenceRepository(tmp_path)

    records = repository.list_acquisitions()

    assert len(records) == 1

    record = records[0]

    assert record["manifest_valid"] is True
    assert record["manifest_error"] is None
    assert record["manifest_path"] == str(manifest_path.resolve())
    assert record["executable_path"] == str(executable_path.resolve())
    assert record["executable_available"] is True
    assert record["acquisition_id"] == "process_123_test"
    assert record["status"] == "success"
    assert record["pid"] == 123
    assert record["process_name"] == "example.exe"
    assert record["file_name"] == "example.exe"
    assert record["size_bytes"] == 23
    assert record["sha256"] == "test-hash"


def test_list_acquisitions_sorts_newest_first(tmp_path):
    create_acquisition(
        tmp_path,
        folder_name="older",
        acquired_at="2026-11-10T10:00:00+00:00",
    )
    create_acquisition(
        tmp_path,
        folder_name="newer",
        acquired_at="2026-11-11T10:00:00+00:00",
    )

    repository = EvidenceRepository(tmp_path)

    records = repository.list_acquisitions()

    assert [record["acquisition_id"] for record in records] == [
        "newer",
        "older",
    ]


def test_list_acquisitions_reports_missing_executable(tmp_path):
    create_acquisition(
        tmp_path,
        executable_exists=False,
    )

    repository = EvidenceRepository(tmp_path)

    records = repository.list_acquisitions()

    assert len(records) == 1
    assert records[0]["manifest_valid"] is True
    assert records[0]["executable_available"] is False


def test_list_acquisitions_reports_invalid_json_manifest(tmp_path):
    acquisition_dir = (
        tmp_path / "acquisitions" / "2026-11-11" / "invalid"
    )
    acquisition_dir.mkdir(parents=True)

    manifest_path = acquisition_dir / "manifest.json"
    manifest_path.write_text("{invalid json", encoding="utf-8")

    repository = EvidenceRepository(tmp_path)

    records = repository.list_acquisitions()

    assert len(records) == 1
    assert records[0]["manifest_valid"] is False
    assert records[0]["status"] == "invalid"
    assert records[0]["manifest_error"] is not None


def test_list_acquisitions_rejects_invalid_executable_filename(tmp_path):
    acquisition_dir = (
        tmp_path / "acquisitions" / "2026-11-11" / "invalid"
    )
    acquisition_dir.mkdir(parents=True)

    manifest = {
        "process": {"pid": 123, "name": "example.exe"},
        "artifact": {
            "file_name": "../outside.exe",
            "size_bytes": 10,
            "sha256": "test-hash",
        },
    }

    (acquisition_dir / "manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    repository = EvidenceRepository(tmp_path)

    records = repository.list_acquisitions()

    assert len(records) == 1
    assert records[0]["manifest_valid"] is False
    assert records[0]["executable_path"] is None


def test_clear_executables_requires_exact_confirmation(tmp_path):
    _, executable_path = create_acquisition(tmp_path)

    repository = EvidenceRepository(tmp_path)

    with pytest.raises(ValueError, match="DELETE"):
        repository.clear_executables("delete")

    assert executable_path.exists()


def test_clear_executables_deletes_files_and_preserves_manifests(
    tmp_path,
):
    manifest_one, executable_one = create_acquisition(
        tmp_path,
        folder_name="first",
    )
    manifest_two, executable_two = create_acquisition(
        tmp_path,
        folder_name="second",
    )

    repository = EvidenceRepository(tmp_path)

    deleted_count = repository.clear_executables("DELETE")

    assert deleted_count == 2

    assert not executable_one.exists()
    assert not executable_two.exists()

    assert manifest_one.exists()
    assert manifest_two.exists()


def test_clear_executables_skips_missing_executables(tmp_path):
    manifest_path, _ = create_acquisition(
        tmp_path,
        executable_exists=False,
    )

    repository = EvidenceRepository(tmp_path)

    deleted_count = repository.clear_executables("DELETE")

    assert deleted_count == 0
    assert manifest_path.exists()


def test_clear_executables_skips_invalid_manifests(tmp_path):
    acquisition_dir = (
        tmp_path / "acquisitions" / "2026-11-11" / "invalid"
    )
    acquisition_dir.mkdir(parents=True)

    manifest_path = acquisition_dir / "manifest.json"
    manifest_path.write_text("{invalid json", encoding="utf-8")

    unrelated_executable = acquisition_dir / "example.exe"
    unrelated_executable.write_bytes(b"test executable content")

    repository = EvidenceRepository(tmp_path)

    deleted_count = repository.clear_executables("DELETE")

    assert deleted_count == 0
    assert manifest_path.exists()
    assert unrelated_executable.exists()


def test_clear_executables_returns_zero_when_no_acquisitions_exist(
    tmp_path,
):
    repository = EvidenceRepository(tmp_path)

    assert repository.clear_executables("DELETE") == 0
