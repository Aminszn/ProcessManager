
import json
import sys

import pytest

from acquisition.memory_acquirer import MemoryAcquirer
from unittest.mock import patch
from subprocess import TimeoutExpired

@pytest.fixture
def fake_executable(tmp_path):
    executable = tmp_path / "fake_rust_memory.py"
    executable.write_text(
        """
import json
import sys

request = json.loads(sys.stdin.readline())

print(json.dumps({
    "success": True,
    "action": request["action"],
    "message": "Rust memory service is ready"
}))
""",
        encoding="utf-8",
    )
    return executable


@pytest.fixture
def acquirer(fake_executable):
    return MemoryAcquirer(
        executable_path=fake_executable,
        timeout_seconds=5,
    )


def test_execute_returns_json_response(acquirer):
    expected_response = {
        "success": True,
        "action": "ping",
        "message": "Rust memory service is ready",
    }

    with patch(
        "acquisition.memory_acquirer.subprocess.run"
    ) as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = json.dumps(expected_response)
        mock_run.return_value.stderr = ""

        response = acquirer.execute("ping")

    assert response == expected_response

    mock_run.assert_called_once()
    request = json.loads(mock_run.call_args.kwargs["input"])
    assert request["action"] == "ping"


def test_execute_rejects_empty_action(acquirer):
    with pytest.raises(ValueError, match="Action is required"):
        acquirer.execute("")


def test_execute_raises_when_executable_is_missing(tmp_path):
    acquirer = MemoryAcquirer(
        executable_path=tmp_path / "missing.exe"
    )

    with pytest.raises(FileNotFoundError):
        acquirer.execute("ping")


def test_execute_rejects_invalid_timeout(tmp_path):
    with pytest.raises(ValueError, match="Timeout"):
        MemoryAcquirer(
            executable_path=tmp_path / "fake.exe",
            timeout_seconds=0,
        )

def test_execute_rejects_invalid_json(acquirer):
    with patch(
        "acquisition.memory_acquirer.subprocess.run"
    ) as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "not valid json"
        mock_run.return_value.stderr = ""

        with pytest.raises(RuntimeError, match="invalid JSON"):
            acquirer.execute("ping")


def test_execute_raises_on_nonzero_exit(acquirer):
    with patch(
        "acquisition.memory_acquirer.subprocess.run"
    ) as mock_run:
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = "Rust execution failed"

        with pytest.raises(RuntimeError, match="Rust memory service failed"):
            acquirer.execute("ping")


def test_execute_handles_timeout(acquirer):
    with patch(
        "acquisition.memory_acquirer.subprocess.run",
        side_effect=TimeoutExpired(
            cmd="rust_memory.exe",
            timeout=5,
        ),
    ):
        with pytest.raises(RuntimeError, match="timed out"):
            acquirer.execute("ping")

def test_execute_supports_memory_inspection(acquirer):
    expected_response = {
        "success": True,
        "action": "inspect_memory",
        "message": "Memory inspection successful",
    }

    parameters = {
        "destination": "test.dmp",
        "address": 0x0BE9001C,
        "length": 64,
        "bytes_per_line": 16,
    }

    with patch(
        "acquisition.memory_acquirer.subprocess.run"
    ) as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = json.dumps(expected_response)
        mock_run.return_value.stderr = ""

        response = acquirer.execute(
            "inspect_memory",
            **parameters,
        )

    assert response == expected_response

    request = json.loads(mock_run.call_args.kwargs["input"])

    assert request["action"] == "inspect_memory"
    assert request["destination"] == "test.dmp"
    assert request["address"] == 0x0BE9001C
    assert request["length"] == 64
    assert request["bytes_per_line"] == 16


def test_execute_supports_memory_region_listing(acquirer):
    expected_response = {
        "success": True,
        "action": "list_memory_regions",
        "message": "Memory regions retrieved successfully",
        "memory_regions": 290,
        "memory_region_details": [
            {
                "start_address": 199819264,
                "size": 4096,
                "address_space": "virtual",
            }
        ],
    }

    parameters = {
        "destination": "test.dmp",
    }

    with patch(
        "acquisition.memory_acquirer.subprocess.run"
    ) as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = json.dumps(expected_response)
        mock_run.return_value.stderr = ""

        response = acquirer.execute(
            "list_memory_regions",
            **parameters,
        )

    assert response == expected_response

    request = json.loads(mock_run.call_args.kwargs["input"])

    assert request["action"] == "list_memory_regions"
    assert request["destination"] == "test.dmp"
