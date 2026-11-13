
import pytest

from platform_support import detector


def test_detect_linux(monkeypatch):
    monkeypatch.setattr(
        detector.platform,
        "system",
        lambda: "Linux"
    )

    assert detector.detect_platform() == "linux"


def test_detect_windows(monkeypatch):
    monkeypatch.setattr(
        detector.platform,
        "system",
        lambda: "Windows"
    )

    assert detector.detect_platform() == "windows"


def test_reject_unsupported_platform(monkeypatch):
    monkeypatch.setattr(
        detector.platform,
        "system",
        lambda: "Darwin"
    )

    with pytest.raises(RuntimeError):
        detector.detect_platform()
