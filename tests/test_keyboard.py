
import sys
from unittest.mock import Mock

import pytest

from cli.keyboard import KeyboardController


def test_windows_start_does_not_modify_terminal(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")

    keyboard = KeyboardController()
    keyboard.start()

    assert keyboard._original_terminal_settings is None


def test_posix_start_skips_non_terminal_input(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    keyboard = KeyboardController()
    keyboard.start()

    assert keyboard._original_terminal_settings is None


def test_windows_read_key_returns_available_key(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")

    fake_msvcrt = Mock()
    fake_msvcrt.kbhit.return_value = True
    fake_msvcrt.getwch.return_value = "r"

    monkeypatch.setitem(sys.modules, "msvcrt", fake_msvcrt)

    keyboard = KeyboardController()

    assert keyboard.read_key() == "r"


def test_windows_read_key_returns_none_when_no_key(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")

    fake_msvcrt = Mock()
    fake_msvcrt.kbhit.return_value = False

    monkeypatch.setitem(sys.modules, "msvcrt", fake_msvcrt)

    keyboard = KeyboardController()

    assert keyboard.read_key() is None


def test_windows_special_key_is_ignored(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")

    fake_msvcrt = Mock()
    fake_msvcrt.kbhit.return_value = True
    fake_msvcrt.getwch.side_effect = ["\xe0", "H"]

    monkeypatch.setitem(sys.modules, "msvcrt", fake_msvcrt)

    keyboard = KeyboardController()

    assert keyboard.read_key() is None
    assert fake_msvcrt.getwch.call_count == 2


def test_posix_read_key_returns_none_when_no_input(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")

    select_mock = Mock(return_value=([], [], []))
    monkeypatch.setattr("cli.keyboard.select.select", select_mock)

    keyboard = KeyboardController()

    assert keyboard.read_key() is None


def test_posix_read_key_returns_available_character(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")

    select_mock = Mock(return_value=([sys.stdin], [], []))
    monkeypatch.setattr("cli.keyboard.select.select", select_mock)
    monkeypatch.setattr(sys.stdin, "read", lambda size: "q")

    keyboard = KeyboardController()

    assert keyboard.read_key() == "q"


def test_stop_without_start_is_safe():
    keyboard = KeyboardController()

    keyboard.stop()

    assert keyboard._original_terminal_settings is None
    assert keyboard._terminal_fd is None


def test_windows_stop_does_not_restore_terminal(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")

    keyboard = KeyboardController()
    keyboard.start()
    keyboard.stop()

    assert keyboard._original_terminal_settings is None
