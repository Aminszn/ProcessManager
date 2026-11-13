
import pytest

from cli import main


class FakeConnection:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeController:
    def __init__(self, *args, **kwargs):
        self.run_called = False

    def run(self):
        self.run_called = True


def configure_dependencies(monkeypatch):
    connection = FakeConnection()
    initialized = {"value": False}
    controller_instances = []

    class FakeRepository:
        def __init__(self, connection):
            self.connection = connection

    class FakeService:
        def __init__(self, repository):
            self.repository = repository

    class FakeLoop:
        def __init__(self, service, poll_interval):
            self.service = service
            self.poll_interval = poll_interval

    class FakeDashboard:
        pass

    class FakeKeyboard:
        def start(self):
            pass

        def read_key(self):
            return "q"

        def stop(self):
            pass

    class TestController(FakeController):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            controller_instances.append(self)

    monkeypatch.setattr(
        main, "get_connection", lambda: connection
    )
    monkeypatch.setattr(
        main, "initialize_database",
        lambda conn: initialized.update(value=True),
    )
    monkeypatch.setattr(main, "ProcessRepository", FakeRepository)
    monkeypatch.setattr(main, "MonitoringService", FakeService)
    monkeypatch.setattr(main, "MonitoringLoop", FakeLoop)
    monkeypatch.setattr(main, "LiveDashboard", FakeDashboard)
    monkeypatch.setattr(main, "KeyboardController", FakeKeyboard)
    monkeypatch.setattr(
        main, "MonitoringController", TestController
    )

    return connection, initialized, controller_instances


def test_exit_option_closes_database_connection(monkeypatch):
    connection, initialized, controllers = configure_dependencies(
        monkeypatch
    )
    monkeypatch.setattr("builtins.input", lambda _: "3")

    main.run_application()

    assert initialized["value"] is True
    assert connection.closed is True
    assert controllers == []


def test_start_option_runs_monitoring_controller(monkeypatch):
    connection, initialized, controllers = configure_dependencies(
        monkeypatch
    )

    choices = iter(["1", "3"])
    monkeypatch.setattr(
        "builtins.input", lambda _: next(choices)
    )

    main.run_application()

    assert len(controllers) == 1
    assert controllers[0].run_called is True
    assert connection.closed is True


def test_invalid_menu_option_returns_to_menu(monkeypatch, capsys):
    connection, initialized, controllers = configure_dependencies(
        monkeypatch
    )

    choices = iter(["invalid", "3"])
    monkeypatch.setattr(
            "builtins.input", lambda _: next(choices)
        )

    main.run_application()

    output = capsys.readouterr().out

    assert "Invalid option" in output
    assert connection.closed is True
    assert controllers == []


def test_eof_exits_application_cleanly(monkeypatch):
    connection, initialized, controllers = configure_dependencies(
        monkeypatch
    )

    def raise_eof(_):
        raise EOFError

    monkeypatch.setattr("builtins.input", raise_eof)

    main.run_application()

    assert connection.closed is True


def test_database_connection_closes_if_initialization_fails(
    monkeypatch,
):
    connection = FakeConnection()

    monkeypatch.setattr(
        main, "get_connection", lambda: connection
    )

    def fail_initialization(conn):
        raise RuntimeError("Database initialization failed")

    monkeypatch.setattr(
        main, "initialize_database", fail_initialization
    )

    with pytest.raises(
        RuntimeError, match="Database initialization failed"
    ):
        main.run_application()

    assert connection.closed is True


def test_monitoring_can_be_started_more_than_once(monkeypatch):
    connection, initialized, controllers = configure_dependencies(
        monkeypatch
    )

    choices = iter(["1", "1", "3"])
    monkeypatch.setattr(
        "builtins.input", lambda _: next(choices)
    )

    main.run_application()

    assert len(controllers) == 1
    assert controllers[0].run_called is True
    assert connection.closed is True
