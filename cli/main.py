
from acquisition.evidence_repository import EvidenceRepository
from cli.evidence_controller import EvidenceController
from cli.keyboard import KeyboardController
from cli.monitoring_controller import MonitoringController
from config.settings import DEFAULT_POLL_INTERVAL
from database.connection import get_connection
from database.repository import ProcessRepository
from database.schema import initialize_database
from monitoring.monitor import MonitoringLoop
from monitoring.monitoring_service import MonitoringService
from visualization.evidence_browser import EvidenceBrowser
from visualization.live_dashboard import LiveDashboard


def run_application() -> None:
    connection = get_connection()

    try:
        initialize_database(connection)

        monitoring_controller = None

        while True:
            print("\n================================")
            print("       PROCESS MONITOR")
            print("================================")
            print("1. Start live monitoring")
            print("2. Browse acquired evidence")
            print("3. Exit")

            try:
                choice = input("\nSelect an option: ").strip()
            except EOFError:
                break

            if choice == "1":
                if monitoring_controller is None:
                    repository = ProcessRepository(connection)
                    service = MonitoringService(repository)

                    monitoring_loop = MonitoringLoop(
                        service=service,
                        poll_interval=DEFAULT_POLL_INTERVAL,
                    )

                    dashboard = LiveDashboard()
                    keyboard = KeyboardController()

                    monitoring_controller = MonitoringController(
                        monitoring_loop=monitoring_loop,
                        dashboard=dashboard,
                        keyboard=keyboard,
                    )

                print("\nStarting live monitoring...")
                print("Press R to toggle database recording.")
                print("Press S to freeze the current snapshot.")
                print("After freezing:")
                print("  Press A to acquire a process executable.")
                print("  Press M to acquire a full process memory dump.")
                print("  Press N/P to navigate process pages.")
                print("  Press Q to return to the main menu.")
                print("\nMemory dumps may contain sensitive information.\n")

                monitoring_controller.run()

            elif choice == "2":
                evidence_repository = EvidenceRepository()
                evidence_browser = EvidenceBrowser()
                evidence_keyboard = KeyboardController()

                evidence_controller = EvidenceController(
                    repository=evidence_repository,
                    browser=evidence_browser,
                    keyboard=evidence_keyboard,
                )

                print("\nOpening Evidence Browser...")

                evidence_controller.run()

            elif choice == "3":
                print("\nExiting Process Monitor.")
                break

            else:
                print("\nInvalid option. Please select 1, 2, or 3.")

    finally:
        connection.close()


def main() -> None:
    try:
        run_application()
    except KeyboardInterrupt:
        print("\nProcess Monitor interrupted. Exiting.")


if __name__ == "__main__":
    main()
