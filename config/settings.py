
from pathlib import Path


# Project root directory
BASE_DIR = Path(__file__).resolve().parent.parent


# Application information
APP_NAME = "ProcessMonitor"
APP_VERSION = "0.1.0"


# Storage directories
DATA_DIR = BASE_DIR / "data"
EVIDENCE_DIR = BASE_DIR / "evidence"


# SQLite database
DATABASE_PATH = DATA_DIR / "process_monitor.db"


# Monitoring configuration
DEFAULT_POLL_INTERVAL = 1.0


# Timestamp configuration
TIMEZONE = "UTC"

# Rust memory service
RUST_MEMORY_EXECUTABLE = (
    BASE_DIR / "rust_memory" / "target" / "debug" / "rust_memory.exe"
)