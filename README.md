# ProcessMonitor

A Windows-focused process monitoring and forensic evidence acquisition application built with Python and Rust.

ProcessMonitor combines process monitoring, executable acquisition, and memory acquisition in one application. Python handles the application workflow and user interface, while Rust provides the native Windows memory acquisition and analysis capabilities.

## Current Features

### 1. Process Monitoring

- Live process monitoring.
- Process information collection.
- Process snapshot functionality.
- Process navigation and monitoring controls.

### 2. Executable Acquisition

- Acquire executable files associated with monitored processes.
- Preserve acquired executable evidence.
- Generate and retain acquisition metadata.
- Browse acquired executable evidence through the application.
- View evidence details.
- Copy executable paths for use with external analysis tools.
- Clear acquired executable copies through an explicit confirmation while preserving their manifests.

Acquired executables can be opened separately in tools such as Ghidra for static analysis.

Ghidra is an external tool; ProcessMonitor does not currently provide native Ghidra integration.

### 3. Windows Memory Acquisition

The Rust memory subsystem supports full-memory Windows minidump acquisition.

Implemented capabilities include:

- Process memory acquisition using Windows `MiniDumpWriteDump`.
- Full-memory minidump generation.
- Memory dump format validation.
- Acquisition manifests.
- SHA-256 hashing.
- Acquisition manifest verification.
- Minidump parsing.
- Memory region enumeration.
- Virtual memory region inspection.
- ASCII and UTF-16LE string extraction.
- Extraction manifests.
- Extraction verification.

Memory acquisition produces a `.dmp` file and a corresponding JSON acquisition manifest.

String extraction produces JSONL output and a separate extraction manifest.

**Current integration status:** Memory acquisition is accessible through the monitoring workflow. The Rust backend also supports memory inspection, region listing, string extraction, and verification. However, memory evidence browsing and interactive inspection are not yet integrated into the main application navigation.

### 4. Python and Rust Integration

Python communicates with the Rust memory executable through a JSON request/response interface.

The Python `MemoryAcquirer` provides:

- Rust executable path configuration.
- JSON request serialization.
- Subprocess execution.
- Execution timeout handling.
- Process error handling.
- JSON response validation.

This keeps the application workflow in Python while delegating native memory acquisition and analysis operations to Rust.

## Architecture

```text
                    ProcessMonitor
                          |
             +------------+------------+
             |                         |
       Python Application        Rust Memory Engine
             |                         |
      +------+-------+          +------+--------+
      |              |          |               |
  Monitoring    Acquisition  Acquisition    Minidump
  Workflow      Controllers  Engine         Analysis
      |              |          |               |
      +------+-------+          +-------+-------+
             |                          |
       Process Data                Memory Evidence
             |                          |
       Executable Evidence       Dumps and Manifests
```

### Main Project Components

| Directory | Responsibility |
|---|---|
| `acquisition/` | Executable and memory acquisition interfaces |
| `cli/` | Application entry point, controllers, and keyboard interaction |
| `collectors/` | Process information collection |
| `config/` | Application configuration |
| `core/` | Core application functionality, where applicable |
| `database/` | Database functionality |
| `data/` | Runtime application data |
| `evidence/` | Acquired forensic evidence |
| `monitoring/` | Monitoring functionality |
| `platform_support/` | Platform-specific functionality |
| `rust_memory/` | Native Rust memory acquisition and analysis |
| `tests/` | Automated tests |
| `visualization/` | Monitoring visualization |

## Current Application Workflow

### Home Page

The current application provides three main options:

1. **Start Live Monitoring**
   - Enter the monitoring workflow.
   - View process information.
   - Freeze a process snapshot.
   - Acquire executable or memory evidence through the available controls.

2. **Browse Acquired Evidence**
   - Browse acquired executable evidence.
   - View evidence details.
   - Copy executable paths.
   - Manage acquired executable copies.

3. **Exit**
   - Close the application.

### Executable Acquisition Flow

```text
Start Application
       |
Start Live Monitoring
       |
Freeze Process Snapshot
       |
Select Executable Acquisition
       |
Enter Process ID
       |
Confirm Acquisition
       |
Acquire Executable
       |
Generate Evidence Metadata
       |
Browse Acquired Evidence
       |
Copy Executable Path
       |
Open in External Analysis Tool
```

### Memory Acquisition Flow

```text
Start Application
       |
Start Live Monitoring
       |
Freeze Process Snapshot
       |
Select Memory Acquisition
       |
Enter Process ID
       |
Confirm Acquisition
       |
Python MemoryAcquirer
       |
Rust Memory Service
       |
Windows MiniDumpWriteDump
       |
Generate Memory Dump
       |
Generate Acquisition Manifest
       |
Verify Acquisition Manifest
```

Memory evidence is stored under:

```text
evidence/
    memory/
        process_<pid>_<timestamp>_<id>.dmp
        process_<pid>_<timestamp>_<id>.json
```

The Rust backend also provides separate actions for inspecting memory regions, extracting strings, and verifying extraction manifests.

## Technology Stack

- **Python** — Application workflow, monitoring, acquisition orchestration, and CLI.
- **Rust** — Native memory acquisition and forensic processing.
- **Windows API** — Process access and minidump generation.
- **pytest** — Python testing.
- **Cargo** — Rust build and testing.
- **SHA-256** — Evidence integrity verification.
- **JSON / JSONL** — Requests, responses, manifests, and extracted strings.

## Requirements

- Windows
- Python 3
- Rust toolchain
- Cargo
- Required Python dependencies from `requirements.txt`

## Setup

Clone the repository:

```powershell
git clone <repository-url>
cd ProcessMonitor
```

Create and activate a Python virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install Python dependencies:

```powershell
pip install -r requirements.txt
```

Build the Rust memory service:

```powershell
cd rust_memory
cargo build
cd ..
```

## Running the Application

From the project root:

```powershell
python -m cli.main
```

## Running Tests

Python tests:

```powershell
pytest
```

Rust tests:

```powershell
cd rust_memory
cargo test
```

Rust build verification:

```powershell
cargo build
```

## Evidence Integrity

Memory acquisition and extraction produce manifests containing metadata used to verify the associated evidence.

The Rust service supports:

- Acquisition manifest verification.
- Extraction manifest verification.
- SHA-256 integrity checks.
- File size validation.
- Minidump format validation.
- Extraction output validation.

Evidence files should be preserved separately from source code and should not be committed to the repository.

## Current Scope and Limitations

ProcessMonitor currently focuses on Windows process monitoring and memory acquisition.

The following distinctions are important:

- Memory acquisition works through the Python application and Rust backend.
- Memory inspection and extraction capabilities exist in the Rust backend, but their full interactive workflow is not yet exposed through the home page.
- The main evidence browser currently focuses on executable acquisition evidence rather than providing a unified browser for all memory artifacts.
- Ghidra is used externally for executable analysis.
- ELF core dump parsing is not currently implemented.
- Acquired memory dumps and extracted strings may contain sensitive process data and should be handled as forensic evidence.

## Project Objective

ProcessMonitor aims to provide a practical process-monitoring and forensic acquisition workflow, combining Python application development with Rust systems programming and Windows internals.

**Understand systems. Build reliable tools. Preserve evidence integrity.**