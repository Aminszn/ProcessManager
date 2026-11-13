use crate::forensic::memory_image::MemoryImageReader;
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

const MINI_DUMP_WITH_FULL_MEMORY: u32 = 0x00000002;

#[link(name = "Dbghelp")]
unsafe extern "system" {
    fn MiniDumpWriteDump(
        process: *mut c_void,
        process_id: u32,
        file: *mut c_void,
        dump_type: u32,
        exception_param: *const c_void,
        user_stream_param: *const c_void,
        callback_param: *const c_void,
    ) -> i32;
}

struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct DumpFileGuard {
    path: PathBuf,
    committed: bool,
}

impl Drop for DumpFileGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub fn write_full_memory_dump(pid: u32, destination: &Path) -> Result<(), String> {
    if pid == 0 {
        return Err("PID 0 cannot be acquired".to_string());
    }

    if destination.exists() {
        return Err(format!(
            "Destination already exists: {}",
            destination.display()
        ));
    }

    let raw_process = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE,
            false,
            pid,
        )
    }
    .map_err(|error| format!("Could not open process {pid}: {error}"))?;

    let process = ProcessHandle(raw_process);

    let file: File = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| format!("Could not create dump file: {error}"))?;

    let mut guard = DumpFileGuard {
        path: destination.to_path_buf(),
        committed: false,
    };

    let result = unsafe {
        MiniDumpWriteDump(
            process.0.0,
            pid,
            file.as_raw_handle() as *mut c_void,
            MINI_DUMP_WITH_FULL_MEMORY,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };

    if result == 0 {
        return Err(format!(
            "MiniDumpWriteDump failed for PID {pid}: {}",
            std::io::Error::last_os_error()
        ));
    }

    file.sync_all()
        .map_err(|error| format!("Could not flush dump file: {error}"))?;

    drop(file);

    let reader = crate::forensic::minidump_reader::MinidumpReader::open(destination)
        .map_err(|error| format!("Created dump failed validation: {error}"))?;

    reader
        .memory_regions()
        .map_err(|error| format!("Created dump memory regions failed validation: {error}"))?;

    drop(reader);

    guard.committed = true;

    Ok(())
}
