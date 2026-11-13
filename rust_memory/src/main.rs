mod extraction_manifest;
mod forensic;
mod hashing;
mod manifest;
mod memory_dumps;

use std::fs::{self, OpenOptions};
use std::io::BufWriter;

use serde::{Deserialize, Serialize};
use std::io::{self, BufRead};
use std::path::Path;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

use forensic::extraction_verifier::verify_extraction;
use forensic::memory_image::{AddressSpace, MemoryImageReader};
use forensic::minidump_reader::MinidumpReader;

#[derive(Debug, Deserialize)]
struct Request {
    action: String,
    pid: Option<u32>,
    destination: Option<String>,
    address: Option<u64>,
    length: Option<usize>,
    bytes_per_line: Option<usize>,
    min_length: Option<usize>,
}

#[derive(Debug, Serialize)]
struct MemoryRegionResponse {
    start_address: u64,
    size: u64,
    address_space: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    permissions: Option<String>,
}

#[derive(Debug, Serialize)]
struct Response {
    success: bool,
    action: String,
    message: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    process_id: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    executable_path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    dump_path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    output_path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    strings_extracted: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    architecture: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    memory_regions: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    memory_region_details: Option<Vec<MemoryRegionResponse>>,
}

fn main() {
    let stdin = io::stdin();
    let mut input = String::new();

    if let Err(error) = stdin.lock().read_line(&mut input) {
        send_response(Response {
            success: false,
            action: "unknown".to_string(),
            message: format!("Failed to read request: {error}"),
            process_id: None,
            executable_path: None,
            dump_path: None,
            sha256: None,
            manifest_path: None,
            output_path: None,
            strings_extracted: None,
            architecture: None,
            memory_regions: None,
            memory_region_details: None,
        });
        return;
    }

    match serde_json::from_str::<Request>(&input) {
        Ok(request) => {
            let response = match request.action.as_str() {
                "ping" => Response {
                    success: true,
                    action: "ping".to_string(),
                    message: "Rust memory service is ready".to_string(),
                    process_id: None,
                    executable_path: None,
                    dump_path: None,
                    sha256: None,
                    manifest_path: None,
                    output_path: None,
                    strings_extracted: None,
                    architecture: None,
                    memory_regions: None,
                    memory_region_details: None,
                },

                "process_info" => match request.pid {
                    Some(pid) => match get_process_path(pid) {
                        Ok(path) => Response {
                            success: true,
                            action: "process_info".to_string(),
                            message: "Process information retrieved".to_string(),
                            process_id: Some(pid),
                            executable_path: Some(path),
                            dump_path: None,
                            sha256: None,
                            manifest_path: None,
                            output_path: None,
                            strings_extracted: None,
                            architecture: None,
                            memory_regions: None,
                            memory_region_details: None,
                        },

                        Err(error) => Response {
                            success: false,
                            action: "process_info".to_string(),
                            message: error,
                            process_id: Some(pid),
                            executable_path: None,
                            dump_path: None,
                            sha256: None,
                            manifest_path: None,
                            output_path: None,
                            strings_extracted: None,
                            architecture: None,
                            memory_regions: None,
                            memory_region_details: None,
                        },
                    },

                    None => error_response("process_info", "Missing required field: pid"),
                },

                "acquire_memory" => match (request.pid, request.destination) {
                    (Some(pid), Some(destination)) => acquire_memory(pid, &destination),

                    (None, _) => error_response("acquire_memory", "Missing required field: pid"),

                    (_, None) => {
                        error_response("acquire_memory", "Missing required field: destination")
                    }
                },
                "list_memory_regions" => match request.destination.as_deref() {
                    Some(path) => list_memory_regions(path),
                    None => {
                        error_response("list_memory_regions", "Missing required field: destination")
                    }
                },
                "inspect_memory" => {
                    match (
                        request.destination.as_deref(),
                        request.address,
                        request.length,
                    ) {
                        (Some(path), Some(address), Some(length)) => inspect_memory(
                            path,
                            address,
                            length,
                            request.bytes_per_line.unwrap_or(16),
                        ),

                        (None, _, _) => {
                            error_response("inspect_memory", "Missing required field: destination")
                        }

                        (_, None, _) => {
                            error_response("inspect_memory", "Missing required field: address")
                        }

                        (_, _, None) => {
                            error_response("inspect_memory", "Missing required field: length")
                        }
                    }
                }

                "extract_strings" => match request.destination.as_deref() {
                    Some(path) => extract_strings(path, request.min_length.unwrap_or(4)),
                    None => {
                        error_response("extract_strings", "Missing required field: destination")
                    }
                },

                "verify_extraction" => match request.destination.as_deref() {
                    Some(path) => match verify_extraction(Path::new(path)) {
                        Ok(result) => Response {
                            success: true,
                            action: "verify_extraction".to_string(),
                            message: format!(
                                "Extraction verification successful\n\
                 Source size: {} bytes\n\
                 Output size: {} bytes\n\
                 Verified strings: {}",
                                result.source_size_bytes,
                                result.output_size_bytes,
                                result.strings_verified,
                            ),
                            process_id: None,
                            executable_path: None,
                            sha256: None,
                            dump_path: None,
                            manifest_path: Some(path.to_string()),
                            output_path: None,
                            strings_extracted: None,
                            architecture: None,
                            memory_regions: None,
                            memory_region_details: None,
                        },

                        Err(error) => error_response("verify_extraction", &error),
                    },

                    None => {
                        error_response("verify_extraction", "Missing required field: destination")
                    }
                },
                "verify_acquisition" => match request.destination.as_deref() {
                    Some(path) => match manifest::verify_manifest(Path::new(path)) {
                        Ok(()) => Response {
                            success: true,
                            action: "verify_acquisition".to_string(),
                            message: "Acquisition manifest verification successful".to_string(),
                            process_id: None,
                            executable_path: None,
                            dump_path: None,
                            sha256: None,
                            manifest_path: Some(path.to_string()),
                            output_path: None,
                            strings_extracted: None,
                            architecture: None,
                            memory_regions: None,
                            memory_region_details: None,
                        },

                        Err(error) => error_response("verify_acquisition", &error),
                    },

                    None => {
                        error_response("verify_acquisition", "Missing required field: destination")
                    }
                },
                "hash_file" => match request.destination.as_deref() {
                    Some(path) => match hashing::calculate_sha256(Path::new(path)) {
                        Ok(hash) => Response {
                            success: true,
                            action: "hash_file".to_string(),
                            message: "SHA-256 calculated successfully".to_string(),
                            process_id: None,
                            executable_path: None,
                            dump_path: Some(path.to_string()),
                            sha256: Some(hash),
                            manifest_path: None,
                            output_path: None,
                            strings_extracted: None,
                            architecture: None,
                            memory_regions: None,
                            memory_region_details: None,
                        },

                        Err(error) => error_response("hash_file", &error),
                    },

                    None => error_response("hash_file", "Missing required field: destination"),
                },

                _ => error_response(&request.action, "Unsupported action"),
            };

            send_response(response);
        }

        Err(error) => send_response(Response {
            success: false,
            action: "unknown".to_string(),
            message: format!("Invalid JSON request: {error}"),
            process_id: None,
            executable_path: None,
            dump_path: None,
            sha256: None,
            manifest_path: None,
            output_path: None,
            strings_extracted: None,
            architecture: None,
            memory_regions: None,
            memory_region_details: None,
        }),
    }
}

fn acquire_memory(pid: u32, destination: &str) -> Response {
    let dump_path = Path::new(destination);

    // Capture process information before acquisition.
    let executable_path = match get_process_path(pid) {
        Ok(path) => path,
        Err(error) => {
            return error_response("acquire_memory", &error);
        }
    };

    // Create the full memory dump.
    if let Err(error) = memory_dumps::write_full_memory_dump(pid, dump_path) {
        return error_response("acquire_memory", &error);
    }

    // Calculate the dump's SHA-256 hash.
    let sha256 = match hashing::calculate_sha256(dump_path) {
        Ok(hash) => hash,

        Err(error) => {
            return cleanup_failed_acquisition(dump_path, &error);
        }
    };

    // Generate the acquisition manifest.
    let manifest_path =
        match manifest::write_manifest(dump_path, pid, executable_path.clone(), sha256.clone()) {
            Ok(path) => path,

            Err(error) => {
                return cleanup_failed_acquisition(dump_path, &error);
            }
        };

    Response {
        success: true,
        action: "acquire_memory".to_string(),
        message: "Memory dump, SHA-256 hash, and acquisition manifest created successfully"
            .to_string(),
        process_id: Some(pid),
        executable_path: Some(executable_path),
        dump_path: Some(dump_path.to_string_lossy().into_owned()),
        sha256: Some(sha256),
        manifest_path: Some(manifest_path.to_string_lossy().into_owned()),
        output_path: None,
        strings_extracted: None,
        architecture: None,
        memory_regions: None,
        memory_region_details: None,
    }
}

fn inspect_memory(
    destination: &str,
    address: u64,
    length: usize,
    bytes_per_line: usize,
) -> Response {
    const MAX_INSPECTION_BYTES: usize = 4096;

    if length == 0 {
        return error_response(
            "inspect_memory",
            "Inspection length must be greater than zero",
        );
    }

    if length > MAX_INSPECTION_BYTES {
        return error_response(
            "inspect_memory",
            "Inspection length cannot exceed 4096 bytes",
        );
    }

    if bytes_per_line == 0 || bytes_per_line > 64 {
        return error_response("inspect_memory", "Bytes per line must be between 1 and 64");
    }

    let reader = match MinidumpReader::open(destination) {
        Ok(reader) => reader,
        Err(error) => return error_response("inspect_memory", &error),
    };

    let regions = match reader.memory_regions() {
        Ok(regions) => regions,
        Err(error) => return error_response("inspect_memory", &error),
    };

    let bytes = match reader.read_memory(address, length, AddressSpace::Virtual) {
        Ok(bytes) => bytes,
        Err(error) => return error_response("inspect_memory", &error),
    };

    let formatted = match forensic::memory_viewer::format_hex_ascii(address, &bytes, bytes_per_line)
    {
        Ok(output) => output,
        Err(error) => return error_response("inspect_memory", &error),
    };

    let architecture = reader.metadata().architecture.clone();

    let region_details: Vec<MemoryRegionResponse> = regions
        .iter()
        .map(|region| MemoryRegionResponse {
            start_address: region.start_address,
            size: region.size,
            address_space: match region.address_space {
                AddressSpace::Virtual => "virtual".to_string(),
                AddressSpace::Physical => "physical".to_string(),
            },
            permissions: region.permissions.clone(),
        })
        .collect();

    Response {
        success: true,
        action: "inspect_memory".to_string(),
        message: format!(
            "Memory inspection successful\n\
             File: {destination}\n\
             Address: 0x{address:016X}\n\
             Bytes read: {}\n\
             Captured memory regions: {}\n\n\
             {formatted}",
            bytes.len(),
            regions.len(),
        ),
        process_id: None,
        executable_path: None,
        dump_path: Some(destination.to_string()),
        sha256: None,
        manifest_path: None,
        output_path: None,
        strings_extracted: None,
        architecture,
        memory_regions: Some(regions.len()),
        memory_region_details: Some(region_details),
    }
}

fn list_memory_regions(destination: &str) -> Response {
    let reader = match MinidumpReader::open(destination) {
        Ok(reader) => reader,
        Err(error) => return error_response("list_memory_regions", &error),
    };

    let regions = match reader.memory_regions() {
        Ok(regions) => regions,
        Err(error) => return error_response("list_memory_regions", &error),
    };

    let region_details: Vec<MemoryRegionResponse> = regions
        .iter()
        .map(|region| MemoryRegionResponse {
            start_address: region.start_address,
            size: region.size,
            address_space: match region.address_space {
                AddressSpace::Virtual => "virtual".to_string(),
                AddressSpace::Physical => "physical".to_string(),
            },
            permissions: region.permissions.clone(),
        })
        .collect();

    Response {
        success: true,
        action: "list_memory_regions".to_string(),
        message: format!(
            "Memory regions retrieved successfully\n\
             File: {destination}\n\
             Total regions: {}",
            regions.len(),
        ),
        process_id: None,
        executable_path: None,
        dump_path: Some(destination.to_string()),
        sha256: None,
        manifest_path: None,
        output_path: None,
        strings_extracted: None,
        architecture: reader.metadata().architecture.clone(),
        memory_regions: Some(regions.len()),
        memory_region_details: Some(region_details),
    }
}

fn extract_strings(destination: &str, min_length: usize) -> Response {
    if min_length == 0 {
        return error_response(
            "extract_strings",
            "Minimum string length must be greater than zero",
        );
    }

    let reader = match MinidumpReader::open(destination) {
        Ok(reader) => reader,
        Err(error) => return error_response("extract_strings", &error),
    };

    let source_path = Path::new(destination);
    let output_path = source_path.with_extension(format!("strings-min-{min_length}.jsonl"));

    let file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)
    {
        Ok(file) => file,
        Err(error) => {
            return error_response(
                "extract_strings",
                &format!(
                    "Could not create output file {}: {}",
                    output_path.display(),
                    error
                ),
            );
        }
    };

    let mut writer = BufWriter::new(file);

    let total_count = match forensic::string_extractor::write_strings_from_image(
        &reader,
        min_length,
        &mut writer,
    ) {
        Ok(count) => count,
        Err(error) => {
            drop(writer);
            let _ = fs::remove_file(&output_path);
            return error_response("extract_strings", &error);
        }
    };

    if let Err(error) = writer.get_ref().sync_all() {
        drop(writer);
        let _ = fs::remove_file(&output_path);

        return error_response(
            "extract_strings",
            &format!("Could not synchronize output file: {error}"),
        );
    }

    drop(writer);

    // Hash the original memory image.
    let source_sha256 = match hashing::calculate_sha256(source_path) {
        Ok(hash) => hash,
        Err(error) => {
            return error_response(
                "extract_strings",
                &format!(
                    "Extraction completed, but source hashing failed. Output preserved at {}. Error: {error}",
                    output_path.display()
                ),
            );
        }
    };

    // Hash the completed JSONL output.
    let output_sha256 = match hashing::calculate_sha256(&output_path) {
        Ok(hash) => hash,
        Err(error) => {
            return error_response(
                "extract_strings",
                &format!(
                    "Extraction completed, but output hashing failed. Output preserved at {}. Error: {error}",
                    output_path.display()
                ),
            );
        }
    };

    // Create the extraction manifest.
    let manifest_path = match extraction_manifest::write_extraction_manifest(
        source_path,
        &output_path,
        source_sha256,
        output_sha256.clone(),
        min_length,
        total_count,
    ) {
        Ok(path) => path,
        Err(error) => {
            return error_response(
                "extract_strings",
                &format!(
                    "Extraction completed, but manifest creation failed. Output preserved at {}. Error: {error}",
                    output_path.display()
                ),
            );
        }
    };

    let architecture = reader.metadata().architecture.clone();

    Response {
        success: true,
        action: "extract_strings".to_string(),
        message: format!(
            "Memory string extraction successful\n\
             File: {destination}\n\
             Output: {}\n\
             Manifest: {}\n\
             Minimum string length: {min_length}\n\
             Total strings extracted: {total_count}\n\
             Output format: JSONL",
            output_path.display(),
            manifest_path.display()
        ),
        process_id: None,
        executable_path: None,
        dump_path: Some(destination.to_string()),
        sha256: Some(output_sha256),
        manifest_path: Some(manifest_path.to_string_lossy().into_owned()),
        output_path: Some(output_path.to_string_lossy().into_owned()),
        strings_extracted: Some(total_count),
        architecture,
        memory_regions: None,
        memory_region_details: None,
    }
}

fn cleanup_failed_acquisition(dump_path: &Path, original_error: &str) -> Response {
    match std::fs::remove_file(dump_path) {
        Ok(()) => error_response(
            "acquire_memory",
            &format!("Acquisition failed: {original_error}. Incomplete dump removed."),
        ),

        Err(cleanup_error) => error_response(
            "acquire_memory",
            &format!(
                "Acquisition failed: {original_error}. Could not remove incomplete dump: {cleanup_error}"
            ),
        ),
    }
}

fn get_process_path(pid: u32) -> Result<String, String> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .map_err(|error| format!("Could not open process {pid}: {error}"))?;

    let mut buffer = vec![0u16; 32768];
    let mut size = buffer.len() as u32;

    let query_result = unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
    };

    let close_result = unsafe { CloseHandle(process) };

    query_result
        .map_err(|error| format!("Could not retrieve executable path for PID {pid}: {error}"))?;

    close_result
        .map_err(|error| format!("Could not close process handle for PID {pid}: {error}"))?;

    String::from_utf16(&buffer[..size as usize])
        .map_err(|error| format!("Invalid executable path encoding: {error}"))
}

fn error_response(action: &str, message: &str) -> Response {
    Response {
        success: false,
        action: action.to_string(),
        message: message.to_string(),
        process_id: None,
        executable_path: None,
        dump_path: None,
        sha256: None,
        manifest_path: None,
        output_path: None,
        strings_extracted: None,
        architecture: None,
        memory_regions: None,
        memory_region_details: None,
    }
}

fn send_response(response: Response) {
    println!(
        "{}",
        serde_json::to_string(&response).expect("Failed to serialize response")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_serializes_memory_region_details() {
        let response = Response {
            success: true,
            action: "inspect_memory".to_string(),
            message: "Memory inspection successful".to_string(),
            process_id: None,
            executable_path: None,
            dump_path: Some("test.dmp".to_string()),
            sha256: None,
            manifest_path: None,
            output_path: None,
            strings_extracted: None,
            architecture: Some("x86_64".to_string()),
            memory_regions: Some(1),
            memory_region_details: Some(vec![MemoryRegionResponse {
                start_address: 0x1000,
                size: 4096,
                address_space: "virtual".to_string(),
                permissions: None,
            }]),
        };

        let json = serde_json::to_value(response).unwrap();

        assert_eq!(json["memory_regions"], 1);
        assert_eq!(json["memory_region_details"][0]["start_address"], 0x1000);
        assert_eq!(json["memory_region_details"][0]["size"], 4096);
        assert_eq!(json["memory_region_details"][0]["address_space"], "virtual");
        assert!(
            json["memory_region_details"][0]
                .get("permissions")
                .is_none()
        );
    }
    #[test]
    fn list_memory_regions_returns_region_details() {
        let response =
            list_memory_regions("../evidence/memory/process_1064_20261112_234810_b5b4e498.dmp");

        assert!(response.success);
        assert_eq!(response.action, "list_memory_regions");
        assert_eq!(response.memory_regions, Some(290));

        let regions = response.memory_region_details.unwrap();

        assert_eq!(regions.len(), 290);
        assert_eq!(regions[0].address_space, "virtual");
        assert!(regions[0].size > 0);
    }

    #[test]
    fn list_memory_regions_rejects_missing_dump() {
        let response = list_memory_regions("nonexistent.dmp");

        assert!(!response.success);
        assert_eq!(response.action, "list_memory_regions");
        assert!(response.memory_region_details.is_none());
    }
}
