use crate::forensic::formats::detect_format;
use crate::forensic::memory_image::MemoryImageFormat;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct AcquisitionManifest {
    pub process_id: u32,
    pub executable_path: String,
    pub dump_path: String,
    pub dump_size_bytes: u64,
    pub sha256: String,
    pub dump_format: String,
    pub acquired_at_unix_seconds: u64,
    pub tool_name: String,
    pub tool_version: String,
}

pub fn write_manifest(
    dump_path: &Path,
    process_id: u32,
    executable_path: String,
    sha256: String,
) -> Result<PathBuf, String> {
    if process_id == 0 {
        return Err("Invalid process ID for acquisition manifest".to_string());
    }

    if executable_path.trim().is_empty() {
        return Err("Executable path is empty for acquisition manifest".to_string());
    }
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Invalid SHA-256 format for acquisition manifest".to_string());
    }
    let metadata = fs::metadata(dump_path)
        .map_err(|error| format!("Could not read dump metadata: {error}"))?;

    if !metadata.is_file() {
        return Err("Acquired dump path is not a file".to_string());
    }
    let detected_format = detect_format(dump_path)
        .map_err(|error| format!("Could not identify acquired dump format: {error}"))?;

    if detected_format != MemoryImageFormat::WindowsMinidump {
        return Err("Acquired dump is not a Windows minidump".to_string());
    }
    let actual_sha256 = crate::hashing::calculate_sha256(dump_path)?;

    if !actual_sha256.eq_ignore_ascii_case(&sha256) {
        return Err("Acquisition dump SHA-256 does not match supplied hash".to_string());
    }
    let acquired_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("Could not obtain acquisition time: {error}"))?
        .as_secs();

    let manifest = AcquisitionManifest {
        process_id,
        executable_path,
        dump_path: dump_path.to_string_lossy().into_owned(),
        dump_size_bytes: metadata.len(),
        sha256,
        dump_format: "MiniDumpWithFullMemory".to_string(),
        acquired_at_unix_seconds: acquired_at,
        tool_name: "ProcessMonitor Rust Memory".to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let manifest_path = dump_path.with_extension("json");

    let serialized = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("Could not serialize manifest: {error}"))?;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest_path)
        .map_err(|error| format!("Could not create manifest: {error}"))?;

    if let Err(error) = file.write_all(&serialized).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&manifest_path);

        return Err(format!("Could not write manifest: {error}"));
    }

    Ok(manifest_path)
}

pub fn verify_manifest(manifest_path: &Path) -> Result<(), String> {
    let content = fs::read(manifest_path)
        .map_err(|error| format!("Could not read acquisition manifest: {error}"))?;

    let manifest: AcquisitionManifest = serde_json::from_slice(&content)
        .map_err(|error| format!("Could not parse acquisition manifest: {error}"))?;

    if manifest.sha256.len() != 64 || !manifest.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("Invalid SHA-256 format in acquisition manifest".to_string());
    }
    if manifest.dump_path.trim().is_empty() {
        return Err("Acquired dump path is empty in manifest".to_string());
    }

    if manifest.dump_format != "MiniDumpWithFullMemory" {
        return Err("Unsupported dump format in acquisition manifest".to_string());
    }
    if manifest.executable_path.trim().is_empty() {
        return Err("Executable path is empty in acquisition manifest".to_string());
    }
    if manifest.process_id == 0 {
        return Err("Invalid process ID in acquisition manifest".to_string());
    }
    if manifest.acquired_at_unix_seconds == 0 {
        return Err("Invalid acquisition timestamp in manifest".to_string());
    }
    let dump_path = Path::new(&manifest.dump_path);

    let metadata = fs::metadata(dump_path)
        .map_err(|error| format!("Could not access acquired dump: {error}"))?;
    if !metadata.is_file() {
        return Err("Acquired dump path is not a file".to_string());
    }
    let detected_format = detect_format(dump_path)
        .map_err(|error| format!("Could not identify acquired dump format: {error}"))?;

    if detected_format != MemoryImageFormat::WindowsMinidump {
        return Err("Acquired dump is not a Windows minidump".to_string());
    }
    if metadata.len() != manifest.dump_size_bytes {
        return Err("Acquired dump size does not match manifest".to_string());
    }

    let actual_sha256 = crate::hashing::calculate_sha256(dump_path)?;

    if !actual_sha256.eq_ignore_ascii_case(&manifest.sha256) {
        return Err("Acquired dump SHA-256 does not match manifest".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AcquisitionManifest, verify_manifest, write_manifest};
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn creates_valid_acquisition_manifest() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let dump_path =
            PathBuf::from(std::env::temp_dir()).join(format!("memory_test_{unique}.dmp"));

        fs::write(&dump_path, b"MDMP test memory dump").expect("Could not create test dump");

        let sha256 = crate::hashing::calculate_sha256(&dump_path).unwrap();

        let result = write_manifest(
            &dump_path,
            1234,
            "C:\\Windows\\test.exe".to_string(),
            sha256,
        );

        let manifest_path = result.expect("Manifest creation failed");

        let content = fs::read(&manifest_path).expect("Could not read manifest");

        let manifest: AcquisitionManifest =
            serde_json::from_slice(&content).expect("Invalid manifest JSON");

        assert_eq!(manifest.process_id, 1234);
        assert_eq!(
            manifest.sha256,
            crate::hashing::calculate_sha256(&dump_path).unwrap()
        );
        assert_eq!(manifest.dump_size_bytes, 21);
        assert_eq!(manifest.dump_format, "MiniDumpWithFullMemory");

        fs::remove_file(&dump_path).unwrap();
        fs::remove_file(&manifest_path).unwrap();
    }

    #[test]
    fn refuses_to_overwrite_existing_acquisition_manifest() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let dump_path =
            PathBuf::from(std::env::temp_dir()).join(format!("memory_test_{unique}.dmp"));

        let manifest_path = dump_path.with_extension("json");

        fs::write(&dump_path, b"MDMP test memory dump").unwrap();
        fs::write(&manifest_path, b"existing manifest").unwrap();

        let sha256 = crate::hashing::calculate_sha256(&dump_path).unwrap();

        let result = write_manifest(
            &dump_path,
            1234,
            "C:\\Windows\\test.exe".to_string(),
            sha256,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Could not create manifest"));

        let existing_content = fs::read(&manifest_path).unwrap();

        assert_eq!(existing_content, b"existing manifest");

        fs::remove_file(&dump_path).unwrap();
        fs::remove_file(&manifest_path).unwrap();
    }

    #[test]
    fn rejects_invalid_sha256_format() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let dump_path =
            PathBuf::from(std::env::temp_dir()).join(format!("memory_test_{unique}.dmp"));

        fs::write(&dump_path, b"MDMP test memory dump").unwrap();

        let result = write_manifest(
            &dump_path,
            1234,
            "C:\\Windows\\test.exe".to_string(),
            "invalid_hash".to_string(),
        );

        assert!(result.unwrap_err().contains("Invalid SHA-256 format"));

        fs::remove_file(&dump_path).unwrap();
    }
    #[test]
    fn verifies_valid_acquisition_manifest() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let dump_path =
            PathBuf::from(std::env::temp_dir()).join(format!("memory_test_{unique}.dmp"));

        fs::write(&dump_path, b"MDMP test memory dump").unwrap();
        let sha256 = crate::hashing::calculate_sha256(&dump_path).unwrap();

        let manifest_path = write_manifest(
            &dump_path,
            1234,
            "C:\\Windows\\test.exe".to_string(),
            sha256,
        )
        .unwrap();

        let result = verify_manifest(&manifest_path);

        assert!(
            result.is_ok(),
            "Valid acquisition manifest should pass verification: {result:?}"
        );

        fs::remove_file(&dump_path).unwrap();
        fs::remove_file(&manifest_path).unwrap();
    }

    #[test]
    fn rejects_modified_acquired_dump() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let dump_path =
            PathBuf::from(std::env::temp_dir()).join(format!("memory_test_{unique}.dmp"));

        fs::write(&dump_path, b"MDMP original memory dump").unwrap();
        let sha256 = crate::hashing::calculate_sha256(&dump_path).unwrap();

        let manifest_path = write_manifest(
            &dump_path,
            1234,
            "C:\\Windows\\test.exe".to_string(),
            sha256,
        )
        .unwrap();

        fs::write(&dump_path, b"MDMP modified memory dump").unwrap();
        let result = verify_manifest(&manifest_path);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Acquired dump SHA-256 does not match manifest"
        );

        fs::remove_file(&dump_path).unwrap();
        fs::remove_file(&manifest_path).unwrap();
    }
    #[test]
    fn rejects_acquired_dump_size_mismatch() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let dump_path =
            PathBuf::from(std::env::temp_dir()).join(format!("memory_test_{unique}.dmp"));

        fs::write(&dump_path, b"MDMP original memory dump").unwrap();
        let sha256 = crate::hashing::calculate_sha256(&dump_path).unwrap();

        let manifest_path = write_manifest(
            &dump_path,
            1234,
            "C:\\Windows\\test.exe".to_string(),
            sha256,
        )
        .unwrap();

        fs::write(&dump_path, b"MDMP").unwrap();
        let result = verify_manifest(&manifest_path);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Acquired dump size does not match manifest"
        );

        fs::remove_file(&dump_path).unwrap();
        fs::remove_file(&manifest_path).unwrap();
    }
    #[test]
    fn rejects_missing_acquired_dump() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let dump_path =
            PathBuf::from(std::env::temp_dir()).join(format!("memory_test_{unique}.dmp"));

        fs::write(&dump_path, b"MDMP test memory dump").unwrap();

        let sha256 = crate::hashing::calculate_sha256(&dump_path).unwrap();

        let manifest_path = write_manifest(
            &dump_path,
            1234,
            "C:\\Windows\\test.exe".to_string(),
            sha256,
        )
        .unwrap();

        fs::remove_file(&dump_path).unwrap();

        let result = verify_manifest(&manifest_path);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .starts_with("Could not access acquired dump:")
        );

        fs::remove_file(&manifest_path).unwrap();
    }
    #[test]
    fn rejects_directory_as_acquired_dump_during_verification() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let dump_path = std::env::temp_dir().join(format!("memory_test_{unique}.dmp"));

        let directory_path = std::env::temp_dir().join(format!("memory_directory_{unique}"));

        fs::write(&dump_path, b"MDMP test memory dump").unwrap();
        fs::create_dir(&directory_path).unwrap();

        let sha256 = crate::hashing::calculate_sha256(&dump_path).unwrap();

        let manifest_path = write_manifest(
            &dump_path,
            1234,
            "C:\\Windows\\test.exe".to_string(),
            sha256,
        )
        .unwrap();

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();

        manifest["dump_path"] =
            serde_json::Value::String(directory_path.to_string_lossy().into_owned());

        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_manifest(&manifest_path);

        assert_eq!(result.unwrap_err(), "Acquired dump path is not a file");

        fs::remove_file(&dump_path).unwrap();
        fs::remove_file(&manifest_path).unwrap();
        fs::remove_dir(&directory_path).unwrap();
    }
    #[test]
    fn rejects_invalid_sha256_in_acquisition_manifest() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let dump_path =
            PathBuf::from(std::env::temp_dir()).join(format!("memory_test_{unique}.dmp"));

        fs::write(&dump_path, b"MDMP test memory dump").unwrap();

        let sha256 = crate::hashing::calculate_sha256(&dump_path).unwrap();

        let manifest_path = write_manifest(
            &dump_path,
            1234,
            "C:\\Windows\\test.exe".to_string(),
            sha256,
        )
        .unwrap();

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();

        manifest["sha256"] = serde_json::Value::String("invalid-hash".to_string());

        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_manifest(&manifest_path);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid SHA-256 format in acquisition manifest"
        );

        fs::remove_file(&dump_path).unwrap();
        fs::remove_file(&manifest_path).unwrap();
    }
    #[test]
    fn rejects_empty_dump_path_in_acquisition_manifest() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let dump_path =
            PathBuf::from(std::env::temp_dir()).join(format!("memory_test_{unique}.dmp"));

        fs::write(&dump_path, b"MDMP test memory dump").unwrap();

        let sha256 = crate::hashing::calculate_sha256(&dump_path).unwrap();

        let manifest_path = write_manifest(
            &dump_path,
            1234,
            "C:\\Windows\\test.exe".to_string(),
            sha256,
        )
        .unwrap();

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();

        manifest["dump_path"] = serde_json::Value::String("   ".to_string());

        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_manifest(&manifest_path);

        assert_eq!(
            result.unwrap_err(),
            "Acquired dump path is empty in manifest"
        );

        fs::remove_file(&dump_path).unwrap();
        fs::remove_file(&manifest_path).unwrap();
    }

    #[test]
    fn rejects_unsupported_dump_format_in_acquisition_manifest() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let dump_path =
            PathBuf::from(std::env::temp_dir()).join(format!("memory_test_{unique}.dmp"));

        fs::write(&dump_path, b"MDMP test memory dump").unwrap();

        let sha256 = crate::hashing::calculate_sha256(&dump_path).unwrap();

        let manifest_path = write_manifest(
            &dump_path,
            1234,
            "C:\\Windows\\test.exe".to_string(),
            sha256,
        )
        .unwrap();

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();

        manifest["dump_format"] = serde_json::Value::String("UnsupportedFormat".to_string());

        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_manifest(&manifest_path);

        assert_eq!(
            result.unwrap_err(),
            "Unsupported dump format in acquisition manifest"
        );

        fs::remove_file(&dump_path).unwrap();
        fs::remove_file(&manifest_path).unwrap();
    }
    #[test]
    fn rejects_empty_executable_path_in_acquisition_manifest() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let dump_path =
            PathBuf::from(std::env::temp_dir()).join(format!("memory_test_{unique}.dmp"));

        fs::write(&dump_path, b"MDMP test memory dump").unwrap();

        let sha256 = crate::hashing::calculate_sha256(&dump_path).unwrap();

        let manifest_path = write_manifest(
            &dump_path,
            1234,
            "C:\\Windows\\test.exe".to_string(),
            sha256,
        )
        .unwrap();

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();

        manifest["executable_path"] = serde_json::Value::String("   ".to_string());

        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_manifest(&manifest_path);

        assert_eq!(
            result.unwrap_err(),
            "Executable path is empty in acquisition manifest"
        );

        fs::remove_file(&dump_path).unwrap();
        fs::remove_file(&manifest_path).unwrap();
    }
    #[test]
    fn rejects_zero_process_id_in_acquisition_manifest() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let dump_path =
            PathBuf::from(std::env::temp_dir()).join(format!("memory_test_{unique}.dmp"));

        fs::write(&dump_path, b"MDMP test memory dump").unwrap();

        let sha256 = crate::hashing::calculate_sha256(&dump_path).unwrap();

        let manifest_path = write_manifest(
            &dump_path,
            1234,
            "C:\\Windows\\test.exe".to_string(),
            sha256,
        )
        .unwrap();

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();

        manifest["process_id"] = serde_json::Value::Number(0.into());

        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_manifest(&manifest_path);

        assert_eq!(
            result.unwrap_err(),
            "Invalid process ID in acquisition manifest"
        );

        fs::remove_file(&dump_path).unwrap();
        fs::remove_file(&manifest_path).unwrap();
    }
    #[test]
    fn rejects_zero_acquisition_timestamp_in_manifest() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let dump_path =
            PathBuf::from(std::env::temp_dir()).join(format!("memory_test_{unique}.dmp"));

        fs::write(&dump_path, b"MDMP test memory dump").unwrap();

        let sha256 = crate::hashing::calculate_sha256(&dump_path).unwrap();

        let manifest_path = write_manifest(
            &dump_path,
            1234,
            "C:\\Windows\\test.exe".to_string(),
            sha256,
        )
        .unwrap();

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();

        manifest["acquired_at_unix_seconds"] = serde_json::Value::Number(0.into());

        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_manifest(&manifest_path);

        assert_eq!(
            result.unwrap_err(),
            "Invalid acquisition timestamp in manifest"
        );

        fs::remove_file(&dump_path).unwrap();
        fs::remove_file(&manifest_path).unwrap();
    }
    #[test]
    fn rejects_corrupted_acquisition_manifest() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let manifest_path =
            PathBuf::from(std::env::temp_dir()).join(format!("manifest_test_{unique}.json"));

        fs::write(&manifest_path, b"{ invalid json }").unwrap();

        let result = verify_manifest(&manifest_path);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .starts_with("Could not parse acquisition manifest:")
        );

        fs::remove_file(&manifest_path).unwrap();
    }

    #[test]
    fn rejects_missing_acquisition_manifest() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let manifest_path =
            PathBuf::from(std::env::temp_dir()).join(format!("missing_manifest_{unique}.json"));

        let result = verify_manifest(&manifest_path);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .starts_with("Could not read acquisition manifest:")
        );
    }

    #[test]
    fn rejects_zero_process_id_when_creating_manifest() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let dump_path =
            PathBuf::from(std::env::temp_dir()).join(format!("memory_test_{unique}.dmp"));

        fs::write(&dump_path, b"MDMP test memory dump").unwrap();

        let result = write_manifest(
            &dump_path,
            0,
            "C:\\Windows\\test.exe".to_string(),
            "a".repeat(64),
        );

        assert_eq!(
            result.unwrap_err(),
            "Invalid process ID for acquisition manifest"
        );

        fs::remove_file(&dump_path).unwrap();
    }

    #[test]
    fn rejects_empty_executable_path_when_creating_manifest() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let dump_path =
            PathBuf::from(std::env::temp_dir()).join(format!("memory_test_{unique}.dmp"));

        fs::write(&dump_path, b"MDMP test memory dump").unwrap();

        let result = write_manifest(&dump_path, 1234, "   ".to_string(), "a".repeat(64));

        assert_eq!(
            result.unwrap_err(),
            "Executable path is empty for acquisition manifest"
        );

        fs::remove_file(&dump_path).unwrap();
    }

    #[test]
    fn rejects_directory_as_acquisition_dump() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let directory_path = std::env::temp_dir().join(format!("memory_test_{unique}"));

        fs::create_dir(&directory_path).unwrap();

        let result = write_manifest(
            &directory_path,
            1234,
            "C:\\Windows\\test.exe".to_string(),
            "a".repeat(64),
        );

        assert_eq!(result.unwrap_err(), "Acquired dump path is not a file");

        fs::remove_dir(&directory_path).unwrap();
    }

    #[test]
    fn rejects_hash_that_does_not_match_acquired_dump() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let dump_path =
            PathBuf::from(std::env::temp_dir()).join(format!("memory_test_{unique}.dmp"));

        fs::write(&dump_path, b"MDMP test memory dump").unwrap();

        let result = write_manifest(
            &dump_path,
            1234,
            "C:\\Windows\\test.exe".to_string(),
            "a".repeat(64),
        );

        assert_eq!(
            result.unwrap_err(),
            "Acquisition dump SHA-256 does not match supplied hash"
        );

        assert!(!dump_path.with_extension("json").exists());

        fs::remove_file(&dump_path).unwrap();
    }

    #[test]
    fn rejects_elf_core_when_creating_acquisition_manifest() {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let dump_path =
            PathBuf::from(std::env::temp_dir()).join(format!("memory_test_{unique}.dmp"));

        // ELF64, little-endian, ET_CORE.
        let elf_core_header = [
            0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0,
        ];

        fs::write(&dump_path, elf_core_header).unwrap();

        let sha256 = crate::hashing::calculate_sha256(&dump_path).unwrap();

        let result = write_manifest(
            &dump_path,
            1234,
            "C:\\Windows\\test.exe".to_string(),
            sha256,
        );

        assert_eq!(
            result.unwrap_err(),
            "Acquired dump is not a Windows minidump"
        );

        assert!(!dump_path.with_extension("json").exists());

        fs::remove_file(&dump_path).unwrap();
    }
}
