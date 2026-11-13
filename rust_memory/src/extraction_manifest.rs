use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtractionManifest {
    pub source_path: String,
    pub source_sha256: String,
    pub source_size_bytes: u64,
    pub output_path: String,
    pub output_sha256: String,
    pub output_size_bytes: u64,
    pub min_string_length: usize,
    pub strings_extracted: usize,
    pub extraction_format: String,
    pub extracted_at_unix_seconds: u64,
    pub tool_name: String,
    pub tool_version: String,
}

fn validate_sha256(hash: &str, field: &str) -> Result<(), String> {
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("Invalid SHA-256 format: {field}"));
    }

    Ok(())
}

pub fn write_extraction_manifest(
    source_path: &Path,
    output_path: &Path,
    source_sha256: String,
    output_sha256: String,
    min_string_length: usize,
    strings_extracted: usize,
) -> Result<PathBuf, String> {
    if min_string_length == 0 {
        return Err("Minimum string length must be greater than zero".to_string());
    }

    validate_sha256(&source_sha256, "source_sha256")?;
    validate_sha256(&output_sha256, "output_sha256")?;
    let source_metadata = fs::metadata(source_path)
        .map_err(|error| format!("Could not read source metadata: {error}"))?;

    let output_metadata = fs::metadata(output_path)
        .map_err(|error| format!("Could not read output metadata: {error}"))?;

    let extracted_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("Could not obtain extraction time: {error}"))?
        .as_secs();

    let manifest = ExtractionManifest {
        source_path: source_path.to_string_lossy().into_owned(),
        source_sha256,
        source_size_bytes: source_metadata.len(),
        output_path: output_path.to_string_lossy().into_owned(),
        output_sha256,
        output_size_bytes: output_metadata.len(),
        min_string_length,
        strings_extracted,
        extraction_format: "JSONL".to_string(),
        extracted_at_unix_seconds: extracted_at,
        tool_name: "ProcessMonitor Rust Memory".to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let manifest_path = output_path.with_extension("manifest.json");

    let serialized = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("Could not serialize extraction manifest: {error}"))?;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest_path)
        .map_err(|error| format!("Could not create extraction manifest: {error}"))?;

    if let Err(error) = file.write_all(&serialized).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&manifest_path);

        return Err(format!("Could not write extraction manifest: {error}"));
    }

    Ok(manifest_path)
}

pub fn read_extraction_manifest(path: &Path) -> Result<ExtractionManifest, String> {
    let content =
        fs::read(path).map_err(|error| format!("Could not read extraction manifest: {error}"))?;

    let manifest: ExtractionManifest = serde_json::from_slice(&content)
        .map_err(|error| format!("Could not parse extraction manifest: {error}"))?;

    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::{ExtractionManifest, write_extraction_manifest};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn create_test_directory() -> PathBuf {
        let base = std::env::temp_dir();

        loop {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();

            let directory = base.join(format!(
                "rust_memory_manifest_{}_{}",
                std::process::id(),
                unique
            ));

            match fs::create_dir(&directory) {
                Ok(()) => return directory,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    continue;
                }
                Err(error) => {
                    panic!("Could not create test directory: {error}");
                }
            }
        }
    }

    #[test]
    fn creates_valid_extraction_manifest() {
        let directory = create_test_directory();

        let source_path = directory.join("source.dmp");
        let output_path = directory.join("output.jsonl");

        fs::write(&source_path, b"test memory dump").unwrap();
        fs::write(&output_path, b"{\"value\":\"test\"}\n").unwrap();

        let manifest_path = write_extraction_manifest(
            &source_path,
            &output_path,
            "a".repeat(64),
            "b".repeat(64),
            5,
            1,
        )
        .expect("Manifest creation failed");

        let content = fs::read(&manifest_path).unwrap();

        let manifest: ExtractionManifest =
            serde_json::from_slice(&content).expect("Invalid manifest JSON");

        assert_eq!(manifest.source_sha256, "a".repeat(64));
        assert_eq!(manifest.output_sha256, "b".repeat(64));
        assert_eq!(manifest.source_size_bytes, 16);
        assert_eq!(manifest.output_size_bytes, 17);
        assert_eq!(manifest.min_string_length, 5);
        assert_eq!(manifest.strings_extracted, 1);
        assert_eq!(manifest.extraction_format, "JSONL");
        assert!(manifest.extracted_at_unix_seconds > 0);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_zero_minimum_string_length() {
        let directory = create_test_directory();

        let source_path = directory.join("source.dmp");
        let output_path = directory.join("output.jsonl");

        fs::write(&source_path, b"source").unwrap();
        fs::write(&output_path, b"output").unwrap();

        let result = write_extraction_manifest(
            &source_path,
            &output_path,
            "source_hash".to_string(),
            "output_hash".to_string(),
            0,
            1,
        );

        assert_eq!(
            result.unwrap_err(),
            "Minimum string length must be greater than zero"
        );

        assert!(!output_path.with_extension("manifest.json").exists());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_invalid_source_sha256() {
        let directory = create_test_directory();

        let source_path = directory.join("source.dmp");
        let output_path = directory.join("output.jsonl");

        fs::write(&source_path, b"source").unwrap();
        fs::write(&output_path, b"output").unwrap();

        let result = write_extraction_manifest(
            &source_path,
            &output_path,
            "invalid_hash".to_string(),
            "a".repeat(64),
            5,
            1,
        );

        assert_eq!(result.unwrap_err(), "Invalid SHA-256 format: source_sha256");

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_invalid_output_sha256() {
        let directory = create_test_directory();

        let source_path = directory.join("source.dmp");
        let output_path = directory.join("output.jsonl");

        fs::write(&source_path, b"source").unwrap();
        fs::write(&output_path, b"output").unwrap();

        let result = write_extraction_manifest(
            &source_path,
            &output_path,
            "a".repeat(64),
            "invalid_hash".to_string(),
            5,
            1,
        );

        assert_eq!(result.unwrap_err(), "Invalid SHA-256 format: output_sha256");

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_missing_source_file() {
        let directory = create_test_directory();

        let source_path = directory.join("missing_source.dmp");
        let output_path = directory.join("output.jsonl");

        fs::write(&output_path, b"output").unwrap();

        let result = write_extraction_manifest(
            &source_path,
            &output_path,
            "a".repeat(64),
            "b".repeat(64),
            5,
            1,
        );

        assert!(
            result
                .unwrap_err()
                .contains("Could not read source metadata")
        );

        assert!(!output_path.with_extension("manifest.json").exists());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_missing_output_file() {
        let directory = create_test_directory();

        let source_path = directory.join("source.dmp");
        let output_path = directory.join("missing_output.jsonl");

        fs::write(&source_path, b"source").unwrap();

        let result = write_extraction_manifest(
            &source_path,
            &output_path,
            "a".repeat(64),
            "b".repeat(64),
            5,
            1,
        );

        assert!(
            result
                .unwrap_err()
                .contains("Could not read output metadata")
        );

        assert!(!output_path.with_extension("manifest.json").exists());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn refuses_to_overwrite_existing_manifest() {
        let directory = create_test_directory();

        let source_path = directory.join("source.dmp");
        let output_path = directory.join("output.jsonl");

        fs::write(&source_path, b"source").unwrap();
        fs::write(&output_path, b"output").unwrap();

        let manifest_path = output_path.with_extension("manifest.json");

        fs::write(&manifest_path, b"existing evidence").unwrap();

        let result = write_extraction_manifest(
            &source_path,
            &output_path,
            "a".repeat(64),
            "b".repeat(64),
            5,
            1,
        );

        assert!(result.is_err());

        let existing_content = fs::read(&manifest_path).unwrap();
        assert_eq!(existing_content, b"existing evidence");

        fs::remove_dir_all(directory).unwrap();
    }
}
