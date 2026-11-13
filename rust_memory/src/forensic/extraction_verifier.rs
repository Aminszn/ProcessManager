use super::formats::detect_format;
use super::memory_image::MemoryImageFormat;
use crate::extraction_manifest::read_extraction_manifest;
use crate::hashing::calculate_sha256;
use serde_json::Value;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug)]
pub struct ExtractionVerification {
    pub source_size_bytes: u64,
    pub output_size_bytes: u64,
    pub strings_verified: usize,
}

pub fn verify_extraction(manifest_path: &Path) -> Result<ExtractionVerification, String> {
    // Read the extraction manifest.
    let manifest = read_extraction_manifest(manifest_path)?;
    if manifest.source_path.trim().is_empty() {
        return Err("Source dump path in manifest is empty".to_string());
    }
    if manifest.output_path.trim().is_empty() {
        return Err("Extraction output path in manifest is empty".to_string());
    }
    if manifest.min_string_length == 0 {
        return Err("Manifest minimum string length must be greater than zero".to_string());
    }

    if manifest.extraction_format != "JSONL" {
        return Err(format!(
            "Unsupported extraction format in manifest: {}",
            manifest.extraction_format
        ));
    }

    let source_path = Path::new(&manifest.source_path);
    let output_path = Path::new(&manifest.output_path);

    // Verify that both evidence files exist and can be inspected.
    let source_metadata = fs::metadata(source_path)
        .map_err(|error| format!("Could not access source dump: {error}"))?;

    // Verify that the source file is a supported Windows minidump.
    let source_format = detect_format(source_path)?;

    if source_format != MemoryImageFormat::WindowsMinidump {
        return Err(format!(
            "Unsupported source memory-image format: {source_format:?}"
        ));
    }

    let output_metadata = fs::metadata(output_path)
        .map_err(|error| format!("Could not access extraction output: {error}"))?;

    // Verify file sizes.
    if source_metadata.len() != manifest.source_size_bytes {
        return Err(format!(
            "Source file size mismatch: expected {}, found {}",
            manifest.source_size_bytes,
            source_metadata.len()
        ));
    }

    if output_metadata.len() != manifest.output_size_bytes {
        return Err(format!(
            "Output file size mismatch: expected {}, found {}",
            manifest.output_size_bytes,
            output_metadata.len()
        ));
    }

    validate_sha256_format(&manifest.source_sha256, "source_sha256")?;
    validate_sha256_format(&manifest.output_sha256, "output_sha256")?;

    // Verify SHA-256 hashes.
    let source_hash = calculate_sha256(source_path)?;

    if !source_hash.eq_ignore_ascii_case(&manifest.source_sha256) {
        return Err("Source dump SHA-256 mismatch".to_string());
    }

    let output_hash = calculate_sha256(output_path)?;

    if !output_hash.eq_ignore_ascii_case(&manifest.output_sha256) {
        return Err("Extraction output SHA-256 mismatch".to_string());
    }

    // Validate every JSONL record and count the findings.
    let file = File::open(output_path)
        .map_err(|error| format!("Could not open extraction output: {error}"))?;

    let reader = BufReader::new(file);
    let mut strings_verified = 0_usize;

    for (index, line_result) in reader.lines().enumerate() {
        let line_number = index + 1;

        let line = line_result
            .map_err(|error| format!("Could not read JSONL line {line_number}: {error}"))?;

        if line.trim().is_empty() {
            return Err(format!("Empty JSONL record at line {line_number}"));
        }

        let record: Value = serde_json::from_str(&line)
            .map_err(|error| format!("Invalid JSON at line {line_number}: {error}"))?;

        validate_record(&record, line_number, manifest.min_string_length)?;

        strings_verified = strings_verified
            .checked_add(1)
            .ok_or_else(|| "Verified string count overflow".to_string())?;
    }

    // Compare the actual record count with the manifest.
    if strings_verified != manifest.strings_extracted {
        return Err(format!(
            "String count mismatch: manifest reports {}, output contains {}",
            manifest.strings_extracted, strings_verified
        ));
    }

    Ok(ExtractionVerification {
        source_size_bytes: source_metadata.len(),
        output_size_bytes: output_metadata.len(),
        strings_verified,
    })
}

fn validate_sha256_format(hash: &str, field: &str) -> Result<(), String> {
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("Invalid SHA-256 format in manifest: {field}"));
    }

    Ok(())
}

fn validate_record(
    record: &Value,
    line_number: usize,
    min_string_length: usize,
) -> Result<(), String> {
    let object = record
        .as_object()
        .ok_or_else(|| format!("JSONL record at line {line_number} is not an object"))?;

    if object.len() != 3
        || !object.contains_key("address")
        || !object.contains_key("encoding")
        || !object.contains_key("value")
    {
        return Err(format!(
            "Unexpected or missing fields in JSONL record at line {line_number}"
        ));
    }

    let address = object
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Missing or invalid address at line {line_number}"))?;

    let address_digits = address
        .strip_prefix("0x")
        .ok_or_else(|| format!("Invalid address prefix at line {line_number}"))?;

    if address_digits.len() != 16 || !address_digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("Invalid hexadecimal address at line {line_number}"));
    }

    let encoding = object
        .get("encoding")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Missing or invalid encoding at line {line_number}"))?;

    if encoding != "ASCII" && encoding != "UTF-16LE" {
        return Err(format!(
            "Unsupported string encoding at line {line_number}: {encoding}"
        ));
    }

    let value = object
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Missing or invalid string value at line {line_number}"))?;

    if value.len() < min_string_length {
        return Err(format!(
            "String at line {line_number} is shorter than the configured minimum"
        ));
    }

    let valid_value = match encoding {
        "ASCII" => value.bytes().all(|byte| (0x20..=0x7E).contains(&byte)),
        "UTF-16LE" => value
            .chars()
            .all(|character| character.is_ascii() && (0x20..=0x7E).contains(&(character as u8))),
        _ => false,
    };

    if !valid_value {
        return Err(format!(
            "String at line {line_number} contains unsupported characters"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extraction_manifest::write_extraction_manifest;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    struct TestFixture {
        directory: PathBuf,
        manifest_path: PathBuf,
        output_path: PathBuf,
    }

    impl TestFixture {
        fn new(output: &[u8], expected_count: usize) -> Self {
            let id = TEST_ID.fetch_add(1, Ordering::Relaxed);

            let directory = std::env::temp_dir().join(format!(
                "processmonitor-extraction-verifier-{}-{id}",
                std::process::id()
            ));

            fs::create_dir_all(&directory).unwrap();

            let source_path = directory.join("source.dmp");
            let output_path = directory.join("strings.jsonl");

            fs::write(&source_path, b"MDMP").unwrap();
            fs::write(&output_path, output).unwrap();

            let source_hash = calculate_sha256(&source_path).unwrap();
            let output_hash = calculate_sha256(&output_path).unwrap();

            let manifest_path = write_extraction_manifest(
                &source_path,
                &output_path,
                source_hash,
                output_hash,
                5,
                expected_count,
            )
            .unwrap();

            Self {
                directory,
                manifest_path,
                output_path,
            }
        }
    }

    impl Drop for TestFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    const VALID_RECORD: &[u8] =
        b"{\"address\":\"0x0000000000001000\",\"encoding\":\"ASCII\",\"value\":\"Hello World\"}\n";

    #[test]
    fn verifies_valid_extraction() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        let result = verify_extraction(&fixture.manifest_path).unwrap();

        assert_eq!(result.strings_verified, 1);
        assert!(result.source_size_bytes > 0);
        assert!(result.output_size_bytes > 0);
    }
    #[test]
    fn rejects_unsupported_source_format() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        let source_path = fixture.directory.join("source.dmp");

        fs::write(&source_path, b"NOT A DUMP").unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert!(
            result
                .unwrap_err()
                .contains("Unrecognized memory-image format")
        );
    }

    #[test]
    fn rejects_modified_output_hash() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        let mut modified = fs::read(&fixture.output_path).unwrap();
        modified[0] = b'X';

        fs::write(&fixture.output_path, modified).unwrap();
        let result = verify_extraction(&fixture.manifest_path);

        assert!(result.unwrap_err().contains("SHA-256 mismatch"));
    }

    #[test]
    fn rejects_modified_source_hash() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.manifest_path).unwrap()).unwrap();

        manifest["source_sha256"] =
            serde_json::json!("0000000000000000000000000000000000000000000000000000000000000000");

        fs::write(
            &fixture.manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert!(result.unwrap_err().contains("Source dump SHA-256 mismatch"));
    }

    #[test]
    fn rejects_modified_source_size() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        let source_path = fixture.directory.join("source.dmp");

        let mut source = fs::read(&source_path).unwrap();
        source.extend_from_slice(b"MODIFIED");

        fs::write(&source_path, source).unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert!(result.unwrap_err().contains("Source file size mismatch"));
    }

    #[test]
    fn rejects_modified_output_size() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        let mut output = fs::read(&fixture.output_path).unwrap();
        output.extend_from_slice(b"MODIFIED");

        fs::write(&fixture.output_path, output).unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert!(result.unwrap_err().contains("Output file size mismatch"));
    }

    #[test]
    fn rejects_invalid_jsonl_record() {
        let fixture = TestFixture::new(b"not valid JSON\n", 1);

        let result = verify_extraction(&fixture.manifest_path);

        assert!(result.unwrap_err().contains("Invalid JSON"));
    }

    #[test]
    fn rejects_non_object_jsonl_record() {
        let output = b"[\"address\", \"encoding\", \"value\"]\n";

        let fixture = TestFixture::new(output, 1);

        let result = verify_extraction(&fixture.manifest_path);

        assert!(result.unwrap_err().contains("is not an object"));
    }

    #[test]
    fn rejects_empty_jsonl_record() {
        let output = b"\n";

        let fixture = TestFixture::new(output, 1);

        let result = verify_extraction(&fixture.manifest_path);

        assert!(result.unwrap_err().contains("Empty JSONL record at line 1"));
    }

    #[test]
    fn rejects_manifest_string_count_mismatch() {
        let fixture = TestFixture::new(VALID_RECORD, 2);

        let result = verify_extraction(&fixture.manifest_path);

        assert!(result.unwrap_err().contains("String count mismatch"));
    }

    #[test]
    fn rejects_zero_minimum_length_in_manifest() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.manifest_path).unwrap()).unwrap();

        manifest["min_string_length"] = serde_json::json!(0);

        fs::write(
            &fixture.manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert!(
            result
                .unwrap_err()
                .contains("minimum string length must be greater than zero")
        );
    }

    #[test]
    fn rejects_unsupported_extraction_format() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.manifest_path).unwrap()).unwrap();

        manifest["extraction_format"] = serde_json::json!("CSV");

        fs::write(
            &fixture.manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert!(
            result
                .unwrap_err()
                .contains("Unsupported extraction format")
        );
    }

    #[test]
    fn rejects_invalid_hexadecimal_address() {
        let output =
            b"{\"address\":\"not-an-address\",\"encoding\":\"ASCII\",\"value\":\"Hello World\"}\n";

        let fixture = TestFixture::new(output, 1);

        let result = verify_extraction(&fixture.manifest_path);

        assert!(result.unwrap_err().contains("Invalid address"));
    }

    #[test]
    fn rejects_unsupported_string_encoding() {
        let output =
        b"{\"address\":\"0x0000000000001000\",\"encoding\":\"UTF-8\",\"value\":\"Hello World\"}\n";

        let fixture = TestFixture::new(output, 1);

        let result = verify_extraction(&fixture.manifest_path);

        assert!(result.unwrap_err().contains("Unsupported string encoding"));
    }

    #[test]
    fn rejects_non_ascii_character_in_utf16le_record() {
        let output =
            "{\"address\":\"0x0000000000001000\",\"encoding\":\"UTF-16LE\",\"value\":\"Café\"}\n";

        let fixture = TestFixture::new(output.as_bytes(), 1);

        let result = verify_extraction(&fixture.manifest_path);

        assert!(
            result
                .unwrap_err()
                .contains("contains unsupported characters")
        );
    }

    #[test]
    fn verifies_valid_utf16le_record() {
        let output =
        b"{\"address\":\"0x0000000000001000\",\"encoding\":\"UTF-16LE\",\"value\":\"Text Editor\"}\n";

        let fixture = TestFixture::new(output, 1);

        let result = verify_extraction(&fixture.manifest_path).unwrap();

        assert_eq!(result.strings_verified, 1);
    }

    #[test]
    fn rejects_missing_extraction_output() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        fs::remove_file(&fixture.output_path).unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert!(
            result
                .unwrap_err()
                .contains("Could not access extraction output")
        );
    }

    #[test]
    fn rejects_missing_source_dump() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        let source_path = fixture.directory.join("source.dmp");
        fs::remove_file(&source_path).unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert!(result.unwrap_err().contains("Could not access source dump"));
    }

    #[test]
    fn rejects_missing_manifest() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        fs::remove_file(&fixture.manifest_path).unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert!(
            result.is_err(),
            "Verification should reject a missing manifest"
        );
    }

    #[test]
    fn rejects_corrupted_manifest() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        fs::write(&fixture.manifest_path, b"{ invalid json").unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert!(
            result.is_err(),
            "Verification should reject a corrupted manifest"
        );
    }

    #[test]
    fn rejects_invalid_source_sha256_format() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.manifest_path).unwrap()).unwrap();

        manifest["source_sha256"] = serde_json::json!("invalid_hash");

        fs::write(
            &fixture.manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert!(
            result
                .unwrap_err()
                .contains("Invalid SHA-256 format in manifest: source_sha256")
        );
    }

    #[test]
    fn rejects_invalid_output_sha256_format() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.manifest_path).unwrap()).unwrap();

        manifest["output_sha256"] = serde_json::json!("invalid_hash");

        fs::write(
            &fixture.manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert!(
            result
                .unwrap_err()
                .contains("Invalid SHA-256 format in manifest: output_sha256")
        );
    }

    #[test]
    fn rejects_non_hexadecimal_sha256_value() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.manifest_path).unwrap()).unwrap();

        manifest["source_sha256"] = serde_json::json!("Z".repeat(64));

        fs::write(
            &fixture.manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert!(
            result
                .unwrap_err()
                .contains("Invalid SHA-256 format in manifest: source_sha256")
        );
    }

    #[test]
    fn rejects_manifest_with_missing_required_field() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.manifest_path).unwrap()).unwrap();

        manifest.as_object_mut().unwrap().remove("tool_name");

        fs::write(
            &fixture.manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert!(
            result
                .unwrap_err()
                .contains("Could not parse extraction manifest")
        );
    }

    #[test]
    fn rejects_manifest_with_invalid_field_type() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.manifest_path).unwrap()).unwrap();

        manifest["source_size_bytes"] = serde_json::json!("not_a_number");

        fs::write(
            &fixture.manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert!(
            result
                .unwrap_err()
                .contains("Could not parse extraction manifest")
        );
    }

    #[test]
    fn rejects_empty_source_path_in_manifest() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.manifest_path).unwrap()).unwrap();

        manifest["source_path"] = serde_json::json!("");

        fs::write(
            &fixture.manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert_eq!(result.unwrap_err(), "Source dump path in manifest is empty");
    }

    #[test]
    fn rejects_empty_output_path_in_manifest() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.manifest_path).unwrap()).unwrap();

        manifest["output_path"] = serde_json::json!("");

        fs::write(
            &fixture.manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert_eq!(
            result.unwrap_err(),
            "Extraction output path in manifest is empty"
        );
    }

    #[test]
    fn rejects_whitespace_only_source_path_in_manifest() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.manifest_path).unwrap()).unwrap();

        manifest["source_path"] = serde_json::json!("   ");

        fs::write(
            &fixture.manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert_eq!(result.unwrap_err(), "Source dump path in manifest is empty");
    }

    #[test]
    fn rejects_whitespace_only_output_path_in_manifest() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.manifest_path).unwrap()).unwrap();

        manifest["output_path"] = serde_json::json!("   ");

        fs::write(
            &fixture.manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert_eq!(
            result.unwrap_err(),
            "Extraction output path in manifest is empty"
        );
    }

    #[test]
    fn rejects_non_hexadecimal_output_sha256_value() {
        let fixture = TestFixture::new(VALID_RECORD, 1);

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.manifest_path).unwrap()).unwrap();

        manifest["output_sha256"] = serde_json::json!("Z".repeat(64));

        fs::write(
            &fixture.manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let result = verify_extraction(&fixture.manifest_path);

        assert!(
            result
                .unwrap_err()
                .contains("Invalid SHA-256 format in manifest: output_sha256")
        );
    }

    #[test]
    fn rejects_string_shorter_than_manifest_minimum() {
        let output =
            b"{\"address\":\"0x0000000000001000\",\"encoding\":\"ASCII\",\"value\":\"Hey\"}\n";

        let fixture = TestFixture::new(output, 1);

        let result = verify_extraction(&fixture.manifest_path);

        assert!(
            result
                .unwrap_err()
                .contains("shorter than the configured minimum")
        );
    }

    #[test]
    fn rejects_unexpected_record_fields() {
        let output = b"{\"address\":\"0x0000000000001000\",\"encoding\":\"ASCII\",\"value\":\"Hello World\",\"extra\":\"unexpected\"}\n";

        let fixture = TestFixture::new(output, 1);

        let result = verify_extraction(&fixture.manifest_path);

        assert!(result.unwrap_err().contains("Unexpected or missing fields"));
    }

    #[test]
    fn rejects_missing_record_field() {
        let output = b"{\"address\":\"0x0000000000001000\",\"encoding\":\"ASCII\"}\n";

        let fixture = TestFixture::new(output, 1);

        let result = verify_extraction(&fixture.manifest_path);

        assert!(result.unwrap_err().contains("Unexpected or missing fields"));
    }

    #[test]
    fn rejects_non_string_record_value() {
        let output = b"{\"address\":\"0x0000000000001000\",\"encoding\":\"ASCII\",\"value\":123}\n";

        let fixture = TestFixture::new(output, 1);

        let result = verify_extraction(&fixture.manifest_path);

        assert!(
            result
                .unwrap_err()
                .contains("Missing or invalid string value")
        );
    }

    #[test]
    fn rejects_non_string_encoding() {
        let output =
            b"{\"address\":\"0x0000000000001000\",\"encoding\":123,\"value\":\"Hello World\"}\n";

        let fixture = TestFixture::new(output, 1);

        let result = verify_extraction(&fixture.manifest_path);

        assert!(result.unwrap_err().contains("Missing or invalid encoding"));
    }

    #[test]
    fn rejects_non_string_address() {
        let output = b"{\"address\":4096,\"encoding\":\"ASCII\",\"value\":\"Hello World\"}\n";

        let fixture = TestFixture::new(output, 1);

        let result = verify_extraction(&fixture.manifest_path);

        assert!(result.unwrap_err().contains("Missing or invalid address"));
    }
}
