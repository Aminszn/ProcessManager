use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub fn calculate_sha256(path: &Path) -> Result<String, String> {
    let mut file =
        File::open(path).map_err(|error| format!("Could not open evidence file: {error}"))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|error| format!("Could not read evidence file: {error}"))?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::calculate_sha256;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn calculates_sha256_correctly() {
        let path = PathBuf::from(std::env::temp_dir())
            .join(format!("rust_memory_hash_test_{}.txt", std::process::id()));

        fs::write(&path, b"abc").expect("Could not create test file");

        let result = calculate_sha256(&path);

        fs::remove_file(&path).expect("Could not remove test file");

        assert_eq!(
            result.expect("Hash calculation failed"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn calculates_sha256_for_empty_file() {
        let path = PathBuf::from(std::env::temp_dir()).join(format!(
            "rust_memory_empty_hash_test_{}.txt",
            std::process::id()
        ));

        fs::write(&path, b"").expect("Could not create test file");

        let result = calculate_sha256(&path);

        fs::remove_file(&path).expect("Could not remove test file");

        assert_eq!(
            result.expect("Hash calculation failed"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hashes_file_larger_than_buffer() {
        let path = PathBuf::from(std::env::temp_dir()).join(format!(
            "rust_memory_large_hash_test_{}.bin",
            std::process::id()
        ));

        let contents: Vec<u8> = (0..(64 * 1024 * 3 + 17))
            .map(|index| (index % 256) as u8)
            .collect();

        fs::write(&path, &contents).expect("Could not create test file");

        let expected_hash = format!("{:x}", Sha256::digest(&contents));
        let result = calculate_sha256(&path);

        fs::remove_file(&path).expect("Could not remove test file");

        assert_eq!(result.expect("Hash calculation failed"), expected_hash);
    }

    #[test]
    fn rejects_missing_evidence_file() {
        let path = PathBuf::from(std::env::temp_dir()).join(format!(
            "rust_memory_missing_hash_test_{}.bin",
            std::process::id()
        ));

        let _ = fs::remove_file(&path);

        let result = calculate_sha256(&path);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Could not open evidence file"));
    }
}
