use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::memory_image::MemoryImageFormat;

/// Reads a file header and identifies its memory-image format.
pub fn detect_format(path: &Path) -> Result<MemoryImageFormat, String> {
    let mut file =
        File::open(path).map_err(|error| format!("Failed to open memory image: {error}"))?;

    let mut header = [0u8; 20];

    let bytes_read = file
        .read(&mut header)
        .map_err(|error| format!("Failed to read memory image header: {error}"))?;

    detect_format_from_header(&header[..bytes_read])
}

/// Identifies a supported format from its file header.
pub fn detect_format_from_header(header: &[u8]) -> Result<MemoryImageFormat, String> {
    // Windows minidump signature: MDMP
    if header.starts_with(b"MDMP") {
        return Ok(MemoryImageFormat::WindowsMinidump);
    }

    // ELF magic: 0x7F followed by ELF
    if header.starts_with(b"\x7FELF") {
        if header.len() < 18 {
            return Err("ELF header is incomplete".to_string());
        }

        let file_type = match header[5] {
            1 => u16::from_le_bytes([header[16], header[17]]),
            2 => u16::from_be_bytes([header[16], header[17]]),
            _ => return Err("Invalid ELF byte order".to_string()),
        };

        // ET_CORE = 4
        if file_type == 4 {
            return Ok(MemoryImageFormat::ElfCore);
        }

        return Err(format!(
            "ELF file is not a core dump (file type: {file_type})"
        ));
    }

    Err("Unrecognized memory-image format".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_windows_minidump() {
        let header = b"MDMP";

        let result = detect_format_from_header(header);

        assert_eq!(result, Ok(MemoryImageFormat::WindowsMinidump));
    }

    #[test]
    fn detects_little_endian_elf_core() {
        let mut header = vec![0u8; 20];

        header[0..4].copy_from_slice(b"\x7FELF");
        header[4] = 2; // 64-bit
        header[5] = 1; // Little-endian
        header[16..18].copy_from_slice(&4u16.to_le_bytes());

        let result = detect_format_from_header(&header);

        assert_eq!(result, Ok(MemoryImageFormat::ElfCore));
    }

    #[test]
    fn detects_big_endian_elf_core() {
        let mut header = vec![0u8; 20];

        header[0..4].copy_from_slice(b"\x7FELF");
        header[4] = 2; // 64-bit
        header[5] = 2; // Big-endian
        header[16..18].copy_from_slice(&4u16.to_be_bytes());

        let result = detect_format_from_header(&header);

        assert_eq!(result, Ok(MemoryImageFormat::ElfCore));
    }

    #[test]
    fn rejects_non_core_elf_file() {
        let mut header = vec![0u8; 20];

        header[0..4].copy_from_slice(b"\x7FELF");
        header[5] = 1;
        header[16..18].copy_from_slice(&2u16.to_le_bytes());

        let result = detect_format_from_header(&header);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_unknown_format() {
        let header = b"UNKNOWN";

        let result = detect_format_from_header(header);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_incomplete_elf_header() {
        let header = b"\x7FELF";

        let result = detect_format_from_header(header);

        assert!(result.is_err());
    }
}
