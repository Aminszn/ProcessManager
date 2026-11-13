use crate::forensic::memory_image::{MemoryImageReader, MemoryRegion};
use serde::Serialize;
use std::io::Write;

const CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum StringEncoding {
    #[serde(rename = "ASCII")]
    Ascii,

    #[serde(rename = "UTF-16LE")]
    Utf16Le,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtractedString {
    #[serde(serialize_with = "serialize_address")]
    pub address: u64,
    pub encoding: StringEncoding,
    pub value: String,
}

fn serialize_address<S>(address: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("0x{address:016X}"))
}

/// Extracts printable ASCII and ASCII-range UTF-16LE strings
/// from a memory buffer.
pub fn extract_strings(
    start_address: u64,
    bytes: &[u8],
    min_length: usize,
) -> Result<Vec<ExtractedString>, String> {
    if min_length == 0 {
        return Err("Minimum string length must be greater than zero".to_string());
    }

    start_address
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| "Memory address range overflows".to_string())?;

    let mut scanner = StringScanner::new(start_address, min_length);
    let mut results = Vec::new();

    for (index, byte) in bytes.iter().enumerate() {
        scanner.push(start_address + index as u64, *byte, &mut results);
    }

    scanner.finish(&mut results);
    results.sort_by_key(|item| item.address);

    Ok(results)
}

/// Extracts strings from all memory regions in an image.
///
/// Reads at most 64 KiB at a time and preserves strings that
/// continue across consecutive chunks within the same region.
pub fn extract_strings_from_image(
    reader: &dyn MemoryImageReader,
    min_length: usize,
) -> Result<Vec<ExtractedString>, String> {
    if min_length == 0 {
        return Err("Minimum string length must be greater than zero".to_string());
    }

    let regions = reader.memory_regions()?;
    let mut results = Vec::new();

    for region in regions {
        scan_region(reader, &region, min_length, &mut results)?;
    }

    results.sort_by_key(|item| item.address);

    Ok(results)
}

/// Extracts strings from a memory image and writes each finding
/// immediately as a JSON Lines record.
///
/// Findings are not filtered or deduplicated.
pub fn write_strings_from_image<W: Write>(
    reader: &dyn MemoryImageReader,
    min_length: usize,
    writer: &mut W,
) -> Result<usize, String> {
    if min_length == 0 {
        return Err("Minimum string length must be greater than zero".to_string());
    }

    let mut regions = reader.memory_regions()?;

    regions.sort_by_key(|region| region.start_address);

    let mut total_count = 0_usize;

    for region in regions {
        write_region_strings(reader, &region, min_length, writer, &mut total_count)?;
    }

    writer
        .flush()
        .map_err(|error| format!("Could not flush string output: {error}"))?;

    Ok(total_count)
}

fn write_region_strings<W: Write>(
    reader: &dyn MemoryImageReader,
    region: &MemoryRegion,
    min_length: usize,
    writer: &mut W,
    total_count: &mut usize,
) -> Result<(), String> {
    region
        .start_address
        .checked_add(region.size)
        .ok_or_else(|| "Memory region address range overflows".to_string())?;

    if region.size == 0 {
        return Ok(());
    }

    let mut scanner = StringScanner::new(region.start_address, min_length);
    let mut offset = 0_u64;

    while offset < region.size {
        let remaining = region.size - offset;
        let chunk_length = remaining.min(CHUNK_SIZE as u64) as usize;

        let address = region
            .start_address
            .checked_add(offset)
            .ok_or_else(|| "Memory address range overflows".to_string())?;

        let chunk = reader.read_memory(address, chunk_length, region.address_space)?;

        if chunk.len() != chunk_length {
            return Err(format!(
                "Incomplete memory read at 0x{address:016X}: expected {chunk_length} bytes, received {}",
                chunk.len()
            ));
        }

        // Findings completed during this chunk are written immediately.
        // Active strings remain in the scanner across chunk boundaries.
        let mut completed = Vec::new();

        for (index, byte) in chunk.iter().enumerate() {
            let byte_address = address
                .checked_add(index as u64)
                .ok_or_else(|| "Memory address range overflows".to_string())?;

            scanner.push(byte_address, *byte, &mut completed);
        }

        write_completed_strings(&completed, writer, total_count)?;

        offset += chunk_length as u64;
    }

    // Flush strings that end at the memory-region boundary.
    let mut completed = Vec::new();
    scanner.finish(&mut completed);

    write_completed_strings(&completed, writer, total_count)?;

    Ok(())
}

fn write_completed_strings<W: Write>(
    strings: &[ExtractedString],
    writer: &mut W,
    total_count: &mut usize,
) -> Result<(), String> {
    for item in strings {
        serde_json::to_writer(&mut *writer, item)
            .map_err(|error| format!("Could not serialize extracted string: {error}"))?;

        writer
            .write_all(b"\n")
            .map_err(|error| format!("Could not write extracted string: {error}"))?;

        *total_count = total_count
            .checked_add(1)
            .ok_or_else(|| "Extracted string count overflow".to_string())?;
    }

    Ok(())
}

fn scan_region(
    reader: &dyn MemoryImageReader,
    region: &MemoryRegion,
    min_length: usize,
    results: &mut Vec<ExtractedString>,
) -> Result<(), String> {
    region
        .start_address
        .checked_add(region.size)
        .ok_or_else(|| "Memory region address range overflows".to_string())?;

    if region.size == 0 {
        return Ok(());
    }

    let mut scanner = StringScanner::new(region.start_address, min_length);
    let mut offset = 0_u64;

    while offset < region.size {
        let remaining = region.size - offset;
        let chunk_length = remaining.min(CHUNK_SIZE as u64) as usize;

        let address = region
            .start_address
            .checked_add(offset)
            .ok_or_else(|| "Memory address range overflows".to_string())?;

        let chunk = reader.read_memory(address, chunk_length, region.address_space)?;

        if chunk.len() != chunk_length {
            return Err(format!(
                "Incomplete memory read at 0x{address:016X}: expected {chunk_length} bytes, received {}",
                chunk.len()
            ));
        }

        for (index, byte) in chunk.iter().enumerate() {
            let byte_address = address
                .checked_add(index as u64)
                .ok_or_else(|| "Memory address range overflows".to_string())?;

            scanner.push(byte_address, *byte, results);
        }

        offset += chunk_length as u64;
    }

    // Finish each region independently. Strings must not continue
    // across separate memory regions.
    scanner.finish(results);

    Ok(())
}

/// Maintains string-extraction state across multiple chunks.
struct StringScanner {
    region_start: u64,
    min_length: usize,
    ascii_run: StringRun,
    utf16_runs: [StringRun; 2],
    previous_byte: Option<(u64, u8)>,
}

impl StringScanner {
    fn new(region_start: u64, min_length: usize) -> Self {
        Self {
            region_start,
            min_length,
            ascii_run: StringRun::default(),
            utf16_runs: [StringRun::default(), StringRun::default()],
            previous_byte: None,
        }
    }

    fn push(&mut self, address: u64, byte: u8, results: &mut Vec<ExtractedString>) {
        // ASCII scanning.
        if (0x20..=0x7E).contains(&byte) {
            self.ascii_run.push(address, byte as char);
        } else {
            self.ascii_run
                .finish(self.min_length, StringEncoding::Ascii, results);
        }

        // UTF-16LE scanning. Examine adjacent byte pairs at both
        // possible alignments relative to the start of this region.
        if let Some((previous_address, previous_byte)) = self.previous_byte {
            let pair_alignment = ((previous_address - self.region_start) % 2) as usize;

            if byte == 0 && (0x20..=0x7E).contains(&previous_byte) {
                self.utf16_runs[pair_alignment].push(previous_address, previous_byte as char);
            } else {
                self.utf16_runs[pair_alignment].finish(
                    self.min_length,
                    StringEncoding::Utf16Le,
                    results,
                );
            }
        }

        self.previous_byte = Some((address, byte));
    }

    fn finish(&mut self, results: &mut Vec<ExtractedString>) {
        self.ascii_run
            .finish(self.min_length, StringEncoding::Ascii, results);

        for run in &mut self.utf16_runs {
            run.finish(self.min_length, StringEncoding::Utf16Le, results);
        }

        self.previous_byte = None;
    }
}

/// Holds one currently detected string run.
#[derive(Default)]
struct StringRun {
    start_address: Option<u64>,
    value: String,
}

impl StringRun {
    fn push(&mut self, address: u64, character: char) {
        if self.start_address.is_none() {
            self.start_address = Some(address);
        }

        self.value.push(character);
    }

    fn finish(
        &mut self,
        min_length: usize,
        encoding: StringEncoding,
        results: &mut Vec<ExtractedString>,
    ) {
        if self.value.len() >= min_length {
            results.push(ExtractedString {
                address: self.start_address.unwrap(),
                encoding,
                value: std::mem::take(&mut self.value),
            });
        } else {
            self.value.clear();
        }

        self.start_address = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forensic::memory_image::{AddressSpace, ImageMetadata, MemoryImageFormat};
    use std::path::PathBuf;

    struct FakeMemoryReader {
        metadata: ImageMetadata,
        base_address: u64,
        bytes: Vec<u8>,
    }

    impl FakeMemoryReader {
        fn new(base_address: u64, bytes: Vec<u8>) -> Self {
            Self {
                metadata: ImageMetadata {
                    format: MemoryImageFormat::WindowsMinidump,
                    source_path: PathBuf::from("fake.dmp"),
                    architecture: None,
                },
                base_address,
                bytes,
            }
        }
    }

    impl MemoryImageReader for FakeMemoryReader {
        fn metadata(&self) -> &ImageMetadata {
            &self.metadata
        }

        fn memory_regions(&self) -> Result<Vec<MemoryRegion>, String> {
            Ok(vec![MemoryRegion {
                start_address: self.base_address,
                size: self.bytes.len() as u64,
                address_space: AddressSpace::Virtual,
                permissions: None,
            }])
        }

        fn read_memory(
            &self,
            address: u64,
            length: usize,
            address_space: AddressSpace,
        ) -> Result<Vec<u8>, String> {
            if address_space != AddressSpace::Virtual {
                return Err("Unsupported address space".to_string());
            }

            let offset = address
                .checked_sub(self.base_address)
                .ok_or_else(|| "Address is outside fake memory".to_string())?
                as usize;

            let end = offset
                .checked_add(length)
                .ok_or_else(|| "Read range overflows".to_string())?;

            self.bytes
                .get(offset..end)
                .map(|slice| slice.to_vec())
                .ok_or_else(|| "Read is outside fake memory".to_string())
        }
    }

    #[test]
    fn extracts_ascii_strings() {
        let bytes = b"\x00Hello World\x00";

        let result = extract_strings(0x1000, bytes, 5).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "Hello World");
        assert_eq!(result[0].encoding, StringEncoding::Ascii);
        assert_eq!(result[0].address, 0x1001);
    }

    #[test]
    fn extracts_utf16le_strings() {
        let bytes = [
            0x54, 0x00, 0x65, 0x00, 0x78, 0x00, 0x74, 0x00, 0x20, 0x00, 0x45, 0x00, 0x64, 0x00,
            0x69, 0x00, 0x74, 0x00, 0x6F, 0x00, 0x72, 0x00,
        ];

        let result = extract_strings(0x2000, &bytes, 5).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "Text Editor");
        assert_eq!(result[0].encoding, StringEncoding::Utf16Le);
        assert_eq!(result[0].address, 0x2000);
    }

    #[test]
    fn respects_minimum_string_length() {
        let bytes = b"\x00ABC\x00";

        let result = extract_strings(0x1000, bytes, 4).unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn rejects_zero_minimum_length() {
        let result = extract_strings(0x1000, b"Hello", 0);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_overflowing_memory_address_range() {
        let result = extract_strings(u64::MAX - 1, b"ABC", 1);

        assert!(
            result.is_err(),
            "String extraction should reject an overflowing address range"
        );

        assert_eq!(result.unwrap_err(), "Memory address range overflows");
    }

    #[test]
    fn returns_strings_in_address_order() {
        let bytes = b"\x00World\x00Hello\x00";

        let result = extract_strings(0x1000, bytes, 5).unwrap();

        assert_eq!(result.len(), 2);
        assert!(result[0].address < result[1].address);
    }

    #[test]
    fn extracts_ascii_string_across_chunk_boundary() {
        let mut bytes = vec![0; CHUNK_SIZE + 32];
        let value = b"BoundaryString";
        let start = CHUNK_SIZE - 5;

        bytes[start..start + value.len()].copy_from_slice(value);

        let reader = FakeMemoryReader::new(0x1000, bytes);
        let result = extract_strings_from_image(&reader, 5).unwrap();

        assert!(result.iter().any(|item| {
            item.value == "BoundaryString"
                && item.encoding == StringEncoding::Ascii
                && item.address == 0x1000 + start as u64
        }));
    }

    #[test]
    fn extracts_utf16le_string_across_chunk_boundary() {
        let value = "BoundaryText";
        let mut bytes = vec![0; CHUNK_SIZE + 64];
        let start = CHUNK_SIZE - 5;

        for (index, character) in value.bytes().enumerate() {
            bytes[start + index * 2] = character;
            bytes[start + index * 2 + 1] = 0;
        }

        let reader = FakeMemoryReader::new(0x2000, bytes);
        let result = extract_strings_from_image(&reader, 5).unwrap();

        assert!(result.iter().any(|item| {
            item.value == "BoundaryText"
                && item.encoding == StringEncoding::Utf16Le
                && item.address == 0x2000 + start as u64
        }));
    }

    #[test]
    fn rejects_zero_minimum_length_for_image_extraction() {
        let reader = FakeMemoryReader::new(0x1000, b"Hello".to_vec());

        assert!(extract_strings_from_image(&reader, 0).is_err());
    }

    #[test]
    fn writes_all_findings_as_json_lines() {
        let reader = FakeMemoryReader::new(0x1000, b"Hello\0".to_vec());

        let expected = extract_strings_from_image(&reader, 1).unwrap();

        let mut output = Vec::new();

        let count = write_strings_from_image(&reader, 1, &mut output).unwrap();

        let actual: Vec<String> = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                serde_json::from_slice::<serde_json::Value>(line)
                    .unwrap()
                    .to_string()
            })
            .collect();

        let mut expected_json: Vec<String> = expected
            .iter()
            .map(|item| serde_json::to_string(item).unwrap())
            .collect();

        let mut actual_json = actual;

        expected_json.sort();
        actual_json.sort();

        assert_eq!(count, expected.len());
        assert_eq!(actual_json, expected_json);
    }
}
