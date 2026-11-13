use std::path::{Path, PathBuf};

use super::formats::detect_format;
use super::memory_image::{
    AddressSpace, ImageMetadata, MemoryImageFormat, MemoryImageReader, MemoryRegion,
};
use minidump::MinidumpSystemInfo;
use minidump::system_info::Cpu;
use minidump::{
    Error as MinidumpError, MinidumpMemory64List, MinidumpMemoryList, MmapMinidump,
    UnifiedMemoryList,
};

pub struct MinidumpReader {
    metadata: ImageMetadata,
}

impl MinidumpReader {
    /// Opens and validates a Windows minidump.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();

        let format = detect_format(path)?;

        if format != MemoryImageFormat::WindowsMinidump {
            return Err("File is not a Windows minidump".to_string());
        }

        // Validate the minidump header and stream directory.
        let dump = MmapMinidump::read_path(path)
            .map_err(|error| format!("Failed to parse minidump: {error}"))?;

        // Read optional system architecture metadata.
        let architecture = match dump.get_stream::<MinidumpSystemInfo>() {
            Ok(system_info) => {
                let architecture = match system_info.cpu {
                    Cpu::X86 => "x86".to_string(),
                    Cpu::X86_64 => "x86_64".to_string(),
                    Cpu::Ppc => "ppc".to_string(),
                    Cpu::Ppc64 => "ppc64".to_string(),
                    Cpu::Sparc => "sparc".to_string(),
                    Cpu::Arm => "arm".to_string(),
                    Cpu::Arm64 => "aarch64".to_string(),
                    Cpu::Mips => "mips".to_string(),
                    Cpu::Mips64 => "mips64".to_string(),
                    Cpu::Unknown(value) => format!("unknown({value})"),
                    _ => "unknown".to_string(),
                };

                Some(architecture)
            }
            Err(MinidumpError::StreamNotFound) => None,
            Err(error) => {
                return Err(format!(
                    "Failed to parse minidump system information: {error}"
                ));
            }
        };

        Ok(Self {
            metadata: ImageMetadata {
                format,
                source_path: PathBuf::from(path),
                architecture,
            },
        })
    }

    fn load_dump(&self) -> Result<MmapMinidump, String> {
        MmapMinidump::read_path(&self.metadata.source_path)
            .map_err(|error| format!("Failed to load minidump: {error}"))
    }

    fn get_memory<'a>(dump: &'a MmapMinidump) -> Result<UnifiedMemoryList<'a>, String> {
        match dump.get_stream::<MinidumpMemory64List>() {
            Ok(memory) => Ok(UnifiedMemoryList::Memory64(memory)),

            Err(MinidumpError::StreamNotFound) => match dump.get_stream::<MinidumpMemoryList>() {
                Ok(memory) => Ok(UnifiedMemoryList::Memory(memory)),
                Err(MinidumpError::StreamNotFound) => {
                    Err("Minidump contains no memory streams".to_string())
                }
                Err(error) => Err(format!("Failed to parse MemoryList stream: {error}")),
            },

            Err(error) => Err(format!("Failed to parse Memory64List stream: {error}")),
        }
    }
}

impl MemoryImageReader for MinidumpReader {
    fn metadata(&self) -> &ImageMetadata {
        &self.metadata
    }

    fn memory_regions(&self) -> Result<Vec<MemoryRegion>, String> {
        let dump = self.load_dump()?;

        let memory = Self::get_memory(&dump)?;
        let mut regions = Vec::new();

        for region in memory.iter() {
            let start_address = region.base_address();
            let size = region.size();

            if size == 0 {
                return Err(format!(
                    "Minidump contains a zero-sized memory region at 0x{start_address:X}"
                ));
            }

            start_address
                .checked_add(size)
                .ok_or_else(|| format!("Memory region address overflows at 0x{start_address:X}"))?;

            let available_size = u64::try_from(region.bytes().len())
                .map_err(|_| "Memory region size exceeds addressable range".to_string())?;

            if available_size != size {
                return Err(format!(
                    "Memory region size mismatch at 0x{start_address:X}: metadata reports {size} bytes, but {available_size} bytes are available"
                ));
            }

            regions.push(MemoryRegion {
                start_address,
                size,
                address_space: AddressSpace::Virtual,
                permissions: None,
            });
        }

        regions.sort_by_key(|region| region.start_address);

        for pair in regions.windows(2) {
            let previous = &pair[0];
            let current = &pair[1];

            let previous_end = previous.start_address + previous.size;

            if current.start_address < previous_end {
                return Err(format!(
                    "Overlapping memory regions detected: 0x{:X}..0x{:X} and 0x{:X}..0x{:X}",
                    previous.start_address,
                    previous_end,
                    current.start_address,
                    current.start_address + current.size
                ));
            }
        }

        Ok(regions)
    }

    fn read_memory(
        &self,
        address: u64,
        length: usize,
        address_space: AddressSpace,
    ) -> Result<Vec<u8>, String> {
        if address_space != AddressSpace::Virtual {
            return Err(
                "Windows minidumps expose process virtual addresses, not physical addresses"
                    .to_string(),
            );
        }

        if length == 0 {
            return Ok(Vec::new());
        }

        let length_u64 = u64::try_from(length)
            .map_err(|_| "Requested memory length exceeds addressable range".to_string())?;

        let requested_end = address
            .checked_add(length_u64)
            .ok_or_else(|| "Requested memory range overflows".to_string())?;

        let dump = self.load_dump()?;

        let memory = Self::get_memory(&dump)?;
        for region in memory.iter() {
            let region_start = region.base_address();

            let region_end = region_start
                .checked_add(region.size())
                .ok_or_else(|| "Memory region address overflows".to_string())?;

            if address >= region_start && requested_end <= region_end {
                let offset = usize::try_from(address - region_start)
                    .map_err(|_| "Memory region offset exceeds addressable range".to_string())?;

                let end = offset
                    .checked_add(length)
                    .ok_or_else(|| "Requested memory length overflows".to_string())?;

                let bytes = region.bytes();

                let requested_bytes = bytes.get(offset..end).ok_or_else(|| {
                    "Requested memory range exceeds available region data".to_string()
                })?;

                return Ok(requested_bytes.to_vec());
            }
        }

        Err(format!(
            "Requested address range 0x{address:X}..0x{requested_end:X} is not fully present in the minidump"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_real_notepad_minidump() {
        let path = PathBuf::from("../evidence/memory/notepad-1064-integrated.dmp");

        let reader =
            MinidumpReader::open(&path).expect("Should open the acquired Notepad minidump");

        assert_eq!(reader.metadata().format, MemoryImageFormat::WindowsMinidump);

        assert_eq!(
            reader.metadata().architecture.as_deref(),
            Some("x86_64"),
            "Expected the Notepad minidump architecture to be x86_64"
        );
        let regions = reader
            .memory_regions()
            .expect("Should enumerate memory regions");

        assert!(
            !regions.is_empty(),
            "Expected at least one captured memory region"
        );

        let first_region = &regions[0];

        let bytes = reader
            .read_memory(first_region.start_address, 16, AddressSpace::Virtual)
            .expect("Should read the first 16 bytes");

        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn rejects_physical_memory_reads() {
        let path = PathBuf::from("../evidence/memory/notepad-1064-integrated.dmp");
        let reader = MinidumpReader::open(&path).unwrap();

        let result = reader.read_memory(0x1000, 16, AddressSpace::Physical);

        assert!(result.unwrap_err().contains("not physical addresses"));
    }

    #[test]
    fn returns_empty_for_zero_length_read() {
        let path = PathBuf::from("../evidence/memory/notepad-1064-integrated.dmp");
        let reader = MinidumpReader::open(&path).unwrap();

        let result = reader
            .read_memory(u64::MAX, 0, AddressSpace::Virtual)
            .unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn rejects_overflowing_memory_range() {
        let path = PathBuf::from("../evidence/memory/notepad-1064-integrated.dmp");
        let reader = MinidumpReader::open(&path).unwrap();

        let result = reader.read_memory(u64::MAX, 1, AddressSpace::Virtual);

        assert!(result.unwrap_err().contains("overflows"));
    }

    #[test]
    fn rejects_unmapped_memory_address() {
        let path = PathBuf::from("../evidence/memory/notepad-1064-integrated.dmp");
        let reader = MinidumpReader::open(&path).unwrap();

        let result = reader.read_memory(0, 1, AddressSpace::Virtual);

        assert!(result.is_err());
    }
    #[test]
    fn rejects_truncated_minidump() {
        let path =
            std::env::temp_dir().join(format!("truncated-minidump-{}.dmp", std::process::id()));

        std::fs::write(&path, b"MDMP").expect("Should create truncated minidump");

        let result = MinidumpReader::open(&path);

        std::fs::remove_file(&path).expect("Should remove temporary minidump");

        assert!(result.is_err(), "Truncated minidump should be rejected");
    }

    #[test]
    fn rejects_non_minidump_format() {
        let path =
            std::env::temp_dir().join(format!("non-minidump-format-{}.elf", std::process::id()));

        let mut header = vec![0u8; 20];
        header[0..4].copy_from_slice(b"\x7FELF");
        header[4] = 2;
        header[5] = 1;
        header[16..18].copy_from_slice(&4u16.to_le_bytes());

        std::fs::write(&path, header).expect("Should create ELF core header");

        let result = MinidumpReader::open(&path);

        std::fs::remove_file(&path).expect("Should remove temporary ELF file");

        match result {
            Ok(_) => panic!("MinidumpReader should reject ELF core files"),
            Err(error) => {
                assert!(error.contains("not a Windows minidump"));
            }
        }
    }

    #[test]
    fn rejects_invalid_stream_directory() {
        let path = std::env::temp_dir().join(format!(
            "invalid-directory-minidump-{}.dmp",
            std::process::id()
        ));

        // A 32-byte header with an invalid stream-directory RVA.
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(b"MDMP");
        data[4..8].copy_from_slice(&0x0000_A793u32.to_le_bytes());
        data[8..12].copy_from_slice(&1u32.to_le_bytes());
        data[12..16].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());

        std::fs::write(&path, data).expect("Should create invalid minidump");

        let result = MinidumpReader::open(&path);

        std::fs::remove_file(&path).expect("Should remove temporary minidump");

        assert!(
            result.is_err(),
            "Minidump with invalid stream directory should be rejected"
        );
    }
    #[test]
    fn rejects_reads_extending_beyond_region_boundary() {
        let path = PathBuf::from("../evidence/memory/notepad-1064-integrated.dmp");
        let reader = MinidumpReader::open(&path).unwrap();

        let regions = reader.memory_regions().unwrap();
        let region = &regions[0];

        let last_address = region.start_address + region.size - 1;

        let result = reader.read_memory(last_address, 2, AddressSpace::Virtual);

        assert!(result.is_err());
    }
}
