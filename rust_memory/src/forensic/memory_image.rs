use std::path::PathBuf;

/// Identifies the format of a memory image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryImageFormat {
    WindowsMinidump,
    ElfCore,
    Raw,
}

/// Identifies the address space represented by a memory image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSpace {
    Virtual,
    Physical,
}

/// Describes a memory region available in an image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegion {
    pub start_address: u64,
    pub size: u64,
    pub address_space: AddressSpace,
    pub permissions: Option<String>,
}

/// General metadata shared by supported memory-image formats.
#[derive(Debug, Clone)]
pub struct ImageMetadata {
    pub format: MemoryImageFormat,
    pub source_path: PathBuf,
    pub architecture: Option<String>,
}

/// Common interface implemented by individual memory-image readers.
pub trait MemoryImageReader {
    fn metadata(&self) -> &ImageMetadata;

    fn memory_regions(&self) -> Result<Vec<MemoryRegion>, String>;

    fn read_memory(
        &self,
        address: u64,
        length: usize,
        address_space: AddressSpace,
    ) -> Result<Vec<u8>, String>;
}
