//! `model.rs` — Core domain types representing scanned filesystem entries and their SHA-256 digests.

use std::path::PathBuf;

/// Classification of a scanned filesystem entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
}

impl EntryKind {
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            EntryKind::File => "FILE",
            EntryKind::Directory => "DIR",
            EntryKind::Symlink => "SYMLINK",
        }
    }

    #[inline]
    pub const fn domain_tag(self) -> u8 {
        match self {
            EntryKind::File => 0x01,
            EntryKind::Directory => 0x02,
            EntryKind::Symlink => 0x03,
        }
    }
}

/// A completed SHA-256 record for a single file, directory, or symlink.
#[derive(Debug, Clone)]
pub struct ScanRecord {
    pub kind: EntryKind,
    /// POSIX file/directory/symlink mode (`st_mode` on Unix, or synthesized mode on non-Unix).
    pub mode: u32,
    /// SHA-256 of the 4-byte little-endian `mode` value.
    pub mode_sha256: [u8; 32],
    /// SHA-256 of the entry's filename or directory/symlink name (`file_name()`).
    pub name_sha256: [u8; 32],
    /// - For `File`: SHA-256 of the file's full byte contents.
    /// - For `Directory`: SHA-256 of the relative directory path.
    /// - For `Symlink`: SHA-256 of the raw symlink target path bytes (`read_link`).
    pub payload_sha256: [u8; 32],
    /// Domain-separated composite SHA-256 combining entry kind, mode, name hash, payload hash, and relative path.
    pub composite_sha256: [u8; 32],
    /// Size in bytes (file size for regular files, target byte length for symlinks, 0 for directories).
    pub size_bytes: u64,
    /// Path relative to the scan root (or `.` for the root directory itself).
    pub path: PathBuf,
    /// Populated only for `EntryKind::Symlink` with the raw target path.
    pub symlink_target: Option<PathBuf>,
}
