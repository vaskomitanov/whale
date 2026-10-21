//! `model.rs` — Core domain types for scanned filesystem entries and snapshot diff records.

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
    pub fn from_str_tag(s: &str) -> Option<Self> {
        match s {
            "FILE" => Some(EntryKind::File),
            "DIR" => Some(EntryKind::Directory),
            "SYMLINK" => Some(EntryKind::Symlink),
            _ => None,
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

/// Compact in-memory representation of a previously indexed baseline entry loaded from Parquet.
#[derive(Debug, Clone)]
pub struct BaselineEntry {
    pub kind: EntryKind,
    pub mode: u32,
    pub size_bytes: u64,
    pub payload_sha256: [u8; 32],
    pub composite_sha256: [u8; 32],
    pub symlink_target: Option<Box<str>>,
}

/// Fine-grained classification of a difference between the live filesystem (or a new snapshot)
/// and a baseline Parquet snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffStatus {
    /// Entry exists in the new scan/snapshot but was not present in the baseline Parquet file.
    Added,
    /// Entry existed in the baseline Parquet file but is no longer present in the new scan/snapshot.
    Deleted,
    /// Entry exists in both, but its file content (or symlink target) SHA-256 changed.
    ModifiedContent,
    /// Entry exists in both with identical content/target, but its POSIX mode (`st_mode`) changed.
    ModifiedMode,
    /// Entry exists in both, and both its content/target SHA-256 and POSIX mode changed.
    ModifiedContentAndMode,
    /// Entry path exists in both, but its object type changed (e.g., `FILE` replaced by `DIR` or `SYMLINK`).
    ModifiedType,
}

impl DiffStatus {
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            DiffStatus::Added => "ADDED",
            DiffStatus::Deleted => "DELETED",
            DiffStatus::ModifiedContent => "MODIFIED_CONTENT",
            DiffStatus::ModifiedMode => "MODIFIED_MODE",
            DiffStatus::ModifiedContentAndMode => "MODIFIED_CONTENT_AND_MODE",
            DiffStatus::ModifiedType => "MODIFIED_TYPE",
        }
    }
}

/// A difference record emitted when comparing a live directory scan or snapshot against a baseline Parquet file.
#[derive(Debug, Clone)]
pub struct DiffRecord {
    pub status: DiffStatus,
    pub path: PathBuf,
    pub old_kind: Option<EntryKind>,
    pub new_kind: Option<EntryKind>,
    pub old_mode: Option<u32>,
    pub new_mode: Option<u32>,
    pub old_size_bytes: Option<u64>,
    pub new_size_bytes: Option<u64>,
    pub old_payload_sha256: Option<[u8; 32]>,
    pub new_payload_sha256: Option<[u8; 32]>,
    pub old_composite_sha256: Option<[u8; 32]>,
    pub new_composite_sha256: Option<[u8; 32]>,
    pub old_symlink_target: Option<String>,
    pub new_symlink_target: Option<String>,
}
