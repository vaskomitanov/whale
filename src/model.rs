//! `model.rs` — Core domain types for scanned filesystem entries (`ScanRecord` enum) and snapshot diff records.

use std::path::{Path, PathBuf};

/// Classification of a scanned filesystem entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Directory,
    Symlink,
    File,
}

impl EntryKind {
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            EntryKind::Directory => "DIR",
            EntryKind::Symlink => "SYMLINK",
            EntryKind::File => "FILE",
        }
    }

    #[inline]
    pub fn from_str_tag(s: &str) -> Option<Self> {
        match s {
            "DIR" => Some(EntryKind::Directory),
            "SYMLINK" => Some(EntryKind::Symlink),
            "FILE" => Some(EntryKind::File),
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

/// Completed SHA-256 scan record modeled as a strongly-typed enum with three variants
/// (`Directory`, `Symlink`, and `File`), each containing strictly the fields applicable
/// to that filesystem object kind.
#[derive(Debug, Clone)]
pub enum ScanRecord {
    /// A directory entry (no file byte size or symlink target).
    Directory {
        /// Path relative to the scan root (or `.` for the root directory itself).
        path: PathBuf,
        /// POSIX directory mode (`st_mode`).
        mode: u32,
        /// SHA-256 of the 4-byte little-endian `mode`.
        mode_sha256: [u8; 32],
        /// SHA-256 of the directory's name (`file_name()`).
        name_sha256: [u8; 32],
        /// SHA-256 of the directory's relative path bytes.
        path_sha256: [u8; 32],
        /// Domain-separated composite SHA-256 digest of the directory entry.
        composite_sha256: [u8; 32],
    },
    /// A symbolic link entry (includes raw `symlink_target` and `target_sha256`, no regular file size).
    Symlink {
        /// Path relative to the scan root.
        path: PathBuf,
        /// Raw target path read via `std::fs::read_link`.
        symlink_target: PathBuf,
        /// POSIX symlink mode (`st_mode`).
        mode: u32,
        /// SHA-256 of the 4-byte little-endian `mode`.
        mode_sha256: [u8; 32],
        /// SHA-256 of the symlink's name (`file_name()`).
        name_sha256: [u8; 32],
        /// SHA-256 of the raw symlink target path bytes.
        target_sha256: [u8; 32],
        /// Domain-separated composite SHA-256 digest of the symlink entry.
        composite_sha256: [u8; 32],
    },
    /// A regular file entry (includes `size_bytes` and `content_sha256`, no symlink target).
    File {
        /// Path relative to the scan root.
        path: PathBuf,
        /// File content length in bytes.
        size_bytes: u64,
        /// POSIX file mode (`st_mode`).
        mode: u32,
        /// SHA-256 of the 4-byte little-endian `mode`.
        mode_sha256: [u8; 32],
        /// SHA-256 of the file's name (`file_name()`).
        name_sha256: [u8; 32],
        /// SHA-256 of the file's full byte contents.
        content_sha256: [u8; 32],
        /// Domain-separated composite SHA-256 digest of the file entry.
        composite_sha256: [u8; 32],
    },
}

impl ScanRecord {
    #[inline]
    pub const fn kind(&self) -> EntryKind {
        match self {
            ScanRecord::Directory { .. } => EntryKind::Directory,
            ScanRecord::Symlink { .. } => EntryKind::Symlink,
            ScanRecord::File { .. } => EntryKind::File,
        }
    }

    #[inline]
    pub fn path(&self) -> &Path {
        match self {
            ScanRecord::Directory { path, .. }
            | ScanRecord::Symlink { path, .. }
            | ScanRecord::File { path, .. } => path,
        }
    }

    #[inline]
    pub const fn mode(&self) -> u32 {
        match self {
            ScanRecord::Directory { mode, .. }
            | ScanRecord::Symlink { mode, .. }
            | ScanRecord::File { mode, .. } => *mode,
        }
    }

    #[inline]
    pub const fn mode_sha256(&self) -> &[u8; 32] {
        match self {
            ScanRecord::Directory { mode_sha256, .. }
            | ScanRecord::Symlink { mode_sha256, .. }
            | ScanRecord::File { mode_sha256, .. } => mode_sha256,
        }
    }

    #[inline]
    pub const fn name_sha256(&self) -> &[u8; 32] {
        match self {
            ScanRecord::Directory { name_sha256, .. }
            | ScanRecord::Symlink { name_sha256, .. }
            | ScanRecord::File { name_sha256, .. } => name_sha256,
        }
    }

    /// Returns the variant-specific primary payload digest:
    /// - `path_sha256` for `Directory`
    /// - `target_sha256` for `Symlink`
    /// - `content_sha256` for `File`
    #[inline]
    pub const fn payload_sha256(&self) -> &[u8; 32] {
        match self {
            ScanRecord::Directory { path_sha256, .. } => path_sha256,
            ScanRecord::Symlink { target_sha256, .. } => target_sha256,
            ScanRecord::File { content_sha256, .. } => content_sha256,
        }
    }

    #[inline]
    pub const fn composite_sha256(&self) -> &[u8; 32] {
        match self {
            ScanRecord::Directory {
                composite_sha256, ..
            }
            | ScanRecord::Symlink {
                composite_sha256, ..
            }
            | ScanRecord::File {
                composite_sha256, ..
            } => composite_sha256,
        }
    }
}

/// Compact in-memory representation of a previously indexed baseline entry loaded from Parquet.
#[derive(Debug, Clone)]
pub struct BaselineEntry {
    pub kind: EntryKind,
    pub mode: u32,
    pub size_bytes: Option<u64>,
    pub payload_sha256: [u8; 32],
    pub composite_sha256: [u8; 32],
    pub symlink_target: Option<Box<str>>,
}

/// Fine-grained classification of a difference between the live filesystem (or a new snapshot)
/// and a baseline Parquet snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffStatus {
    /// Entry exists in the new scan/snapshot but was not present in the baseline Parquet snapshot.
    Added,
    /// Entry existed in the baseline Parquet snapshot but is no longer present in the new scan/snapshot.
    Deleted,
    /// Entry exists in both, but its file content (or symlink target) SHA-256 changed.
    ModifiedContent,
    /// Entry exists in both with identical content/target, but its POSIX mode (`st_mode`) changed.
    ModifiedMode,
    /// Entry exists in both, and both its content/target SHA-256 and POSIX mode changed.
    ModifiedContentAndMode,
    /// Entry path exists in both, but its object kind changed (e.g., `FILE` replaced by `DIR` or `SYMLINK`).
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

/// A difference record emitted when comparing a live directory scan or snapshot against a baseline Parquet snapshot.
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