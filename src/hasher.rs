//! `hasher.rs` — Hardware-accelerated SHA-256 hashing for file contents, names, modes, and symlinks.

use std::cell::RefCell;
use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::path::Path;

use memmap2::MmapOptions;
use sha2::{Digest, Sha256};

use crate::config::THREAD_BUF_SIZE;
use crate::model::EntryKind;

/// Precomputed SHA-256 of an empty byte slice `b""`:
/// `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
pub const EMPTY_SHA256: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

thread_local! {
    /// Reusable per-thread read buffer (256 KiB) to eliminate heap allocations across millions of files.
    static READ_BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; THREAD_BUF_SIZE]);
}

/// Extracts the raw POSIX `st_mode` (or synthesized cross-platform equivalent) from `Metadata`.
#[cfg(unix)]
#[inline]
pub fn extract_mode(meta: &Metadata, permission_bits_only: bool) -> u32 {
    use std::os::unix::fs::MetadataExt;
    let raw_mode = meta.mode();
    if permission_bits_only {
        raw_mode & 0o7777
    } else {
        raw_mode
    }
}

#[cfg(not(unix))]
#[inline]
pub fn extract_mode(meta: &Metadata, permission_bits_only: bool) -> u32 {
    let ft = meta.file_type();
    let type_bits = if ft.is_dir() {
        0o040000
    } else if ft.is_symlink() {
        0o120000
    } else {
        0o100000
    };
    let perm_bits = if meta.permissions().readonly() {
        0o444
    } else {
        0o644
    };
    if permission_bits_only {
        perm_bits
    } else {
        type_bits | perm_bits
    }
}

/// Computes the SHA-256 of a 32-bit file/directory mode (`st_mode`) using domain-separated
/// canonical 4-byte little-endian encoding.
#[inline]
pub fn hash_mode(mode: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(mode.to_le_bytes());
    hasher.finalize().into()
}

/// Computes the SHA-256 of an `OsStr` using its exact native OS byte representation
/// without UTF-8 conversion overhead or lossy replacement.
#[inline]
pub fn hash_os_str(s: &OsStr) -> [u8; 32] {
    let bytes = s.as_encoded_bytes();
    if bytes.is_empty() {
        return EMPTY_SHA256;
    }
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Computes the domain-separated composite SHA-256 digest for any entry, incorporating:
/// - `kind` domain tag (`0x01` file, `0x02` directory, `0x03` symlink)
/// - `mode` (when `include_mode` is enabled)
/// - `name_sha256`
/// - `payload_sha256` (file content hash, directory relative path hash, or symlink target hash)
/// - `rel_path` raw OS bytes (when `include_relative_path` is enabled)
#[inline]
pub fn compute_composite_sha256(
    kind: EntryKind,
    mode: u32,
    rel_path: &Path,
    name_sha256: &[u8; 32],
    payload_sha256: &[u8; 32],
    include_relative_path: bool,
    include_mode: bool,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([kind.domain_tag()]);
    if include_mode {
        hasher.update(mode.to_le_bytes());
    }
    hasher.update(name_sha256);
    hasher.update(payload_sha256);
    if include_relative_path {
        hasher.update(rel_path.as_os_str().as_encoded_bytes());
    }
    hasher.finalize().into()
}

/// Opens a regular file once, retrieves its mode via `fstat` (`file.metadata()`) on the open file
/// descriptor (avoiding a second VFS path walk), and hashes its contents using an adaptive 3-tier
/// I/O strategy:
/// 1. Empty files (`size == 0` or first read `== 0`) return `EMPTY_SHA256` immediately.
/// 2. Files `< mmap_threshold` are hashed via the thread-local 256 KiB `READ_BUF` with zero heap
///    allocations and zero kernel `mmap` TLB shootdown overhead.
/// 3. Files `>= mmap_threshold` transition to `memmap2` with `MADV_SEQUENTIAL` read-ahead hints
///    for the remaining bytes, falling back cleanly to buffered streaming if `mmap` is unsupported.
pub fn hash_file_contents_and_mode(
    path: &Path,
    mmap_threshold: u64,
    permission_bits_only: bool,
) -> io::Result<([u8; 32], u64, u32)> {
    let mut file = File::open(path)?;
    let meta = file.metadata()?;
    let mode = extract_mode(&meta, permission_bits_only);
    let known_len = meta.len();

    if known_len == 0 {
        return Ok((EMPTY_SHA256, 0, mode));
    }

    let threshold = mmap_threshold.max(THREAD_BUF_SIZE as u64);

    READ_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        let first_n = file.read(&mut buf[..])?;
        if first_n == 0 {
            return Ok((EMPTY_SHA256, 0, mode));
        }

        let mut hasher = Sha256::new();
        hasher.update(&buf[..first_n]);
        let mut total_read = first_n as u64;

        while total_read < threshold {
            let n = file.read(&mut buf[..])?;
            if n == 0 {
                return Ok((hasher.finalize().into(), total_read, mode));
            }
            hasher.update(&buf[..n]);
            total_read += n as u64;
        }

        // File is at least `threshold` bytes: attempt zero-copy mmap for the remainder
        if let Ok(mmap) = unsafe { MmapOptions::new().map(&file) } {
            let mapped_len = mmap.len() as u64;
            if mapped_len == total_read {
                return Ok((hasher.finalize().into(), total_read, mode));
            } else if mapped_len > total_read {
                #[cfg(unix)]
                unsafe {
                    let _ = libc::madvise(
                        mmap.as_ptr() as *mut libc::c_void,
                        mmap.len(),
                        libc::MADV_SEQUENTIAL,
                    );
                }
                hasher.update(&mmap[total_read as usize..]);
                return Ok((hasher.finalize().into(), mapped_len, mode));
            }
        }

        // Fallback streaming loop if mmap is unavailable or file is special/growing
        loop {
            let n = file.read(&mut buf[..])?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            total_read += n as u64;
        }
        Ok((hasher.finalize().into(), total_read, mode))
    })
}
