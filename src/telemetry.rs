//! `telemetry.rs` — Lock-free atomic metrics and order-independent 256-bit multiset accumulators.

use std::sync::atomic::{AtomicU64, Ordering};
use sha2::{Digest, Sha256};

use crate::model::{DiffStatus, ScanRecord};

/// Lock-free atomic telemetry and order-independent 256-bit multiset accumulators.
pub struct ScanTelemetry {
    pub files_count: AtomicU64,
    pub dirs_count: AtomicU64,
    pub symlinks_count: AtomicU64,
    pub errors_count: AtomicU64,
    pub total_file_bytes: AtomicU64,
    /// Diff counters populated when running in `whale compare` or `whale compare-snapshots` mode.
    pub baseline_loaded_count: AtomicU64,
    pub unchanged_count: AtomicU64,
    pub added_count: AtomicU64,
    pub deleted_count: AtomicU64,
    pub modified_content_count: AtomicU64,
    pub modified_mode_count: AtomicU64,
    pub modified_content_and_mode_count: AtomicU64,
    pub modified_type_count: AtomicU64,
    /// Order-independent 256-bit accumulators (4 x 64-bit wrapping sum of digests)
    /// so parallel runs over millions of entries always produce deterministic aggregate digests.
    pub multiset_hash: [AtomicU64; 4],
    pub file_content_multiset: [AtomicU64; 4],
    pub file_name_multiset: [AtomicU64; 4],
    pub file_mode_multiset: [AtomicU64; 4],
    pub dir_name_multiset: [AtomicU64; 4],
    pub dir_mode_multiset: [AtomicU64; 4],
    pub symlink_multiset: [AtomicU64; 4],
}

const fn zero_accumulator() -> [AtomicU64; 4] {
    [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ]
}

impl Default for ScanTelemetry {
    fn default() -> Self {
        Self {
            files_count: AtomicU64::new(0),
            dirs_count: AtomicU64::new(0),
            symlinks_count: AtomicU64::new(0),
            errors_count: AtomicU64::new(0),
            total_file_bytes: AtomicU64::new(0),
            baseline_loaded_count: AtomicU64::new(0),
            unchanged_count: AtomicU64::new(0),
            added_count: AtomicU64::new(0),
            deleted_count: AtomicU64::new(0),
            modified_content_count: AtomicU64::new(0),
            modified_mode_count: AtomicU64::new(0),
            modified_content_and_mode_count: AtomicU64::new(0),
            modified_type_count: AtomicU64::new(0),
            multiset_hash: zero_accumulator(),
            file_content_multiset: zero_accumulator(),
            file_name_multiset: zero_accumulator(),
            file_mode_multiset: zero_accumulator(),
            dir_name_multiset: zero_accumulator(),
            dir_mode_multiset: zero_accumulator(),
            symlink_multiset: zero_accumulator(),
        }
    }
}

impl ScanTelemetry {
    /// Atomically folds a 32-byte SHA-256 digest into a 4x64-bit commutative multiset accumulator.
    #[inline]
    pub fn fold_digest(acc: &[AtomicU64; 4], digest: &[u8; 32]) {
        for (i, slot) in acc.iter().enumerate() {
            let offset = i * 8;
            let word = u64::from_le_bytes([
                digest[offset],
                digest[offset + 1],
                digest[offset + 2],
                digest[offset + 3],
                digest[offset + 4],
                digest[offset + 5],
                digest[offset + 6],
                digest[offset + 7],
            ]);
            slot.fetch_add(word, Ordering::Relaxed);
        }
    }

    /// Finalizes a 4x64-bit accumulator into a canonical 32-byte SHA-256 digest.
    pub fn finalize_accumulator(acc: &[AtomicU64; 4], domain: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        for slot in acc {
            hasher.update(slot.load(Ordering::Relaxed).to_le_bytes());
        }
        hasher.finalize().into()
    }

    /// Records a single `ScanRecord` enum variant's metrics and folds its digests into the accumulators.
    #[inline]
    pub fn record_entry(&self, record: &ScanRecord) {
        match record {
            ScanRecord::Directory {
                mode_sha256,
                name_sha256,
                composite_sha256,
                ..
            } => {
                Self::fold_digest(&self.multiset_hash, composite_sha256);
                self.dirs_count.fetch_add(1, Ordering::Relaxed);
                Self::fold_digest(&self.dir_name_multiset, name_sha256);
                Self::fold_digest(&self.dir_mode_multiset, mode_sha256);
            }
            ScanRecord::Symlink {
                composite_sha256, ..
            } => {
                Self::fold_digest(&self.multiset_hash, composite_sha256);
                self.symlinks_count.fetch_add(1, Ordering::Relaxed);
                Self::fold_digest(&self.symlink_multiset, composite_sha256);
            }
            ScanRecord::File {
                size_bytes,
                mode_sha256,
                name_sha256,
                content_sha256,
                composite_sha256,
                ..
            } => {
                Self::fold_digest(&self.multiset_hash, composite_sha256);
                self.files_count.fetch_add(1, Ordering::Relaxed);
                self.total_file_bytes
                    .fetch_add(*size_bytes, Ordering::Relaxed);
                Self::fold_digest(&self.file_content_multiset, content_sha256);
                Self::fold_digest(&self.file_name_multiset, name_sha256);
                Self::fold_digest(&self.file_mode_multiset, mode_sha256);
            }
        }
    }

    /// Increments the atomic counter corresponding to a detected `DiffStatus`.
    #[inline]
    pub fn record_diff(&self, status: DiffStatus) {
        match status {
            DiffStatus::Added => {
                self.added_count.fetch_add(1, Ordering::Relaxed);
            }
            DiffStatus::Deleted => {
                self.deleted_count.fetch_add(1, Ordering::Relaxed);
            }
            DiffStatus::ModifiedContent => {
                self.modified_content_count.fetch_add(1, Ordering::Relaxed);
            }
            DiffStatus::ModifiedMode => {
                self.modified_mode_count.fetch_add(1, Ordering::Relaxed);
            }
            DiffStatus::ModifiedContentAndMode => {
                self.modified_content_and_mode_count
                    .fetch_add(1, Ordering::Relaxed);
            }
            DiffStatus::ModifiedType => {
                self.modified_type_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    #[inline]
    pub fn total_differences(&self) -> u64 {
        self.added_count.load(Ordering::Relaxed)
            + self.deleted_count.load(Ordering::Relaxed)
            + self.modified_content_count.load(Ordering::Relaxed)
            + self.modified_mode_count.load(Ordering::Relaxed)
            + self.modified_content_and_mode_count.load(Ordering::Relaxed)
            + self.modified_type_count.load(Ordering::Relaxed)
    }
}