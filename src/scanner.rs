//! `scanner.rs` — Lock-free work-stealing directory traversal and thread-local batching.

use std::cell::RefCell;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use crossbeam_channel::Sender;
use rayon::ScopeFifo;

use crate::config::{CliConfig, FILE_CHUNK_SIZE, RECORD_BATCH_SIZE};
use crate::diff::{evaluate_live_record_diff, ShardedBaselineIndex};
use crate::hasher::{
    compute_composite_sha256, extract_mode, hash_file_contents_and_mode, hash_mode, hash_os_str,
};
use crate::model::{DiffRecord, EntryKind, ScanRecord};
use crate::telemetry::ScanTelemetry;

thread_local! {
    /// Reusable per-thread record batch to amortize channel send operations by 256x.
    static LOCAL_BATCH: RefCell<Vec<ScanRecord>> = RefCell::new(Vec::with_capacity(RECORD_BATCH_SIZE));
}

/// Shared context passed across Rayon work-stealing tasks.
pub struct ScannerContext {
    pub config: CliConfig,
    pub root_base: PathBuf,
    pub telemetry: ScanTelemetry,
    pub tx: Option<Sender<Vec<ScanRecord>>>,
    /// Present when running in `whale compare` mode for on-the-fly O(1) diff evaluation.
    pub baseline_index: Option<ShardedBaselineIndex>,
    pub diff_tx: Option<Sender<Vec<DiffRecord>>>,
}

impl ScannerContext {
    #[inline]
    pub fn emit_record(&self, record: ScanRecord) {
        self.telemetry.record_entry(&record);

        if let Some(ref baseline) = self.baseline_index {
            evaluate_live_record_diff(record, baseline, &self.telemetry, &self.diff_tx);
            return;
        }

        if let Some(ref tx) = self.tx {
            LOCAL_BATCH.with(|cell| {
                let mut batch = cell.borrow_mut();
                batch.push(record);
                if batch.len() >= RECORD_BATCH_SIZE {
                    let full_batch =
                        std::mem::replace(&mut *batch, Vec::with_capacity(RECORD_BATCH_SIZE));
                    let _ = tx.send(full_batch);
                }
            });
        }
    }

    #[inline]
    pub fn log_error(&self, path: &Path, err: &io::Error) {
        self.telemetry.errors_count.fetch_add(1, Ordering::Relaxed);
        eprintln!("[WARN] {}: {}", path.display(), err);
    }
}

/// Flushes any remaining thread-local `ScanRecord` batches across all Rayon worker threads
/// and the calling thread once directory traversal finishes.
pub fn flush_all_thread_batches(sender: &Sender<Vec<ScanRecord>>) {
    rayon::broadcast(|_| {
        LOCAL_BATCH.with(|cell| {
            let mut batch = cell.borrow_mut();
            if !batch.is_empty() {
                let tail = std::mem::take(&mut *batch);
                let _ = sender.send(tail);
            }
        });
    });
    LOCAL_BATCH.with(|cell| {
        let mut batch = cell.borrow_mut();
        if !batch.is_empty() {
            let tail = std::mem::take(&mut *batch);
            let _ = sender.send(tail);
        }
    });
}

/// Raises the soft open file descriptor limit (`RLIMIT_NOFILE`) toward the hard limit on Unix
/// so parallel traversal across high-core-count machines never hits `EMFILE`.
#[cfg(unix)]
pub fn maximize_file_descriptor_limit() {
    unsafe {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) == 0 && rlim.rlim_cur < rlim.rlim_max {
            let target = std::cmp::min(rlim.rlim_max, 1_048_576);
            if rlim.rlim_cur < target {
                rlim.rlim_cur = target;
                let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &rlim);
            }
        }
    }
}

#[cfg(not(unix))]
pub fn maximize_file_descriptor_limit() {}

/// Computes the path relative to `root_base` without allocating when `strip_prefix` succeeds.
#[inline]
fn relative_path<'a>(path: &'a Path, root_base: &Path) -> &'a Path {
    path.strip_prefix(root_base).unwrap_or(path)
}

/// Processes a single regular file entry and emits `ScanRecord::File`.
pub fn process_file(ctx: &ScannerContext, path: PathBuf) {
    let (content_sha256, size_bytes, mode) = match hash_file_contents_and_mode(
        &path,
        ctx.config.mmap_threshold,
        ctx.config.permission_bits_only,
    ) {
        Ok(res) => res,
        Err(e) => {
            ctx.log_error(&path, &e);
            return;
        }
    };

    let mode_sha256 = hash_mode(mode);
    let name_os = path.file_name().unwrap_or_else(|| path.as_os_str());
    let name_sha256 = hash_os_str(name_os);
    let rel = relative_path(&path, &ctx.root_base);
    let composite_sha256 = compute_composite_sha256(
        EntryKind::File,
        mode,
        rel,
        &name_sha256,
        &content_sha256,
        ctx.config.include_relative_path,
        ctx.config.include_mode,
    );

    ctx.emit_record(ScanRecord::File {
        path: if rel.as_os_str().is_empty() {
            path
        } else {
            rel.to_path_buf()
        },
        size_bytes,
        mode,
        mode_sha256,
        name_sha256,
        content_sha256,
        composite_sha256,
    });
}

/// Processes a single symbolic link entry and emits `ScanRecord::Symlink`.
pub fn process_symlink(ctx: &ScannerContext, path: PathBuf) {
    let symlink_target = match fs::read_link(&path) {
        Ok(t) => t,
        Err(e) => {
            ctx.log_error(&path, &e);
            return;
        }
    };

    let mode = match fs::symlink_metadata(&path) {
        Ok(meta) => extract_mode(&meta, ctx.config.permission_bits_only),
        Err(_) => {
            if ctx.config.permission_bits_only {
                0o777
            } else {
                0o120777
            }
        }
    };
    let mode_sha256 = hash_mode(mode);

    let name_os = path.file_name().unwrap_or_else(|| path.as_os_str());
    let name_sha256 = hash_os_str(name_os);
    let target_sha256 = hash_os_str(symlink_target.as_os_str());
    let rel = relative_path(&path, &ctx.root_base);

    let composite_sha256 = compute_composite_sha256(
        EntryKind::Symlink,
        mode,
        rel,
        &name_sha256,
        &target_sha256,
        ctx.config.include_relative_path,
        ctx.config.include_mode,
    );

    ctx.emit_record(ScanRecord::Symlink {
        path: if rel.as_os_str().is_empty() {
            path
        } else {
            rel.to_path_buf()
        },
        symlink_target,
        mode,
        mode_sha256,
        name_sha256,
        target_sha256,
        composite_sha256,
    });
}

/// Processes a directory entry, emits `ScanRecord::Directory`, and dispatches all children
/// into Rayon's work-stealing FIFO queue after closing the OS directory descriptor.
pub fn process_directory<'scope>(
    ctx: &'scope ScannerContext,
    scope: &ScopeFifo<'scope>,
    dir_path: PathBuf,
) {
    // 1. Retrieve directory metadata for directory mode (`st_mode`)
    let dir_meta = match fs::symlink_metadata(&dir_path) {
        Ok(m) => m,
        Err(e) => {
            ctx.log_error(&dir_path, &e);
            return;
        }
    };
    let mode = extract_mode(&dir_meta, ctx.config.permission_bits_only);
    let mode_sha256 = hash_mode(mode);

    // 2. Hash the directory's own name and relative path
    let name_os = dir_path.file_name().unwrap_or_else(|| dir_path.as_os_str());
    let name_sha256 = hash_os_str(name_os);
    let rel = relative_path(&dir_path, &ctx.root_base);
    let rel_display = if rel.as_os_str().is_empty() {
        Path::new(".")
    } else {
        rel
    };
    let path_sha256 = hash_os_str(rel_display.as_os_str());
    let composite_sha256 = compute_composite_sha256(
        EntryKind::Directory,
        mode,
        rel_display,
        &name_sha256,
        &path_sha256,
        ctx.config.include_relative_path,
        ctx.config.include_mode,
    );

    ctx.emit_record(ScanRecord::Directory {
        path: rel_display.to_path_buf(),
        mode,
        mode_sha256,
        name_sha256,
        path_sha256,
        composite_sha256,
    });

    // 3. Read directory entries and immediately close the OS directory handle (`ReadDir`)
    let mut subdirs: Vec<PathBuf> = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    let mut symlinks: Vec<PathBuf> = Vec::new();

    {
        let read_dir = match fs::read_dir(&dir_path) {
            Ok(rd) => rd,
            Err(e) => {
                ctx.log_error(&dir_path, &e);
                return;
            }
        };

        for entry_res in read_dir {
            let entry = match entry_res {
                Ok(e) => e,
                Err(e) => {
                    ctx.log_error(&dir_path, &e);
                    continue;
                }
            };

            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(e) => {
                    ctx.log_error(&entry.path(), &e);
                    continue;
                }
            };

            let child_path = entry.path();
            if ft.is_file() {
                files.push(child_path);
            } else if ft.is_dir() {
                subdirs.push(child_path);
            } else if ft.is_symlink() {
                symlinks.push(child_path);
            }
        }
        // `read_dir` is dropped here, releasing the OS directory FD before any child tasks run!
    }

    // 4. Spawn child directories into Rayon's FIFO work-stealing queue first
    for subdir in subdirs {
        scope.spawn_fifo(move |s| {
            process_directory(ctx, s, subdir);
        });
    }

    // 5. Process symlinks
    for symlink_path in symlinks {
        process_symlink(ctx, symlink_path);
    }

    // 6. Dispatch files in adaptive chunks (64 files per task)
    if files.len() <= FILE_CHUNK_SIZE {
        for file_path in files {
            process_file(ctx, file_path);
        }
    } else {
        let mut iter = files.into_iter();
        loop {
            let chunk: Vec<PathBuf> = iter.by_ref().take(FILE_CHUNK_SIZE).collect();
            if chunk.is_empty() {
                break;
            }
            scope.spawn_fifo(move |_| {
                for file_path in chunk {
                    process_file(ctx, file_path);
                }
            });
        }
    }
}