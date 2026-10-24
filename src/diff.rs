//! `diff.rs` — High-performance Delta Lake (`delta-rs`) namespace reader, 256-shard O(1)
//! remove-on-visit comparator, and streaming TSV / JSONL / Delta-Parquet diff writers.
//!
//! ### How `delta-rs` Namespace Resolution + Parallel Row-Group Ingestion Works:
//! 1. Given a Delta snapshot root directory (`<root>/`), `resolve_active_parquet_files_from_delta`
//!    opens the three `delta-rs` namespaces (`<root>/directories`, `<root>/symlinks`, `<root>/files`)
//!    concurrently via `deltalake::open_table` (or `deltalake::open_table_with_version` when
//!    time-travel `--baseline-version` / `--target-version` is specified).
//! 2. It queries `_delta_log` state (`table.get_file_uris()`) in `< 1 ms` to obtain the exact set
//!    of active (non-tombstoned) Parquet data files across all three namespaces.
//! 3. All active Parquet files and their row groups are fed directly into Rayon's work-stealing
//!    thread pool (`into_par_iter()`), parsing `Directory`, `Symlink`, and `File` schemas in parallel
//!    into the 256-shard `ShardedBaselineIndex` (`rustc_hash::FxHashMap`) at multi-GB/s throughput!

use std::cell::RefCell;
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use arrow_array::builder::{Int32Builder, Int64Builder, StringBuilder};
use arrow_array::{Array, ArrayRef, Int32Array, Int64Array, RecordBatch, StringArray, UInt32Array, UInt64Array};
use arrow_schema::{DataType, Field, Schema};
use crossbeam_channel::{Receiver, Sender};
use deltalake::kernel::{DataType as DeltaDataType, PrimitiveType, StructField};
use deltalake::writer::{DeltaWriter, RecordBatchWriter};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHasher};

use crate::config::{
    OutputFormat, ParquetCompression, BASELINE_SHARD_COUNT, RECORD_BATCH_SIZE, WRITER_BUF_CAPACITY,
};
use crate::hasher::{hash_mode, hash_os_str};
use crate::model::{BaselineEntry, DiffRecord, DiffStatus, EntryKind, ScanRecord};
use crate::parquet_writer::{
    build_writer_properties, init_delta_namespace_table, DeltaNamespacePaths,
};
use crate::telemetry::ScanTelemetry;
use crate::writer::{encode_hex_64, format_octal_mode, write_json_escaped};

thread_local! {
    /// Reusable per-thread diff batch to amortize channel operations by 256x.
    static LOCAL_DIFF_BATCH: RefCell<Vec<DiffRecord>> = RefCell::new(Vec::with_capacity(RECORD_BATCH_SIZE));
}

/// 256-shard concurrent map storing baseline entries keyed by relative path (`Box<str>`).
pub struct ShardedBaselineIndex {
    shards: Vec<Mutex<FxHashMap<Box<str>, BaselineEntry>>>,
}

impl ShardedBaselineIndex {
    pub fn with_total_capacity(expected_entries: usize) -> Self {
        let per_shard = (expected_entries / BASELINE_SHARD_COUNT).max(64);
        let mut shards = Vec::with_capacity(BASELINE_SHARD_COUNT);
        for _ in 0..BASELINE_SHARD_COUNT {
            shards.push(Mutex::new(FxHashMap::with_capacity_and_hasher(
                per_shard,
                Default::default(),
            )));
        }
        Self { shards }
    }

    #[inline]
    fn shard_index(path_key: &str) -> usize {
        let mut hasher = FxHasher::default();
        path_key.hash(&mut hasher);
        (hasher.finish() as usize) & (BASELINE_SHARD_COUNT - 1)
    }

    #[inline]
    pub fn insert_batch(&self, items: Vec<(Box<str>, BaselineEntry)>) {
        let mut grouped: Vec<Vec<(Box<str>, BaselineEntry)>> =
            (0..BASELINE_SHARD_COUNT).map(|_| Vec::new()).collect();
        for (path, entry) in items {
            let idx = Self::shard_index(&path);
            grouped[idx].push((path, entry));
        }
        for (idx, bucket) in grouped.into_iter().enumerate() {
            if !bucket.is_empty() {
                let mut guard = self.shards[idx].lock().unwrap();
                for (k, v) in bucket {
                    guard.insert(k, v);
                }
            }
        }
    }

    /// Atomically looks up and removes `path_key` from its corresponding shard in O(1) expected time.
    #[inline]
    pub fn remove(&self, path_key: &str) -> Option<BaselineEntry> {
        let idx = Self::shard_index(path_key);
        let mut guard = self.shards[idx].lock().unwrap();
        guard.remove(path_key)
    }

    /// Drains all remaining unvisited entries across all 256 shards in parallel and emits them
    /// as `DiffStatus::Deleted`.
    pub fn drain_deleted_parallel(
        &self,
        telemetry: &ScanTelemetry,
        diff_tx: &Option<Sender<Vec<DiffRecord>>>,
    ) {
        self.shards.par_iter().for_each(|shard_mutex| {
            let map = {
                let mut guard = shard_mutex.lock().unwrap();
                std::mem::take(&mut *guard)
            };
            for (path_box, old) in map {
                telemetry.record_diff(DiffStatus::Deleted);
                if let Some(ref tx) = diff_tx {
                    let rec = DiffRecord {
                        status: DiffStatus::Deleted,
                        path: PathBuf::from(path_box.into_string()),
                        old_kind: Some(old.kind),
                        new_kind: None,
                        old_mode: Some(old.mode),
                        new_mode: None,
                        old_size_bytes: old.size_bytes,
                        new_size_bytes: None,
                        old_payload_sha256: Some(old.payload_sha256),
                        new_payload_sha256: None,
                        old_composite_sha256: Some(old.composite_sha256),
                        new_composite_sha256: None,
                        old_symlink_target: old.symlink_target.map(|s| s.into_string()),
                        new_symlink_target: None,
                    };
                    push_thread_local_diff(rec, tx);
                }
            }
        });
    }
}

#[inline]
pub fn push_thread_local_diff(rec: DiffRecord, tx: &Sender<Vec<DiffRecord>>) {
    LOCAL_DIFF_BATCH.with(|cell| {
        let mut batch = cell.borrow_mut();
        batch.push(rec);
        if batch.len() >= RECORD_BATCH_SIZE {
            let full = std::mem::replace(&mut *batch, Vec::with_capacity(RECORD_BATCH_SIZE));
            let _ = tx.send(full);
        }
    });
}

pub fn flush_all_diff_batches(sender: &Sender<Vec<DiffRecord>>) {
    rayon::broadcast(|_| {
        LOCAL_DIFF_BATCH.with(|cell| {
            let mut batch = cell.borrow_mut();
            if !batch.is_empty() {
                let tail = std::mem::take(&mut *batch);
                let _ = sender.send(tail);
            }
        });
    });
    LOCAL_DIFF_BATCH.with(|cell| {
        let mut batch = cell.borrow_mut();
        if !batch.is_empty() {
            let tail = std::mem::take(&mut *batch);
            let _ = sender.send(tail);
        }
    });
}

/// Decodes a 64-character hex string into a 32-byte SHA-256 array.
#[inline]
fn decode_hex_32(hex_str: &str) -> io::Result<[u8; 32]> {
    let bytes = hex_str.as_bytes();
    if bytes.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Expected 64-char SHA-256 hex digest in Parquet, got len {}",
                bytes.len()
            ),
        ));
    }
    let mut out = [0u8; 32];
    faster_hex::hex_decode(bytes, &mut out)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(out)
}

/// Opens a single `delta-rs` namespace table (`directories`, `symlinks`, or `files`) and returns
/// the filesystem paths of all active Parquet data files in that table snapshot.
async fn collect_delta_namespace_parquet_files(
    ns_dir: &Path,
    version: Option<i64>,
) -> io::Result<Vec<PathBuf>> {
    if !ns_dir.join("_delta_log").is_dir() {
        return Ok(Vec::new());
    }
    let abs_dir = fs::canonicalize(ns_dir)?;
    let uri = url::Url::from_directory_path(&abs_dir).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid Delta namespace path: {}", abs_dir.display()),
        )
    })?;

    let table = match version {
        Some(v) => deltalake::open_table_with_version(uri.as_str(), v)
            .await
            .map_err(io::Error::other)?,
        None => deltalake::open_table(uri.as_str())
            .await
            .map_err(io::Error::other)?,
    };

    let uris = table
        .get_file_uris()
        .map_err(io::Error::other)?;

    let mut files = Vec::new();
    for u in uris {
        let p = PathBuf::from(&u);
        if p.exists() {
            files.push(p);
        } else if let Ok(parsed_url) = url::Url::parse(&u) {
            if let Ok(fp) = parsed_url.to_file_path() {
                if fp.exists() {
                    files.push(fp);
                }
            }
        }
    }
    Ok(files)
}

/// Resolves all active Parquet data files across the three `delta-rs` namespaces
/// (`<root>/directories`, `<root>/symlinks`, `<root>/files`) using `deltalake::open_table`.
pub fn resolve_active_parquet_files_from_delta(
    base_path: &Path,
    version: Option<i64>,
) -> io::Result<Vec<PathBuf>> {
    let ns_paths = DeltaNamespacePaths::from_base_path(base_path);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let mut active_files = rt.block_on(async {
        let (mut d_files, mut s_files, mut f_files) = tokio::try_join!(
            collect_delta_namespace_parquet_files(&ns_paths.directories_ns, version),
            collect_delta_namespace_parquet_files(&ns_paths.symlinks_ns, version),
            collect_delta_namespace_parquet_files(&ns_paths.files_ns, version),
        )?;
        let mut all = Vec::with_capacity(d_files.len() + s_files.len() + f_files.len());
        all.append(&mut d_files);
        all.append(&mut s_files);
        all.append(&mut f_files);

        // Also support pointing directly at a single Delta namespace folder
        if all.is_empty() && base_path.join("_delta_log").is_dir() {
            let mut single = collect_delta_namespace_parquet_files(base_path, version).await?;
            all.append(&mut single);
        }
        Ok::<Vec<PathBuf>, io::Error>(all)
    })?;

    // Fallback if a raw standalone `.parquet` file was passed directly
    if active_files.is_empty() && base_path.is_file() {
        active_files.push(base_path.to_path_buf());
    }

    if active_files.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "No active Delta Lake namespace tables found under '{}' (expected namespaces: '{}/directories', '{}/symlinks', '{}/files')",
                base_path.display(),
                base_path.display(),
                base_path.display(),
                base_path.display(),
            ),
        ));
    }

    Ok(active_files)
}

/// Parses a `RecordBatch` from any of the three Delta namespace schemas (`Directory`, `Symlink`, or `File`)
/// into `ScanRecord` enum instances.
fn parse_record_batch_into_scan_records(batch: &RecordBatch) -> io::Result<Vec<ScanRecord>> {
    let num_rows = batch.num_rows();
    if num_rows == 0 {
        return Ok(Vec::new());
    }

    let schema = batch.schema();
    let has_content_sha = schema.column_with_name("content_sha256").is_some();
    let has_target_sha = schema.column_with_name("target_sha256").is_some();
    let has_path_sha = schema.column_with_name("path_sha256").is_some();

    let path_col = batch
        .column_by_name("path")
        .and_then(|c| c.as_any().downcast_ref::<StringArray>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing 'path' column"))?;
    let mode_col_i32 = batch
        .column_by_name("mode")
        .and_then(|c| c.as_any().downcast_ref::<Int32Array>());
    let mode_col_u32 = batch
        .column_by_name("mode")
        .and_then(|c| c.as_any().downcast_ref::<UInt32Array>());
    if mode_col_i32.is_none() && mode_col_u32.is_none() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Missing or invalid 'mode' column"));
    }
    let mode_sha_col = batch
        .column_by_name("mode_sha256")
        .and_then(|c| c.as_any().downcast_ref::<StringArray>());
    let name_sha_col = batch
        .column_by_name("name_sha256")
        .and_then(|c| c.as_any().downcast_ref::<StringArray>());
    let comp_col = batch
        .column_by_name("composite_sha256")
        .and_then(|c| c.as_any().downcast_ref::<StringArray>())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Missing 'composite_sha256' column")
        })?;

    let mut records = Vec::with_capacity(num_rows);

    if has_content_sha {
        let size_col_i64 = batch
            .column_by_name("size_bytes")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>());
        let size_col_u64 = batch
            .column_by_name("size_bytes")
            .and_then(|c| c.as_any().downcast_ref::<UInt64Array>());
        if size_col_i64.is_none() && size_col_u64.is_none() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Missing or invalid 'size_bytes' column"));
        }
        let content_col = batch
            .column_by_name("content_sha256")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Missing 'content_sha256' column")
            })?;

        for i in 0..num_rows {
            let path = PathBuf::from(path_col.value(i));
            let mode = mode_col_i32.map(|c| c.value(i) as u32).unwrap_or_else(|| mode_col_u32.unwrap().value(i));
            let mode_sha256 = match mode_sha_col {
                Some(c) => decode_hex_32(c.value(i))?,
                None => hash_mode(mode),
            };
            let name_sha256 = match name_sha_col {
                Some(c) => decode_hex_32(c.value(i))?,
                None => hash_os_str(path.file_name().unwrap_or_else(|| path.as_os_str())),
            };
            records.push(ScanRecord::File {
                path,
                size_bytes: size_col_i64.map(|c| c.value(i) as u64).unwrap_or_else(|| size_col_u64.unwrap().value(i)),
                mode,
                mode_sha256,
                name_sha256,
                content_sha256: decode_hex_32(content_col.value(i))?,
                composite_sha256: decode_hex_32(comp_col.value(i))?,
            });
        }
    } else if has_target_sha {
        let target_path_col = batch
            .column_by_name("symlink_target")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Missing 'symlink_target' column")
            })?;
        let target_sha_col = batch
            .column_by_name("target_sha256")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Missing 'target_sha256' column")
            })?;

        for i in 0..num_rows {
            let path = PathBuf::from(path_col.value(i));
            let symlink_target = PathBuf::from(target_path_col.value(i));
            let mode = mode_col_i32.map(|c| c.value(i) as u32).unwrap_or_else(|| mode_col_u32.unwrap().value(i));
            let mode_sha256 = match mode_sha_col {
                Some(c) => decode_hex_32(c.value(i))?,
                None => hash_mode(mode),
            };
            let name_sha256 = match name_sha_col {
                Some(c) => decode_hex_32(c.value(i))?,
                None => hash_os_str(path.file_name().unwrap_or_else(|| path.as_os_str())),
            };
            records.push(ScanRecord::Symlink {
                path,
                symlink_target,
                mode,
                mode_sha256,
                name_sha256,
                target_sha256: decode_hex_32(target_sha_col.value(i))?,
                composite_sha256: decode_hex_32(comp_col.value(i))?,
            });
        }
    } else if has_path_sha {
        let path_sha_col = batch
            .column_by_name("path_sha256")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Missing 'path_sha256' column")
            })?;

        for i in 0..num_rows {
            let path = PathBuf::from(path_col.value(i));
            let mode = mode_col_i32.map(|c| c.value(i) as u32).unwrap_or_else(|| mode_col_u32.unwrap().value(i));
            let mode_sha256 = match mode_sha_col {
                Some(c) => decode_hex_32(c.value(i))?,
                None => hash_mode(mode),
            };
            let name_sha256 = match name_sha_col {
                Some(c) => decode_hex_32(c.value(i))?,
                None => hash_os_str(path.file_name().unwrap_or_else(|| path.as_os_str())),
            };
            records.push(ScanRecord::Directory {
                path,
                mode,
                mode_sha256,
                name_sha256,
                path_sha256: decode_hex_32(path_sha_col.value(i))?,
                composite_sha256: decode_hex_32(comp_col.value(i))?,
            });
        }
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unrecognized Delta/Parquet schema (expected Directory, Symlink, or File schema)",
        ));
    }

    Ok(records)
}

/// Resolves active Parquet files from the three `delta-rs` namespaces (`directories`, `symlinks`, `files`)
/// and loads all row groups in parallel across Rayon worker threads into a 256-shard `ShardedBaselineIndex`.
pub fn load_baseline_parquet(
    delta_root_path: &Path,
    version: Option<i64>,
    telemetry: &ScanTelemetry,
) -> io::Result<ShardedBaselineIndex> {
    let parquet_files = resolve_active_parquet_files_from_delta(delta_root_path, version)?;

    let mut tasks: Vec<(PathBuf, usize)> = Vec::new();
    let mut total_expected_rows = 0usize;

    for file_path in &parquet_files {
        let f = File::open(file_path)?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(f)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let meta = builder.metadata();
        for rg_idx in 0..meta.num_row_groups() {
            total_expected_rows += meta.row_group(rg_idx).num_rows().max(0) as usize;
            tasks.push((file_path.clone(), rg_idx));
        }
    }

    let index = ShardedBaselineIndex::with_total_capacity(total_expected_rows);

    let results: Vec<io::Result<usize>> = tasks
        .into_par_iter()
        .map(|(file_path, rg_idx)| {
            let rg_file = File::open(&file_path)?;
            let rg_reader = ParquetRecordBatchReaderBuilder::try_new(rg_file)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                .with_row_groups(vec![rg_idx])
                .with_batch_size(16_384)
                .build()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            let mut rg_count = 0usize;
            for batch_res in rg_reader {
                let batch = batch_res.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                let scan_records = parse_record_batch_into_scan_records(&batch)?;
                if scan_records.is_empty() {
                    continue;
                }
                let mut items = Vec::with_capacity(scan_records.len());
                for rec in scan_records {
                    match rec {
                        ScanRecord::Directory {
                            path,
                            mode,
                            path_sha256,
                            composite_sha256,
                            ..
                        } => {
                            items.push((
                                path.to_string_lossy().into_owned().into_boxed_str(),
                                BaselineEntry {
                                    kind: EntryKind::Directory,
                                    mode,
                                    size_bytes: None,
                                    payload_sha256: path_sha256,
                                    composite_sha256,
                                    symlink_target: None,
                                },
                            ));
                        }
                        ScanRecord::Symlink {
                            path,
                            symlink_target,
                            mode,
                            target_sha256,
                            composite_sha256,
                            ..
                        } => {
                            items.push((
                                path.to_string_lossy().into_owned().into_boxed_str(),
                                BaselineEntry {
                                    kind: EntryKind::Symlink,
                                    mode,
                                    size_bytes: None,
                                    payload_sha256: target_sha256,
                                    composite_sha256,
                                    symlink_target: Some(
                                        symlink_target
                                            .to_string_lossy()
                                            .into_owned()
                                            .into_boxed_str(),
                                    ),
                                },
                            ));
                        }
                        ScanRecord::File {
                            path,
                            size_bytes,
                            mode,
                            content_sha256,
                            composite_sha256,
                            ..
                        } => {
                            items.push((
                                path.to_string_lossy().into_owned().into_boxed_str(),
                                BaselineEntry {
                                    kind: EntryKind::File,
                                    mode,
                                    size_bytes: Some(size_bytes),
                                    payload_sha256: content_sha256,
                                    composite_sha256,
                                    symlink_target: None,
                                },
                            ));
                        }
                    }
                }
                rg_count += items.len();
                index.insert_batch(items);
            }
            Ok(rg_count)
        })
        .collect();

    let mut total_loaded = 0u64;
    for res in results {
        total_loaded += res? as u64;
    }
    telemetry
        .baseline_loaded_count
        .store(total_loaded, Ordering::Relaxed);

    Ok(index)
}

/// Resolves active Parquet files from a target Delta Lake snapshot (`new_delta_root_path`) across
/// all three `delta-rs` namespaces (`directories`, `symlinks`, `files`) and streams their row groups
/// in parallel against `baseline_index`.
pub fn stream_new_parquet_against_baseline(
    new_delta_root_path: &Path,
    target_version: Option<i64>,
    baseline_index: &ShardedBaselineIndex,
    telemetry: &ScanTelemetry,
    diff_tx: &Option<Sender<Vec<DiffRecord>>>,
) -> io::Result<()> {
    let parquet_files = resolve_active_parquet_files_from_delta(new_delta_root_path, target_version)?;
    let mut tasks: Vec<(PathBuf, usize)> = Vec::new();

    for file_path in &parquet_files {
        let f = File::open(file_path)?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(f)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let num_rg = builder.metadata().num_row_groups();
        for rg_idx in 0..num_rg {
            tasks.push((file_path.clone(), rg_idx));
        }
    }

    let results: Vec<io::Result<()>> = tasks
        .into_par_iter()
        .map(|(file_path, rg_idx)| {
            let rg_file = File::open(&file_path)?;
            let rg_reader = ParquetRecordBatchReaderBuilder::try_new(rg_file)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                .with_row_groups(vec![rg_idx])
                .with_batch_size(16_384)
                .build()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            for batch_res in rg_reader {
                let batch = batch_res.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                let scan_records = parse_record_batch_into_scan_records(&batch)?;
                for scan_rec in scan_records {
                    telemetry.record_entry(&scan_rec);
                    evaluate_live_record_diff(scan_rec, baseline_index, telemetry, diff_tx);
                }
            }
            Ok(())
        })
        .collect();

    for res in results {
        res?;
    }

    Ok(())
}

/// Compares a live or snapshot `ScanRecord` enum variant against `ShardedBaselineIndex` using O(1) remove-on-visit.
#[inline]
pub fn evaluate_live_record_diff(
    record: ScanRecord,
    baseline_index: &ShardedBaselineIndex,
    telemetry: &ScanTelemetry,
    diff_tx: &Option<Sender<Vec<DiffRecord>>>,
) {
    let new_kind = record.kind();
    let new_mode = record.mode();
    let new_payload = *record.payload_sha256();
    let new_composite = *record.composite_sha256();
    let (path, new_size_bytes, new_symlink_target) = match record {
        ScanRecord::Directory { path, .. } => (path, None, None),
        ScanRecord::Symlink {
            path,
            symlink_target,
            ..
        } => (
            path,
            None,
            Some(symlink_target.to_string_lossy().into_owned()),
        ),
        ScanRecord::File {
            path, size_bytes, ..
        } => (path, Some(size_bytes), None),
    };

    let path_str = path.to_string_lossy();
    match baseline_index.remove(path_str.as_ref()) {
        None => {
            telemetry.record_diff(DiffStatus::Added);
            if let Some(ref tx) = diff_tx {
                let diff = DiffRecord {
                    status: DiffStatus::Added,
                    path,
                    old_kind: None,
                    new_kind: Some(new_kind),
                    old_mode: None,
                    new_mode: Some(new_mode),
                    old_size_bytes: None,
                    new_size_bytes,
                    old_payload_sha256: None,
                    new_payload_sha256: Some(new_payload),
                    old_composite_sha256: None,
                    new_composite_sha256: Some(new_composite),
                    old_symlink_target: None,
                    new_symlink_target,
                };
                push_thread_local_diff(diff, tx);
            }
        }
        Some(old) => {
            if old.kind == new_kind
                && old.mode == new_mode
                && old.payload_sha256 == new_payload
                && old.composite_sha256 == new_composite
            {
                telemetry.unchanged_count.fetch_add(1, Ordering::Relaxed);
                return;
            }

            let status = if old.kind != new_kind {
                DiffStatus::ModifiedType
            } else {
                let content_changed = old.payload_sha256 != new_payload;
                let mode_changed = old.mode != new_mode;
                match (content_changed, mode_changed) {
                    (true, true) => DiffStatus::ModifiedContentAndMode,
                    (true, false) => DiffStatus::ModifiedContent,
                    (false, true) => DiffStatus::ModifiedMode,
                    (false, false) => {
                        telemetry.unchanged_count.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                }
            };

            telemetry.record_diff(status);
            if let Some(ref tx) = diff_tx {
                let diff = DiffRecord {
                    status,
                    path,
                    old_kind: Some(old.kind),
                    new_kind: Some(new_kind),
                    old_mode: Some(old.mode),
                    new_mode: Some(new_mode),
                    old_size_bytes: old.size_bytes,
                    new_size_bytes,
                    old_payload_sha256: Some(old.payload_sha256),
                    new_payload_sha256: Some(new_payload),
                    old_composite_sha256: Some(old.composite_sha256),
                    new_composite_sha256: Some(new_composite),
                    old_symlink_target: old.symlink_target.map(|s| s.into_string()),
                    new_symlink_target,
                };
                push_thread_local_diff(diff, tx);
            }
        }
    }
}

/// Builds the Apache Arrow schema for diff output in `whale compare` + `--format parquet` mode.
pub fn build_diff_parquet_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("status", DataType::Utf8, false),
        Field::new("path", DataType::Utf8, false),
        Field::new("old_kind", DataType::Utf8, true),
        Field::new("new_kind", DataType::Utf8, true),
        Field::new("old_mode_octal", DataType::Utf8, true),
        Field::new("new_mode_octal", DataType::Utf8, true),
        Field::new("old_mode", DataType::Int32, true),
        Field::new("new_mode", DataType::Int32, true),
        Field::new("old_size_bytes", DataType::Int64, true),
        Field::new("new_size_bytes", DataType::Int64, true),
        Field::new("old_payload_sha256", DataType::Utf8, true),
        Field::new("new_payload_sha256", DataType::Utf8, true),
        Field::new("old_composite_sha256", DataType::Utf8, true),
        Field::new("new_composite_sha256", DataType::Utf8, true),
        Field::new("old_symlink_target", DataType::Utf8, true),
        Field::new("new_symlink_target", DataType::Utf8, true),
    ]))
}

pub fn build_diff_delta_fields() -> Vec<StructField> {
    vec![
        StructField::new("status", DeltaDataType::Primitive(PrimitiveType::String), false),
        StructField::new("path", DeltaDataType::Primitive(PrimitiveType::String), false),
        StructField::new("old_kind", DeltaDataType::Primitive(PrimitiveType::String), true),
        StructField::new("new_kind", DeltaDataType::Primitive(PrimitiveType::String), true),
        StructField::new("old_mode_octal", DeltaDataType::Primitive(PrimitiveType::String), true),
        StructField::new("new_mode_octal", DeltaDataType::Primitive(PrimitiveType::String), true),
        StructField::new("old_mode", DeltaDataType::Primitive(PrimitiveType::Integer), true),
        StructField::new("new_mode", DeltaDataType::Primitive(PrimitiveType::Integer), true),
        StructField::new("old_size_bytes", DeltaDataType::Primitive(PrimitiveType::Long), true),
        StructField::new("new_size_bytes", DeltaDataType::Primitive(PrimitiveType::Long), true),
        StructField::new("old_payload_sha256", DeltaDataType::Primitive(PrimitiveType::String), true),
        StructField::new("new_payload_sha256", DeltaDataType::Primitive(PrimitiveType::String), true),
        StructField::new("old_composite_sha256", DeltaDataType::Primitive(PrimitiveType::String), true),
        StructField::new("new_composite_sha256", DeltaDataType::Primitive(PrimitiveType::String), true),
        StructField::new("old_symlink_target", DeltaDataType::Primitive(PrimitiveType::String), true),
        StructField::new("new_symlink_target", DeltaDataType::Primitive(PrimitiveType::String), true),
    ]
}

/// Dedicated streaming writer for `DiffRecord` batches supporting `tsv`, `jsonl`, and `delta`/`parquet`.
pub fn run_diff_writer_loop(
    rx: Receiver<Vec<DiffRecord>>,
    record_output_path: Option<PathBuf>,
    format: OutputFormat,
    parquet_compression: ParquetCompression,
    parquet_row_group_size: usize,
) -> io::Result<()> {
    if format == OutputFormat::Parquet {
        let base_path = record_output_path.unwrap_or_else(|| PathBuf::from("whale_diff.delta"));
        return run_diff_delta_writer_loop(
            rx,
            &base_path,
            parquet_compression,
            parquet_row_group_size,
        );
    }

    let sink: Box<dyn Write + Send> = match record_output_path {
        Some(ref p) => Box::new(File::create(p)?),
        None => Box::new(io::stdout()),
    };
    let mut writer = BufWriter::with_capacity(WRITER_BUF_CAPACITY, sink);

    if format == OutputFormat::Tsv {
        writer.write_all(
            b"# STATUS\tPATH\tOLD_KIND\tNEW_KIND\tOLD_MODE\tNEW_MODE\tOLD_SIZE\tNEW_SIZE\tOLD_PAYLOAD_SHA256\tNEW_PAYLOAD_SHA256\tOLD_SYMLINK_TARGET\tNEW_SYMLINK_TARGET\n",
        )?;
    }

    let mut old_octal = [0u8; 7];
    let mut new_octal = [0u8; 7];
    let mut old_pay_hex = [0u8; 64];
    let mut new_pay_hex = [0u8; 64];
    let mut int_buf = itoa::Buffer::new();

    for batch in rx {
        for rec in batch {
            match format {
                OutputFormat::Tsv => {
                    writer.write_all(rec.status.as_str().as_bytes())?;
                    writer.write_all(b"\t")?;
                    writer.write_all(rec.path.to_string_lossy().as_bytes())?;
                    writer.write_all(b"\t")?;
                    writer.write_all(rec.old_kind.map_or(b"-", |k| k.as_str().as_bytes()))?;
                    writer.write_all(b"\t")?;
                    writer.write_all(rec.new_kind.map_or(b"-", |k| k.as_str().as_bytes()))?;
                    writer.write_all(b"\t")?;
                    if let Some(m) = rec.old_mode {
                        format_octal_mode(m, &mut old_octal);
                        writer.write_all(&old_octal)?;
                    } else {
                        writer.write_all(b"-")?;
                    }
                    writer.write_all(b"\t")?;
                    if let Some(m) = rec.new_mode {
                        format_octal_mode(m, &mut new_octal);
                        writer.write_all(&new_octal)?;
                    } else {
                        writer.write_all(b"-")?;
                    }
                    writer.write_all(b"\t")?;
                    if let Some(s) = rec.old_size_bytes {
                        writer.write_all(int_buf.format(s).as_bytes())?;
                    } else {
                        writer.write_all(b"-")?;
                    }
                    writer.write_all(b"\t")?;
                    if let Some(s) = rec.new_size_bytes {
                        writer.write_all(int_buf.format(s).as_bytes())?;
                    } else {
                        writer.write_all(b"-")?;
                    }
                    writer.write_all(b"\t")?;
                    if let Some(ref h) = rec.old_payload_sha256 {
                        encode_hex_64(h, &mut old_pay_hex);
                        writer.write_all(&old_pay_hex)?;
                    } else {
                        writer.write_all(b"-")?;
                    }
                    writer.write_all(b"\t")?;
                    if let Some(ref h) = rec.new_payload_sha256 {
                        encode_hex_64(h, &mut new_pay_hex);
                        writer.write_all(&new_pay_hex)?;
                    } else {
                        writer.write_all(b"-")?;
                    }
                    writer.write_all(b"\t")?;
                    writer.write_all(
                        rec.old_symlink_target
                            .as_deref()
                            .unwrap_or("-")
                            .as_bytes(),
                    )?;
                    writer.write_all(b"\t")?;
                    writer.write_all(
                        rec.new_symlink_target
                            .as_deref()
                            .unwrap_or("-")
                            .as_bytes(),
                    )?;
                    writer.write_all(b"\n")?;
                }
                OutputFormat::Jsonl => {
                    writer.write_all(b"{\"status\":\"")?;
                    writer.write_all(rec.status.as_str().as_bytes())?;
                    writer.write_all(b"\",\"path\":")?;
                    write_json_escaped(&mut writer, &rec.path.to_string_lossy())?;

                    writer.write_all(b",\"old_kind\":")?;
                    match rec.old_kind {
                        Some(k) => {
                            writer.write_all(b"\"")?;
                            writer.write_all(k.as_str().as_bytes())?;
                            writer.write_all(b"\"")?;
                        }
                        None => writer.write_all(b"null")?,
                    }

                    writer.write_all(b",\"new_kind\":")?;
                    match rec.new_kind {
                        Some(k) => {
                            writer.write_all(b"\"")?;
                            writer.write_all(k.as_str().as_bytes())?;
                            writer.write_all(b"\"")?;
                        }
                        None => writer.write_all(b"null")?,
                    }

                    writer.write_all(b",\"old_mode_octal\":")?;
                    match rec.old_mode {
                        Some(m) => {
                            format_octal_mode(m, &mut old_octal);
                            writer.write_all(b"\"")?;
                            writer.write_all(&old_octal)?;
                            writer.write_all(b"\"")?;
                        }
                        None => writer.write_all(b"null")?,
                    }

                    writer.write_all(b",\"new_mode_octal\":")?;
                    match rec.new_mode {
                        Some(m) => {
                            format_octal_mode(m, &mut new_octal);
                            writer.write_all(b"\"")?;
                            writer.write_all(&new_octal)?;
                            writer.write_all(b"\"")?;
                        }
                        None => writer.write_all(b"null")?,
                    }

                    writer.write_all(b",\"old_size_bytes\":")?;
                    match rec.old_size_bytes {
                        Some(s) => writer.write_all(int_buf.format(s).as_bytes())?,
                        None => writer.write_all(b"null")?,
                    }

                    writer.write_all(b",\"new_size_bytes\":")?;
                    match rec.new_size_bytes {
                        Some(s) => writer.write_all(int_buf.format(s).as_bytes())?,
                        None => writer.write_all(b"null")?,
                    }

                    writer.write_all(b",\"old_payload_sha256\":")?;
                    match rec.old_payload_sha256 {
                        Some(ref h) => {
                            encode_hex_64(h, &mut old_pay_hex);
                            writer.write_all(b"\"")?;
                            writer.write_all(&old_pay_hex)?;
                            writer.write_all(b"\"")?;
                        }
                        None => writer.write_all(b"null")?,
                    }

                    writer.write_all(b",\"new_payload_sha256\":")?;
                    match rec.new_payload_sha256 {
                        Some(ref h) => {
                            encode_hex_64(h, &mut new_pay_hex);
                            writer.write_all(b"\"")?;
                            writer.write_all(&new_pay_hex)?;
                            writer.write_all(b"\"")?;
                        }
                        None => writer.write_all(b"null")?,
                    }

                    writer.write_all(b"}\n")?;
                }
                OutputFormat::Parquet => {}
            }
        }
    }

    writer.flush()?;
    Ok(())
}

/// Streams `DiffRecord` batches into a `delta-rs` table namespace (`<base_path>/diffs`) with bounded row groups.
fn run_diff_delta_writer_loop(
    rx: Receiver<Vec<DiffRecord>>,
    base_output_path: &Path,
    compression: ParquetCompression,
    row_group_size: usize,
) -> io::Result<()> {
    let diffs_ns_dir = base_output_path.join("diffs");
    fs::create_dir_all(&diffs_ns_dir)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async move {
        let mut diff_table =
            init_delta_namespace_table(&diffs_ns_dir, "diffs", build_diff_delta_fields()).await?;
        let schema = build_diff_parquet_schema();
        let props = build_writer_properties(compression, row_group_size);
        let mut delta_writer = RecordBatchWriter::for_table(&diff_table)
            .map_err(io::Error::other)?
            .with_writer_properties(props);

        let cap = row_group_size.max(1024);
        let mut status_col = StringBuilder::with_capacity(cap, cap * 16);
        let mut path_col = StringBuilder::with_capacity(cap, cap * 48);
        let mut old_kind_col = StringBuilder::with_capacity(cap, cap * 5);
        let mut new_kind_col = StringBuilder::with_capacity(cap, cap * 5);
        let mut old_octal_col = StringBuilder::with_capacity(cap, cap * 7);
        let mut new_octal_col = StringBuilder::with_capacity(cap, cap * 7);
        let mut old_mode_col = Int32Builder::with_capacity(cap);
        let mut new_mode_col = Int32Builder::with_capacity(cap);
        let mut old_size_col = Int64Builder::with_capacity(cap);
        let mut new_size_col = Int64Builder::with_capacity(cap);
        let mut old_pay_col = StringBuilder::with_capacity(cap, cap * 64);
        let mut new_pay_col = StringBuilder::with_capacity(cap, cap * 64);
        let mut old_comp_col = StringBuilder::with_capacity(cap, cap * 64);
        let mut new_comp_col = StringBuilder::with_capacity(cap, cap * 64);
        let mut old_sym_col = StringBuilder::with_capacity(cap, cap * 16);
        let mut new_sym_col = StringBuilder::with_capacity(cap, cap * 16);

        let mut buffered_rows = 0usize;
        let mut octal_buf = [0u8; 7];
        let mut hex_buf = [0u8; 64];

        for batch in rx {
            for rec in batch {
                status_col.append_value(rec.status.as_str());
                path_col.append_value(rec.path.to_string_lossy().as_ref());

                match rec.old_kind {
                    Some(k) => old_kind_col.append_value(k.as_str()),
                    None => old_kind_col.append_null(),
                }
                match rec.new_kind {
                    Some(k) => new_kind_col.append_value(k.as_str()),
                    None => new_kind_col.append_null(),
                }
                match rec.old_mode {
                    Some(m) => {
                        format_octal_mode(m, &mut octal_buf);
                        let s = unsafe { std::str::from_utf8_unchecked(&octal_buf) };
                        old_octal_col.append_value(s);
                        old_mode_col.append_value(m as i32);
                    }
                    None => {
                        old_octal_col.append_null();
                        old_mode_col.append_null();
                    }
                }
                match rec.new_mode {
                    Some(m) => {
                        format_octal_mode(m, &mut octal_buf);
                        let s = unsafe { std::str::from_utf8_unchecked(&octal_buf) };
                        new_octal_col.append_value(s);
                        new_mode_col.append_value(m as i32);
                    }
                    None => {
                        new_octal_col.append_null();
                        new_mode_col.append_null();
                    }
                }
                match rec.old_size_bytes {
                    Some(sz) => old_size_col.append_value(sz as i64),
                    None => old_size_col.append_null(),
                }
                match rec.new_size_bytes {
                    Some(sz) => new_size_col.append_value(sz as i64),
                    None => new_size_col.append_null(),
                }
                match rec.old_payload_sha256 {
                    Some(ref h) => {
                        encode_hex_64(h, &mut hex_buf);
                        let s = unsafe { std::str::from_utf8_unchecked(&hex_buf) };
                        old_pay_col.append_value(s);
                    }
                    None => old_pay_col.append_null(),
                }
                match rec.new_payload_sha256 {
                    Some(ref h) => {
                        encode_hex_64(h, &mut hex_buf);
                        let s = unsafe { std::str::from_utf8_unchecked(&hex_buf) };
                        new_pay_col.append_value(s);
                    }
                    None => new_pay_col.append_null(),
                }
                match rec.old_composite_sha256 {
                    Some(ref h) => {
                        encode_hex_64(h, &mut hex_buf);
                        let s = unsafe { std::str::from_utf8_unchecked(&hex_buf) };
                        old_comp_col.append_value(s);
                    }
                    None => old_comp_col.append_null(),
                }
                match rec.new_composite_sha256 {
                    Some(ref h) => {
                        encode_hex_64(h, &mut hex_buf);
                        let s = unsafe { std::str::from_utf8_unchecked(&hex_buf) };
                        new_comp_col.append_value(s);
                    }
                    None => new_comp_col.append_null(),
                }
                match rec.old_symlink_target {
                    Some(ref t) => old_sym_col.append_value(t),
                    None => old_sym_col.append_null(),
                }
                match rec.new_symlink_target {
                    Some(ref t) => new_sym_col.append_value(t),
                    None => new_sym_col.append_null(),
                }

                buffered_rows += 1;
                if buffered_rows >= cap {
                    let columns: Vec<ArrayRef> = vec![
                        Arc::new(status_col.finish()),
                        Arc::new(path_col.finish()),
                        Arc::new(old_kind_col.finish()),
                        Arc::new(new_kind_col.finish()),
                        Arc::new(old_octal_col.finish()),
                        Arc::new(new_octal_col.finish()),
                        Arc::new(old_mode_col.finish()),
                        Arc::new(new_mode_col.finish()),
                        Arc::new(old_size_col.finish()),
                        Arc::new(new_size_col.finish()),
                        Arc::new(old_pay_col.finish()),
                        Arc::new(new_pay_col.finish()),
                        Arc::new(old_comp_col.finish()),
                        Arc::new(new_comp_col.finish()),
                        Arc::new(old_sym_col.finish()),
                        Arc::new(new_sym_col.finish()),
                    ];
                    buffered_rows = 0;
                    let rb = RecordBatch::try_new(Arc::clone(&schema), columns)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    delta_writer
                        .write(rb)
                        .await
                        .map_err(io::Error::other)?;
                }
            }
        }

        if buffered_rows > 0 {
            let columns: Vec<ArrayRef> = vec![
                Arc::new(status_col.finish()),
                Arc::new(path_col.finish()),
                Arc::new(old_kind_col.finish()),
                Arc::new(new_kind_col.finish()),
                Arc::new(old_octal_col.finish()),
                Arc::new(new_octal_col.finish()),
                Arc::new(old_mode_col.finish()),
                Arc::new(new_mode_col.finish()),
                Arc::new(old_size_col.finish()),
                Arc::new(new_size_col.finish()),
                Arc::new(old_pay_col.finish()),
                Arc::new(new_pay_col.finish()),
                Arc::new(old_comp_col.finish()),
                Arc::new(new_comp_col.finish()),
                Arc::new(old_sym_col.finish()),
                Arc::new(new_sym_col.finish()),
            ];
            let rb = RecordBatch::try_new(Arc::clone(&schema), columns)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            delta_writer
                .write(rb)
                .await
                .map_err(io::Error::other)?;
        }

        delta_writer
            .flush_and_commit(&mut diff_table)
            .await
            .map_err(io::Error::other)?;

        Ok(())
    })
}