//! `lib.rs` — Library root orchestrating the `whale` parallel SHA-256 directory scanner and Parquet diff engine.

pub mod config;
pub mod diff;
pub mod hasher;
pub mod model;
pub mod parquet_writer;
pub mod scanner;
pub mod telemetry;
pub mod writer;

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;

use crossbeam_channel::bounded;

use crate::config::{CliConfig, OutputFormat, CHANNEL_CAPACITY, WRITER_BUF_CAPACITY};
use crate::diff::{
    flush_all_diff_batches, load_baseline_parquet, run_diff_writer_loop,
    stream_new_parquet_against_baseline,
};
use crate::model::{DiffRecord, ScanRecord};
use crate::scanner::{
    flush_all_thread_batches, maximize_file_descriptor_limit, process_directory, process_file,
    process_symlink, ScannerContext,
};
use crate::telemetry::ScanTelemetry;
use crate::writer::run_writer_loop;

/// Resolves the target output file path for per-record formats (`tsv`, `jsonl`, `parquet`).
/// When `--format parquet` is chosen without `--output`, defaults to `"whale_diff.parquet"`
/// in comparison modes or `"whale_output.parquet"` in scan mode.
#[inline]
pub fn resolve_record_output_path(config: &CliConfig) -> Option<PathBuf> {
    if let Some(ref path) = config.output {
        Some(path.clone())
    } else if config.format == OutputFormat::Parquet {
        if config.is_diff_mode() {
            Some(PathBuf::from("whale_diff.parquet"))
        } else {
            Some(PathBuf::from("whale_output.parquet"))
        }
    } else {
        None
    }
}

/// Runs a full parallel scan, live-vs-Parquet comparison (`--compare`), or direct
/// snapshot-vs-snapshot comparison (`--compare-snapshots`) and returns `ScanTelemetry`.
pub fn execute_scan(config: CliConfig) -> io::Result<ScanTelemetry> {
    maximize_file_descriptor_limit();

    if config.threads > 0 {
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(config.threads)
            .build_global();
    }

    let is_diff_mode = config.is_diff_mode();
    let telemetry = ScanTelemetry::default();

    let baseline_parquet_path = if let Some(ref snapshots) = config.compare_snapshots {
        Some(snapshots[0].clone())
    } else {
        config.compare.clone()
    };

    // Load baseline Parquet index in parallel across row groups if in `--compare` or `--compare-snapshots` mode
    let baseline_index = match baseline_parquet_path {
        Some(ref parquet_path) => Some(load_baseline_parquet(parquet_path, &telemetry)?),
        None => None,
    };

    let record_output_path = resolve_record_output_path(&config);
    let format = config.format;
    let parquet_compression = config.parquet_compression;
    let parquet_row_group_size = config.parquet_row_group_size;

    let (tx, diff_tx, writer_handle) = if format == OutputFormat::Summary {
        (None, None, None)
    } else if is_diff_mode {
        let (d_tx, d_rx) = bounded::<Vec<DiffRecord>>(CHANNEL_CAPACITY);
        let sink: Box<dyn Write + Send> = match record_output_path {
            Some(ref p) => Box::new(File::create(p)?),
            None => Box::new(io::stdout()),
        };
        let buf_writer = BufWriter::with_capacity(WRITER_BUF_CAPACITY, sink);
        let handle = std::thread::spawn(move || {
            run_diff_writer_loop(
                d_rx,
                buf_writer,
                format,
                parquet_compression,
                parquet_row_group_size,
            )
        });
        (None, Some(d_tx), Some(handle))
    } else {
        let (s_tx, s_rx) = bounded::<Vec<ScanRecord>>(CHANNEL_CAPACITY);
        let sink: Box<dyn Write + Send> = match record_output_path {
            Some(ref p) => Box::new(File::create(p)?),
            None => Box::new(io::stdout()),
        };
        let buf_writer = BufWriter::with_capacity(WRITER_BUF_CAPACITY, sink);
        let handle = std::thread::spawn(move || {
            run_writer_loop(
                s_rx,
                buf_writer,
                format,
                parquet_compression,
                parquet_row_group_size,
            )
        });
        (Some(s_tx), None, Some(handle))
    };

    // Branch 1: Direct Parquet-to-Parquet snapshot comparison (`--compare-snapshots <OLD> <NEW>`)
    if let Some(ref snapshots) = config.compare_snapshots {
        let new_parquet_path = &snapshots[1];
        let baseline = baseline_index
            .as_ref()
            .expect("baseline_index initialized for compare_snapshots");

        stream_new_parquet_against_baseline(new_parquet_path, baseline, &telemetry, &diff_tx)?;
        baseline.drain_deleted_parallel(&telemetry, &diff_tx);

        if let Some(ref d_sender) = diff_tx {
            flush_all_diff_batches(d_sender);
        }
        drop(diff_tx);

        if let Some(handle) = writer_handle {
            handle.join().expect("Writer thread panicked")?;
        }
        return Ok(telemetry);
    }

    // Branch 2: Live filesystem scan (standalone or `--compare <BASELINE.parquet>`)
    let root_path = config.root.clone();
    let root_meta = fs::symlink_metadata(&root_path)?;

    let ctx = Arc::new(ScannerContext {
        config,
        root_base: root_path.clone(),
        telemetry,
        tx,
        baseline_index,
        diff_tx,
    });

    rayon::scope_fifo(|scope| {
        let ft = root_meta.file_type();
        if ft.is_dir() {
            process_directory(&ctx, scope, root_path);
        } else if ft.is_file() {
            process_file(&ctx, root_path);
        } else if ft.is_symlink() {
            process_symlink(&ctx, root_path);
        }
    });

    if let Some(ref baseline) = ctx.baseline_index {
        baseline.drain_deleted_parallel(&ctx.telemetry, &ctx.diff_tx);
    }

    if let Some(ref sender) = ctx.tx {
        flush_all_thread_batches(sender);
    }
    if let Some(ref d_sender) = ctx.diff_tx {
        flush_all_diff_batches(d_sender);
    }

    let telemetry = match Arc::try_unwrap(ctx) {
        Ok(c) => {
            drop(c.tx);
            drop(c.diff_tx);
            c.telemetry
        }
        Err(_) => unreachable!("All Rayon tasks completed before unwrapping ScannerContext"),
    };

    if let Some(handle) = writer_handle {
        handle.join().expect("Writer thread panicked")?;
    }

    Ok(telemetry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ParquetCompression, DEFAULT_PARQUET_ROW_GROUP_SIZE};
    use std::sync::atomic::Ordering;

    #[test]
    fn test_live_and_snapshot_to_snapshot_parquet_comparison() -> io::Result<()> {
        let tmp = std::env::temp_dir().join("whale_snapshot_diff_test");
        let _ = fs::remove_dir_all(&tmp);
        let scan_root = tmp.join("workspace");
        fs::create_dir_all(scan_root.join("dir_keep"))?;
        fs::create_dir_all(scan_root.join("dir_to_delete"))?;

        let file_unchanged = scan_root.join("dir_keep/unchanged.txt");
        let file_modified = scan_root.join("dir_keep/modified.txt");
        let file_deleted = scan_root.join("dir_to_delete/old.txt");

        fs::write(&file_unchanged, b"hello world")?;
        fs::write(&file_modified, b"version 1")?;
        fs::write(&file_deleted, b"to be deleted")?;

        let snap_v1 = tmp.join("snap_v1.parquet");
        let snap_v2 = tmp.join("snap_v2.parquet");

        // 1. Index v1 into snap_v1.parquet
        let cfg_v1 = CliConfig {
            root: scan_root.clone(),
            compare: None,
            compare_snapshots: None,
            format: OutputFormat::Parquet,
            output: Some(snap_v1.clone()),
            skip_summary: true,
            threads: 4,
            mmap_threshold: 256 * 1024,
            include_relative_path: true,
            include_mode: true,
            permission_bits_only: false,
            parquet_compression: ParquetCompression::Zstd,
            parquet_row_group_size: DEFAULT_PARQUET_ROW_GROUP_SIZE,
        };
        execute_scan(cfg_v1)?;

        // 2. Mutate filesystem and index v2 into snap_v2.parquet
        fs::write(&file_modified, b"version 2 - updated content")?;
        fs::remove_dir_all(scan_root.join("dir_to_delete"))?;
        fs::write(scan_root.join("dir_keep/added.txt"), b"brand new file")?;

        let cfg_v2 = CliConfig {
            root: scan_root.clone(),
            compare: None,
            compare_snapshots: None,
            format: OutputFormat::Parquet,
            output: Some(snap_v2.clone()),
            skip_summary: true,
            threads: 4,
            mmap_threshold: 256 * 1024,
            include_relative_path: true,
            include_mode: true,
            permission_bits_only: false,
            parquet_compression: ParquetCompression::Zstd,
            parquet_row_group_size: DEFAULT_PARQUET_ROW_GROUP_SIZE,
        };
        execute_scan(cfg_v2)?;

        // 3. Compare snap_v1.parquet and snap_v2.parquet directly without touching the filesystem
        let diff_out = tmp.join("snap_diffs.parquet");
        let cfg_snap_diff = CliConfig {
            root: PathBuf::from("."),
            compare: None,
            compare_snapshots: Some(vec![snap_v1, snap_v2]),
            format: OutputFormat::Parquet,
            output: Some(diff_out.clone()),
            skip_summary: true,
            threads: 4,
            mmap_threshold: 256 * 1024,
            include_relative_path: true,
            include_mode: true,
            permission_bits_only: false,
            parquet_compression: ParquetCompression::Zstd,
            parquet_row_group_size: DEFAULT_PARQUET_ROW_GROUP_SIZE,
        };

        let t_diff = execute_scan(cfg_snap_diff)?;
        assert_eq!(t_diff.added_count.load(Ordering::Relaxed), 1);
        assert_eq!(t_diff.deleted_count.load(Ordering::Relaxed), 2);
        assert_eq!(t_diff.modified_content_count.load(Ordering::Relaxed), 1);
        assert_eq!(t_diff.unchanged_count.load(Ordering::Relaxed), 3);
        assert!(diff_out.exists());

        let _ = fs::remove_dir_all(&tmp);
        Ok(())
    }
}
