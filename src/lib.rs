//! `lib.rs` — Library root orchestrating the `whale` parallel SHA-256 directory scanner and Delta Lake diff engine.

pub mod config;
pub mod diff;
pub mod hasher;
pub mod model;
pub mod parquet_writer;
pub mod scanner;
pub mod telemetry;
pub mod writer;

use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use crossbeam_channel::bounded;

use crate::config::{CliConfig, OutputFormat, CHANNEL_CAPACITY};
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

/// Resolves the target output path for per-record formats (`tsv`, `jsonl`, `parquet` / `delta`).
/// When `--summary-only` is set, returns `None` (since `-o` is used for the summary report).
/// When `--format parquet` is chosen without `--output`, defaults to `"whale_diff.delta"`
/// in comparison modes or `"whale_output.delta"` in scan mode.
#[inline]
pub fn resolve_record_output_path(config: &CliConfig) -> Option<PathBuf> {
    if config.summary_only {
        None
    } else if let Some(ref path) = config.output {
        Some(path.clone())
    } else if config.format == OutputFormat::Parquet {
        if config.is_diff_mode() {
            Some(PathBuf::from("whale_diff.delta"))
        } else {
            Some(PathBuf::from("whale_output.delta"))
        }
    } else {
        None
    }
}

/// Runs a full parallel scan (`whale scan`), live-vs-Delta comparison (`whale compare`),
/// or direct Delta-snapshot-vs-Delta-snapshot comparison (`whale compare-snapshots`) and returns `ScanTelemetry`.
pub fn execute_scan(config: CliConfig) -> io::Result<ScanTelemetry> {
    maximize_file_descriptor_limit();

    if config.threads > 0 {
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(config.threads)
            .build_global();
    }

    let is_diff_mode = config.is_diff_mode();
    let telemetry = ScanTelemetry::default();

    let baseline_delta_path = if let Some(ref snapshots) = config.compare_snapshots {
        Some(snapshots[0].clone())
    } else {
        config.compare.clone()
    };

    // Load baseline Delta Lake namespaces (`directories`, `symlinks`, `files`) in parallel across row groups
    let baseline_index = match baseline_delta_path {
        Some(ref delta_path) => Some(load_baseline_parquet(
            delta_path,
            config.baseline_version,
            &telemetry,
        )?),
        None => None,
    };

    let record_output_path = resolve_record_output_path(&config);
    let format = config.format;
    let parquet_compression = config.parquet_compression;
    let parquet_row_group_size = config.parquet_row_group_size;

    let (tx, diff_tx, writer_handle) = if config.summary_only {
        (None, None, None)
    } else if is_diff_mode {
        let (d_tx, d_rx) = bounded::<Vec<DiffRecord>>(CHANNEL_CAPACITY);
        let handle = std::thread::spawn(move || {
            run_diff_writer_loop(
                d_rx,
                record_output_path,
                format,
                parquet_compression,
                parquet_row_group_size,
            )
        });
        (None, Some(d_tx), Some(handle))
    } else {
        let (s_tx, s_rx) = bounded::<Vec<ScanRecord>>(CHANNEL_CAPACITY);
        let handle = std::thread::spawn(move || {
            run_writer_loop(
                s_rx,
                record_output_path,
                format,
                parquet_compression,
                parquet_row_group_size,
            )
        });
        (Some(s_tx), None, Some(handle))
    };

    // Branch 1: Direct Delta-snapshot-to-Delta-snapshot comparison (`whale compare-snapshots`)
    if let Some(ref snapshots) = config.compare_snapshots {
        let new_delta_path = &snapshots[1];
        let baseline = baseline_index
            .as_ref()
            .expect("baseline_index initialized for compare_snapshots");

        stream_new_parquet_against_baseline(
            new_delta_path,
            config.target_version,
            baseline,
            &telemetry,
            &diff_tx,
        )?;
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

    // Branch 2: Live filesystem scan (`whale scan` or `whale compare <BASELINE_DELTA> <DIR>`)
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
    use crate::config::{Cli, CommonOptions};
    use crate::parquet_writer::DeltaNamespacePaths;
    use clap::Parser;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_delta_rs_namespaces_and_parallel_comparison() -> io::Result<()> {
        let tmp = std::env::temp_dir().join("whale_delta_namespaces_test");
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

        let snap_v1 = tmp.join("snap_v1.delta");
        let snap_v2 = tmp.join("snap_v2.delta");

        // 1. Scan v1 into a Delta Lake repository with `directories`, `symlinks`, and `files` namespaces
        let cli_scan = Cli::parse_from([
            "whale",
            "scan",
            scan_root.to_str().unwrap(),
            "--format",
            "parquet",
            "-o",
            snap_v1.to_str().unwrap(),
            "--skip-summary",
        ]);
        execute_scan(cli_scan.into_config())?;

        let v1_ns = DeltaNamespacePaths::from_base_path(&snap_v1);
        assert!(v1_ns.directories_ns.join("_delta_log").is_dir());
        assert!(v1_ns.symlinks_ns.join("_delta_log").is_dir());
        assert!(v1_ns.files_ns.join("_delta_log").is_dir());

        // 2. Mutate filesystem and compare against the v1 Delta Lake namespaces
        fs::write(&file_modified, b"version 2 - updated content")?;
        fs::remove_dir_all(scan_root.join("dir_to_delete"))?;
        fs::write(scan_root.join("dir_keep/added.txt"), b"brand new file")?;

        let cli_compare_summary = Cli::parse_from([
            "whale",
            "compare",
            snap_v1.to_str().unwrap(),
            scan_root.to_str().unwrap(),
            "--summary",
        ]);
        let t_live_diff = execute_scan(cli_compare_summary.into_config())?;
        assert_eq!(t_live_diff.added_count.load(Ordering::Relaxed), 1);
        assert_eq!(t_live_diff.deleted_count.load(Ordering::Relaxed), 2);
        assert_eq!(t_live_diff.modified_content_count.load(Ordering::Relaxed), 1);

        // 3. Scan v2 into `snap_v2.delta` and compare `snap_v1.delta` vs `snap_v2.delta` directly
        let common_v2 = CommonOptions {
            format: OutputFormat::Parquet,
            output: Some(snap_v2.clone()),
            skip_summary: true,
            ..Default::default()
        };
        execute_scan(CliConfig::from_scan(scan_root.clone(), common_v2))?;

        let snap_diff_out = tmp.join("snap_diffs.delta");
        let cli_compare_snaps = Cli::parse_from([
            "whale",
            "compare",
            snap_v1.to_str().unwrap(),
            snap_v2.to_str().unwrap(),
            "--format",
            "parquet",
            "-o",
            snap_diff_out.to_str().unwrap(),
            "--skip-summary",
        ]);
        let t_snap_diff = execute_scan(cli_compare_snaps.into_config())?;
        assert_eq!(t_snap_diff.added_count.load(Ordering::Relaxed), 1);
        assert_eq!(t_snap_diff.deleted_count.load(Ordering::Relaxed), 2);
        assert_eq!(t_snap_diff.modified_content_count.load(Ordering::Relaxed), 1);
        assert!(snap_diff_out.join("diffs").join("_delta_log").is_dir());

        let _ = fs::remove_dir_all(&tmp);
        Ok(())
    }
}