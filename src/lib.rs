//! `lib.rs` — Library root orchestrating the `whale` parallel SHA-256 directory scanner.

pub mod config;
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
use crate::model::ScanRecord;
use crate::scanner::{
    flush_all_thread_batches, maximize_file_descriptor_limit, process_directory, process_file,
    process_symlink, ScannerContext,
};
use crate::telemetry::ScanTelemetry;
use crate::writer::run_writer_loop;

/// Resolves the target output file path for per-record formats (`tsv`, `jsonl`, `parquet`).
/// When `--format parquet` is chosen without `--output`, defaults to `"whale_output.parquet"`
/// so binary Parquet data is written cleanly to disk rather than raw terminal stdout.
#[inline]
pub fn resolve_record_output_path(config: &CliConfig) -> Option<PathBuf> {
    if let Some(ref path) = config.output {
        Some(path.clone())
    } else if config.format == OutputFormat::Parquet {
        Some(PathBuf::from("whale_output.parquet"))
    } else {
        None
    }
}

/// Runs a full parallel scan using the supplied `CliConfig` and returns the resulting `ScanTelemetry`.
pub fn execute_scan(config: CliConfig) -> io::Result<ScanTelemetry> {
    maximize_file_descriptor_limit();

    if config.threads > 0 {
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(config.threads)
            .build_global();
    }

    let (tx, rx) = if config.format == OutputFormat::Summary {
        (None, None)
    } else {
        let (s, r) = bounded::<Vec<ScanRecord>>(CHANNEL_CAPACITY);
        (Some(s), Some(r))
    };

    let record_output_path = resolve_record_output_path(&config);
    let format = config.format;
    let parquet_compression = config.parquet_compression;
    let parquet_row_group_size = config.parquet_row_group_size;

    let writer_handle = if let Some(rx_chan) = rx {
        let sink: Box<dyn Write + Send> = match record_output_path {
            Some(ref p) => Box::new(File::create(p)?),
            None => Box::new(io::stdout()),
        };
        let buf_writer = BufWriter::with_capacity(WRITER_BUF_CAPACITY, sink);
        Some(std::thread::spawn(move || {
            run_writer_loop(
                rx_chan,
                buf_writer,
                format,
                parquet_compression,
                parquet_row_group_size,
            )
        }))
    } else {
        None
    };

    let root_path = config.root.clone();
    let root_meta = fs::symlink_metadata(&root_path)?;

    let ctx = Arc::new(ScannerContext {
        config,
        root_base: root_path.clone(),
        telemetry: ScanTelemetry::default(),
        tx,
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

    if let Some(ref sender) = ctx.tx {
        flush_all_thread_batches(sender);
    }

    let telemetry = match Arc::try_unwrap(ctx) {
        Ok(c) => {
            drop(c.tx);
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
    use crate::hasher::{hash_file_contents_and_mode, hash_mode, EMPTY_SHA256};
    use sha2::{Digest, Sha256};
    use std::sync::atomic::Ordering;

    #[test]
    fn test_empty_sha256_constant() {
        let computed: [u8; 32] = Sha256::digest(b"").into();
        assert_eq!(computed, EMPTY_SHA256);
    }

    #[test]
    fn test_parquet_and_file_output_with_skip_summary() -> io::Result<()> {
        let tmp = std::env::temp_dir().join("whale_parquet_test");
        let _ = fs::remove_dir_all(&tmp);
        let nested_dir = tmp.join("subdir_a/nested");
        fs::create_dir_all(&nested_dir)?;

        let empty_path = tmp.join("empty.txt");
        fs::write(&empty_path, b"")?;
        let (empty_hash, empty_len, empty_mode) =
            hash_file_contents_and_mode(&empty_path, 256 * 1024, false)?;
        assert_eq!(empty_len, 0);
        assert_eq!(empty_hash, EMPTY_SHA256);
        assert_eq!(
            hash_mode(empty_mode),
            <[u8; 32]>::from(Sha256::digest(empty_mode.to_le_bytes()))
        );

        let payload = vec![0x5Au8; 600 * 1024];
        let large_path = nested_dir.join("large.bin");
        fs::write(&large_path, &payload)?;

        let parquet_out = tmp.join("output.parquet");
        let cfg = CliConfig {
            root: tmp.clone(),
            format: OutputFormat::Parquet,
            output: Some(parquet_out.clone()),
            skip_summary: true,
            threads: 4,
            mmap_threshold: 256 * 1024,
            include_relative_path: true,
            include_mode: true,
            permission_bits_only: false,
            parquet_compression: ParquetCompression::Zstd,
            parquet_row_group_size: DEFAULT_PARQUET_ROW_GROUP_SIZE,
        };

        let telemetry = execute_scan(cfg)?;
        assert!(parquet_out.exists());
        assert!(fs::metadata(&parquet_out)?.len() > 0);
        assert!(telemetry.files_count.load(Ordering::Relaxed) >= 2);
        assert_eq!(telemetry.dirs_count.load(Ordering::Relaxed), 3);

        let _ = fs::remove_dir_all(&tmp);
        Ok(())
    }
}
