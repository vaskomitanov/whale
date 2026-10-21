//! `lib.rs` — Library root orchestrating the modular parallel SHA-256 directory scanner.

pub mod config;
pub mod hasher;
pub mod model;
pub mod scanner;
pub mod telemetry;
pub mod writer;

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
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

    let output_path = config.output.clone();
    let format = config.format;
    let writer_handle = if let Some(rx_chan) = rx {
        let sink: Box<dyn Write + Send> = match output_path {
            Some(ref p) => Box::new(File::create(p)?),
            None => Box::new(io::stdout()),
        };
        let buf_writer = BufWriter::with_capacity(WRITER_BUF_CAPACITY, sink);
        Some(std::thread::spawn(move || {
            run_writer_loop(rx_chan, buf_writer, format)
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
    use crate::hasher::{hash_file_contents_and_mode, hash_mode, EMPTY_SHA256};
    use sha2::{Digest, Sha256};
    use std::sync::atomic::Ordering;

    #[test]
    fn test_empty_sha256_constant() {
        let computed: [u8; 32] = Sha256::digest(b"").into();
        assert_eq!(computed, EMPTY_SHA256);
    }

    #[test]
    fn test_mode_hashing_and_tree_determinism() -> io::Result<()> {
        let tmp = std::env::temp_dir().join("fast_sha256_scan_modular_test");
        let _ = fs::remove_dir_all(&tmp);
        let nested_dir = tmp.join("subdir_a/nested");
        fs::create_dir_all(&nested_dir)?;

        let empty_path = tmp.join("empty.txt");
        fs::write(&empty_path, b"")?;
        let (empty_hash, empty_len, empty_mode) =
            hash_file_contents_and_mode(&empty_path, 256 * 1024, false)?;
        assert_eq!(empty_len, 0);
        assert_eq!(empty_hash, EMPTY_SHA256);
        assert_ne!(empty_mode, 0);
        assert_eq!(
            hash_mode(empty_mode),
            <[u8; 32]>::from(Sha256::digest(empty_mode.to_le_bytes()))
        );

        let payload = vec![0x5Au8; 600 * 1024];
        let large_path = nested_dir.join("large.bin");
        fs::write(&large_path, &payload)?;

        let expected: [u8; 32] = Sha256::digest(&payload).into();
        let (mmap_hash, mmap_len, _) = hash_file_contents_and_mode(&large_path, 256 * 1024, false)?;
        let (stream_hash, stream_len, _) =
            hash_file_contents_and_mode(&large_path, 16 * 1024 * 1024, false)?;
        assert_eq!(mmap_len, payload.len() as u64);
        assert_eq!(stream_len, payload.len() as u64);
        assert_eq!(mmap_hash, expected);
        assert_eq!(stream_hash, expected);

        let cfg = CliConfig {
            root: tmp.clone(),
            format: OutputFormat::Summary,
            output: None,
            threads: 4,
            mmap_threshold: 256 * 1024,
            include_relative_path: true,
            include_mode: true,
            permission_bits_only: false,
        };
        let t1 = execute_scan(cfg.clone())?;
        let t2 = execute_scan(cfg)?;

        assert_eq!(
            ScanTelemetry::finalize_accumulator(&t1.multiset_hash, b"ROOT_ALL_V2:"),
            ScanTelemetry::finalize_accumulator(&t2.multiset_hash, b"ROOT_ALL_V2:")
        );
        assert_eq!(
            ScanTelemetry::finalize_accumulator(&t1.file_mode_multiset, b"FILE_MODES_V1:"),
            ScanTelemetry::finalize_accumulator(&t2.file_mode_multiset, b"FILE_MODES_V1:")
        );
        assert_eq!(
            ScanTelemetry::finalize_accumulator(&t1.dir_mode_multiset, b"DIR_MODES_V1:"),
            ScanTelemetry::finalize_accumulator(&t2.dir_mode_multiset, b"DIR_MODES_V1:")
        );
        assert_eq!(t1.files_count.load(Ordering::Relaxed), 2);
        assert_eq!(t1.dirs_count.load(Ordering::Relaxed), 3);

        // Verify that changing file mode alters `file_mode_multiset` and `multiset_hash` on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&empty_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&empty_path, perms)?;

            let cfg_after = CliConfig {
                root: tmp.clone(),
                format: OutputFormat::Summary,
                output: None,
                threads: 4,
                mmap_threshold: 256 * 1024,
                include_relative_path: true,
                include_mode: true,
                permission_bits_only: false,
            };
            let t3 = execute_scan(cfg_after)?;
            assert_ne!(
                ScanTelemetry::finalize_accumulator(&t1.file_mode_multiset, b"FILE_MODES_V1:"),
                ScanTelemetry::finalize_accumulator(&t3.file_mode_multiset, b"FILE_MODES_V1:")
            );
            assert_ne!(
                ScanTelemetry::finalize_accumulator(&t1.multiset_hash, b"ROOT_ALL_V2:"),
                ScanTelemetry::finalize_accumulator(&t3.multiset_hash, b"ROOT_ALL_V2:")
            );
        }

        let _ = fs::remove_dir_all(&tmp);
        Ok(())
    }
}