//! `main.rs` — Binary entrypoint for `fast-sha256-scan`.

use std::io::{self, Write};
use std::sync::atomic::Ordering;
use std::time::Instant;

use clap::Parser;

use whale::config::{CliConfig, OutputFormat};
use whale::execute_scan;
use whale::telemetry::ScanTelemetry;
use whale::writer::format_hex_string;

fn main() -> io::Result<()> {
    let config = CliConfig::parse();
    let is_summary_only = config.format == OutputFormat::Summary;
    let start_time = Instant::now();

    let telemetry = execute_scan(config)?;

    let elapsed = start_time.elapsed();
    let secs = elapsed.as_secs_f64().max(1e-9);

    let files = telemetry.files_count.load(Ordering::Relaxed);
    let dirs = telemetry.dirs_count.load(Ordering::Relaxed);
    let symlinks = telemetry.symlinks_count.load(Ordering::Relaxed);
    let errors = telemetry.errors_count.load(Ordering::Relaxed);
    let total_entries = files + dirs + symlinks;
    let total_bytes = telemetry.total_file_bytes.load(Ordering::Relaxed);

    let root_all_sha256 = format_hex_string(&ScanTelemetry::finalize_accumulator(
        &telemetry.multiset_hash,
        b"ROOT_ALL_V2:",
    ));
    let root_file_contents_sha256 = format_hex_string(&ScanTelemetry::finalize_accumulator(
        &telemetry.file_content_multiset,
        b"FILE_CONTENTS_V1:",
    ));
    let root_file_names_sha256 = format_hex_string(&ScanTelemetry::finalize_accumulator(
        &telemetry.file_name_multiset,
        b"FILE_NAMES_V1:",
    ));
    let root_file_modes_sha256 = format_hex_string(&ScanTelemetry::finalize_accumulator(
        &telemetry.file_mode_multiset,
        b"FILE_MODES_V1:",
    ));
    let root_dir_names_sha256 = format_hex_string(&ScanTelemetry::finalize_accumulator(
        &telemetry.dir_name_multiset,
        b"DIR_NAMES_V1:",
    ));
    let root_dir_modes_sha256 = format_hex_string(&ScanTelemetry::finalize_accumulator(
        &telemetry.dir_mode_multiset,
        b"DIR_MODES_V1:",
    ));
    let root_symlinks_sha256 = format_hex_string(&ScanTelemetry::finalize_accumulator(
        &telemetry.symlink_multiset,
        b"SYMLINKS_V1:",
    ));

    let mut summary_out: Box<dyn Write> = if is_summary_only {
        Box::new(io::stdout())
    } else {
        Box::new(io::stderr())
    };

    writeln!(summary_out, "=== Summary ===")?;
    writeln!(
        summary_out,
        "Entries Scanned        : {} total ({} files, {} dirs, {} symlinks, {} errors)",
        total_entries, files, dirs, symlinks, errors
    )?;
    writeln!(
        summary_out,
        "Total File Bytes       : {} bytes ({:.2} GiB)",
        total_bytes,
        (total_bytes as f64) / (1024.0 * 1024.0 * 1024.0)
    )?;
    writeln!(
        summary_out,
        "Elapsed Time           : {:.4} s ({:.0} entries/sec, {:.2} MiB/sec)",
        secs,
        (total_entries as f64) / secs,
        (total_bytes as f64) / (1024.0 * 1024.0) / secs
    )?;
    writeln!(
        summary_out,
        "File Contents SHA-256  : {}",
        root_file_contents_sha256
    )?;
    writeln!(
        summary_out,
        "File Names SHA-256     : {}",
        root_file_names_sha256
    )?;
    writeln!(
        summary_out,
        "File Modes SHA-256     : {}",
        root_file_modes_sha256
    )?;
    writeln!(
        summary_out,
        "Directory Names SHA-256: {}",
        root_dir_names_sha256
    )?;
    writeln!(
        summary_out,
        "Directory Modes SHA-256: {}",
        root_dir_modes_sha256
    )?;
    writeln!(
        summary_out,
        "Symlinks SHA-256       : {}",
        root_symlinks_sha256
    )?;
    writeln!(
        summary_out,
        "Aggregate Tree SHA-256 : {}",
        root_all_sha256
    )?;

    Ok(())
}