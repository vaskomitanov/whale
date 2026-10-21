//! `main.rs` — Binary entrypoint for `whale`.

use std::fs::File;
use std::io::{self, BufWriter, Write};
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
    let is_diff_mode = config.is_diff_mode();
    let skip_summary = config.skip_summary;
    let summary_output_file = if is_summary_only {
        config.output.clone()
    } else {
        None
    };

    let start_time = Instant::now();
    let telemetry = execute_scan(config)?;
    let elapsed = start_time.elapsed();

    if skip_summary {
        return Ok(());
    }

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

    let mut summary_out: Box<dyn Write> = match summary_output_file {
        Some(ref path) => Box::new(BufWriter::new(File::create(path)?)),
        None if is_summary_only => Box::new(io::stdout()),
        None => Box::new(io::stderr()),
    };

    writeln!(summary_out, "=== whale Summary ===")?;
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

    if is_diff_mode {
        writeln!(
            summary_out,
            "Baseline Indexed Rows  : {}",
            telemetry.baseline_loaded_count.load(Ordering::Relaxed)
        )?;
        writeln!(
            summary_out,
            "Unchanged Entries      : {}",
            telemetry.unchanged_count.load(Ordering::Relaxed)
        )?;
        writeln!(
            summary_out,
            "Total Differences      : {} (added: {}, deleted: {}, content: {}, mode: {}, content+mode: {}, type: {})",
            telemetry.total_differences(),
            telemetry.added_count.load(Ordering::Relaxed),
            telemetry.deleted_count.load(Ordering::Relaxed),
            telemetry.modified_content_count.load(Ordering::Relaxed),
            telemetry.modified_mode_count.load(Ordering::Relaxed),
            telemetry.modified_content_and_mode_count.load(Ordering::Relaxed),
            telemetry.modified_type_count.load(Ordering::Relaxed),
        )?;
    }

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
    summary_out.flush()?;

    Ok(())
}
