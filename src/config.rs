//! `config.rs` — CLI configuration and runtime tuning parameters for `whale`.

use std::path::PathBuf;
use clap::{Parser, ValueEnum};

/// Size of the thread-local reusable read buffer (256 KiB).
pub const THREAD_BUF_SIZE: usize = 256 * 1024;

/// Number of records accumulated per worker before sending to the writer channel.
pub const RECORD_BATCH_SIZE: usize = 256;

/// Capacity of the bounded channel between workers and the dedicated writer thread.
pub const CHANNEL_CAPACITY: usize = 1024;

/// Size of the dedicated writer thread's output buffer (8 MiB).
pub const WRITER_BUF_CAPACITY: usize = 8 * 1024 * 1024;

/// Number of files grouped per Rayon work-stealing task when a directory is very wide.
pub const FILE_CHUNK_SIZE: usize = 64;

/// Default number of rows per Apache Parquet row group (65,536 rows) for bounded memory streaming.
pub const DEFAULT_PARQUET_ROW_GROUP_SIZE: usize = 65_536;

/// CLI configuration for `whale`.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "whale",
    version,
    about = "Whale: ultra-scalable parallel recursive SHA-256 scanner supporting TSV, JSONL, and Apache Parquet output."
)]
pub struct CliConfig {
    /// Root directory (or file/symlink) path to scan recursively.
    #[arg(default_value = ".")]
    pub root: PathBuf,

    /// Output format: `tsv`, `jsonl`, `parquet`, or `summary`.
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Tsv)]
    pub format: OutputFormat,

    /// Write output to a file path instead of printing to the console (`stdout`).
    /// Defaults to `whale_output.parquet` when `--format parquet` is selected without `-o`.
    #[arg(short = 'o', long = "output", visible_alias = "output-file", value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Skip printing the summary report and aggregate SHA-256 digests at the end of the scan.
    #[arg(short = 'S', long = "skip-summary", visible_alias = "no-summary", default_value_t = false)]
    pub skip_summary: bool,

    /// Number of worker threads (0 = use all available logical CPU cores).
    #[arg(short = 'j', long, default_value_t = 0)]
    pub threads: usize,

    /// Minimum file size in bytes to transition from buffered `read` to `mmap` (default: 262144 = 256 KiB).
    #[arg(long, default_value_t = 256 * 1024)]
    pub mmap_threshold: u64,

    /// Include relative path in composite entry digest (makes root digest sensitive to tree structure).
    #[arg(long, default_value_t = true)]
    pub include_relative_path: bool,

    /// Include file and directory mode (`st_mode`) in the composite SHA-256 digest.
    #[arg(long, default_value_t = true)]
    pub include_mode: bool,

    /// Normalize mode to permission bits only (`mode & 0o7777`) instead of full `st_mode`.
    #[arg(long, default_value_t = false)]
    pub permission_bits_only: bool,

    /// Compression codec used when `--format parquet` is selected.
    #[arg(long, value_enum, default_value_t = ParquetCompression::Zstd)]
    pub parquet_compression: ParquetCompression,

    /// Number of records buffered per Apache Parquet row group (default: 65536).
    #[arg(long, default_value_t = DEFAULT_PARQUET_ROW_GROUP_SIZE)]
    pub parquet_row_group_size: usize,
}

/// Supported output serialization formats.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Tab-separated values: `KIND\tMODE_OCTAL\tMODE_SHA256\tNAME_SHA256\tPAYLOAD_SHA256\tCOMPOSITE_SHA256\tSIZE_BYTES\tPATH\tSYMLINK_TARGET`
    Tsv,
    /// JSON Lines (one compact JSON object per entry)
    Jsonl,
    /// Apache Parquet columnar binary format (streamed in bounded row groups)
    Parquet,
    /// Only emit final summary statistics and aggregate root SHA-256 digests
    Summary,
}

/// Supported compression codecs for Apache Parquet output.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParquetCompression {
    /// Zstandard compression (level 3) — high compression ratio and fast decompression
    Zstd,
    /// Google Snappy compression — ultra-low CPU overhead
    Snappy,
    /// Gzip / Deflate compression
    Gzip,
    /// Uncompressed columnar pages
    Uncompressed,
}
