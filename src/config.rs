//! `config.rs` — Clap subcommands (`scan`, `compare`, `compare-snapshots`) and runtime tuning parameters for `whale`.

use std::path::{Path, PathBuf};
use clap::{Args, Parser, Subcommand, ValueEnum};

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

/// Default number of rows per Apache Parquet / Delta row group (65,536 rows) for bounded memory streaming.
pub const DEFAULT_PARQUET_ROW_GROUP_SIZE: usize = 65_536;

/// Number of independent hash-table shards in `ShardedBaselineIndex` (power of two: 256).
pub const BASELINE_SHARD_COUNT: usize = 256;

/// Top-level CLI parser for `whale` with `scan` and `compare` subcommands.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "whale",
    version,
    about = "Whale: ultra-scalable parallel recursive SHA-256 scanner and Delta Lake / Parquet snapshot diff engine.",
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: WhaleCommand,
}

/// Top-level subcommands supported by `whale`.
#[derive(Subcommand, Debug, Clone)]
pub enum WhaleCommand {
    /// Recursively scan a directory tree and compute SHA-256 digests of all file contents,
    /// file names, directory names, file/directory modes, and symlinks.
    Scan(ScanArgs),

    /// Compare a previously indexed Delta Lake / Parquet snapshot against a live directory tree
    /// (or against a second Delta Lake snapshot) and output only the differences.
    #[command(visible_alias = "diff")]
    Compare(CompareArgs),

    /// Directly compare two existing Delta Lake / Parquet snapshots (`<OLD_SNAPSHOT> <NEW_SNAPSHOT>`)
    /// in parallel across row groups without scanning the live filesystem.
    #[command(visible_alias = "diff-snapshots")]
    CompareSnapshots(CompareSnapshotsArgs),
}

/// Arguments for `whale scan [ROOT] [OPTIONS]`.
#[derive(Args, Debug, Clone)]
pub struct ScanArgs {
    /// Root directory (or file/symlink) path to scan recursively.
    #[arg(default_value = ".", value_name = "ROOT")]
    pub root: PathBuf,

    #[command(flatten)]
    pub common: CommonOptions,
}

/// Arguments for `whale compare <BASELINE_DELTA_PATH> [TARGET] [OPTIONS]`.
#[derive(Args, Debug, Clone)]
pub struct CompareArgs {
    /// Path to the previously indexed baseline Delta Lake root directory (containing
    /// `directories`, `symlinks`, and `files` namespaces).
    #[arg(value_name = "BASELINE_DELTA_PATH")]
    pub baseline: PathBuf,

    /// Target directory path to scan and compare against `BASELINE_DELTA_PATH`, or path to a second
    /// Delta Lake snapshot directory for direct snapshot-to-snapshot comparison.
    #[arg(default_value = ".", value_name = "TARGET")]
    pub target: PathBuf,

    /// Force treating `TARGET` as a second Delta Lake snapshot rather than a live filesystem directory.
    #[arg(long, default_value_t = false)]
    pub snapshots: bool,

    /// Optional Delta Lake table version to time-travel to when loading `BASELINE_DELTA_PATH`.
    #[arg(long, value_name = "VERSION")]
    pub baseline_version: Option<i64>,

    /// Optional Delta Lake table version to time-travel to when comparing against a snapshot `TARGET`.
    #[arg(long, value_name = "VERSION")]
    pub target_version: Option<i64>,

    #[command(flatten)]
    pub common: CommonOptions,
}

/// Arguments for `whale compare-snapshots <OLD_SNAPSHOT> <NEW_SNAPSHOT> [OPTIONS]`.
#[derive(Args, Debug, Clone)]
pub struct CompareSnapshotsArgs {
    /// Path to the older/baseline Delta Lake snapshot root directory.
    #[arg(value_name = "OLD_SNAPSHOT")]
    pub old_parquet: PathBuf,

    /// Path to the newer Delta Lake snapshot root directory.
    #[arg(value_name = "NEW_SNAPSHOT")]
    pub new_parquet: PathBuf,

    /// Optional Delta table version for `OLD_SNAPSHOT`.
    #[arg(long, value_name = "VERSION")]
    pub baseline_version: Option<i64>,

    /// Optional Delta table version for `NEW_SNAPSHOT`.
    #[arg(long, value_name = "VERSION")]
    pub target_version: Option<i64>,

    #[command(flatten)]
    pub common: CommonOptions,
}

/// Shared execution, hashing, and output flags across `scan` and `compare` subcommands.
#[derive(Args, Debug, Clone)]
pub struct CommonOptions {
    /// Output format for per-entry scan or diff records: `tsv`, `jsonl`, or `parquet` (Delta Lake namespaces).
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Tsv)]
    pub format: OutputFormat,

    /// Emit only the summary statistics and aggregate SHA-256 digests (suppress per-entry record output).
    #[arg(
        short = 's',
        long = "summary-only",
        visible_alias = "summary",
        default_value_t = false,
        conflicts_with = "skip_summary"
    )]
    pub summary_only: bool,

    /// Write scan, diff, or summary-only output to a file/Delta root path instead of console (`stdout`).
    /// Defaults to `whale_output.delta` (or `whale_diff.delta` in `compare` mode) when `--format parquet` is used without `-o`.
    #[arg(short = 'o', long = "output", visible_alias = "output-file", value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Skip printing the summary report and aggregate SHA-256 digests at the end of the run.
    #[arg(
        short = 'S',
        long = "skip-summary",
        visible_alias = "no-summary",
        default_value_t = false,
        conflicts_with = "summary_only"
    )]
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

    /// Compression codec used when `--format parquet` (Delta Lake) is selected.
    #[arg(long, value_enum, default_value_t = ParquetCompression::Zstd)]
    pub parquet_compression: ParquetCompression,

    /// Number of records buffered per Apache Parquet / Delta row group (default: 65536).
    #[arg(long, default_value_t = DEFAULT_PARQUET_ROW_GROUP_SIZE)]
    pub parquet_row_group_size: usize,
}

impl Default for CommonOptions {
    fn default() -> Self {
        Self {
            format: OutputFormat::Tsv,
            summary_only: false,
            output: None,
            skip_summary: false,
            threads: 0,
            mmap_threshold: 256 * 1024,
            include_relative_path: true,
            include_mode: true,
            permission_bits_only: false,
            parquet_compression: ParquetCompression::Zstd,
            parquet_row_group_size: DEFAULT_PARQUET_ROW_GROUP_SIZE,
        }
    }
}

/// Normalized execution configuration derived from `Cli` subcommands (`scan`, `compare`, `compare-snapshots`).
#[derive(Debug, Clone)]
pub struct CliConfig {
    pub root: PathBuf,
    pub compare: Option<PathBuf>,
    pub compare_snapshots: Option<Vec<PathBuf>>,
    pub baseline_version: Option<i64>,
    pub target_version: Option<i64>,
    pub format: OutputFormat,
    pub summary_only: bool,
    pub output: Option<PathBuf>,
    pub skip_summary: bool,
    pub threads: usize,
    pub mmap_threshold: u64,
    pub include_relative_path: bool,
    pub include_mode: bool,
    pub permission_bits_only: bool,
    pub parquet_compression: ParquetCompression,
    pub parquet_row_group_size: usize,
}

/// Detects whether `path` is a Delta Lake snapshot root (contains `directories/_delta_log`,
/// `files/_delta_log`, `symlinks/_delta_log`, or `_delta_log`) or a `.parquet`/`.delta` path.
pub fn is_delta_or_parquet_snapshot_path(path: &Path) -> bool {
    if path.join("directories").join("_delta_log").is_dir()
        || path.join("files").join("_delta_log").is_dir()
        || path.join("symlinks").join("_delta_log").is_dir()
        || path.join("_delta_log").is_dir()
    {
        return true;
    }
    path.extension()
        .and_then(|e| e.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("parquet") || ext.eq_ignore_ascii_case("delta"))
        .unwrap_or(false)
        && path.exists()
}

impl Cli {
    /// Converts the parsed `Cli` subcommand (`scan`, `compare`, or `compare-snapshots`) into a unified `CliConfig`.
    pub fn into_config(self) -> CliConfig {
        match self.command {
            WhaleCommand::Scan(args) => CliConfig::from_scan(args.root, args.common),
            WhaleCommand::Compare(args) => {
                if args.snapshots
                    || args.target_version.is_some()
                    || is_delta_or_parquet_snapshot_path(&args.target)
                {
                    let mut cfg =
                        CliConfig::from_compare_snapshots(args.baseline, args.target, args.common);
                    cfg.baseline_version = args.baseline_version;
                    cfg.target_version = args.target_version;
                    cfg
                } else {
                    let mut cfg =
                        CliConfig::from_compare_live(args.baseline, args.target, args.common);
                    cfg.baseline_version = args.baseline_version;
                    cfg
                }
            }
            WhaleCommand::CompareSnapshots(args) => {
                let mut cfg = CliConfig::from_compare_snapshots(
                    args.old_parquet,
                    args.new_parquet,
                    args.common,
                );
                cfg.baseline_version = args.baseline_version;
                cfg.target_version = args.target_version;
                cfg
            }
        }
    }
}

impl CliConfig {
    pub fn from_scan(root: PathBuf, common: CommonOptions) -> Self {
        Self {
            root,
            compare: None,
            compare_snapshots: None,
            baseline_version: None,
            target_version: None,
            format: common.format,
            summary_only: common.summary_only,
            output: common.output,
            skip_summary: common.skip_summary,
            threads: common.threads,
            mmap_threshold: common.mmap_threshold,
            include_relative_path: common.include_relative_path,
            include_mode: common.include_mode,
            permission_bits_only: common.permission_bits_only,
            parquet_compression: common.parquet_compression,
            parquet_row_group_size: common.parquet_row_group_size,
        }
    }

    pub fn from_compare_live(baseline: PathBuf, root: PathBuf, common: CommonOptions) -> Self {
        Self {
            root,
            compare: Some(baseline),
            compare_snapshots: None,
            baseline_version: None,
            target_version: None,
            format: common.format,
            summary_only: common.summary_only,
            output: common.output,
            skip_summary: common.skip_summary,
            threads: common.threads,
            mmap_threshold: common.mmap_threshold,
            include_relative_path: common.include_relative_path,
            include_mode: common.include_mode,
            permission_bits_only: common.permission_bits_only,
            parquet_compression: common.parquet_compression,
            parquet_row_group_size: common.parquet_row_group_size,
        }
    }

    pub fn from_compare_snapshots(
        old_parquet: PathBuf,
        new_parquet: PathBuf,
        common: CommonOptions,
    ) -> Self {
        Self {
            root: PathBuf::from("."),
            compare: None,
            compare_snapshots: Some(vec![old_parquet, new_parquet]),
            baseline_version: None,
            target_version: None,
            format: common.format,
            summary_only: common.summary_only,
            output: common.output,
            skip_summary: common.skip_summary,
            threads: common.threads,
            mmap_threshold: common.mmap_threshold,
            include_relative_path: common.include_relative_path,
            include_mode: common.include_mode,
            permission_bits_only: common.permission_bits_only,
            parquet_compression: common.parquet_compression,
            parquet_row_group_size: common.parquet_row_group_size,
        }
    }

    /// Returns `true` if running under `whale compare` or `whale compare-snapshots`.
    #[inline]
    pub fn is_diff_mode(&self) -> bool {
        self.compare.is_some() || self.compare_snapshots.is_some()
    }
}

/// Supported per-record output serialization formats (`tsv`, `jsonl`, `parquet` / `delta`).
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Tab-separated values
    Tsv,
    /// JSON Lines (one compact JSON object per entry or diff)
    Jsonl,
    /// Apache Parquet grouped into Delta Lake (`delta-rs`) namespaces (`directories`, `symlinks`, `files`)
    #[value(alias = "delta")]
    Parquet,
}

/// Supported compression codecs for Apache Parquet / Delta Lake output.
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