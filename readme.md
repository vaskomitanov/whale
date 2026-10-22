# Whale — Ultra-Scalable Parallel SHA-256 Scanner & Delta Lake Diff Engine

`whale` is a high-throughput, lock-free recursive filesystem scanner and cryptographic snapshot comparison engine written in Rust. It computes hardware-accelerated SHA-256 digests across file contents, file names, directory names, POSIX file/directory modes (`st_mode`), and symbolic link targets, and indexes snapshots into transactional **Delta Lake (`delta-rs`)** table namespaces (`directories`, `symlinks`, and `files`) or streams records in `tsv` and `jsonl` formats.

## Key Architectural Highlights

| Subsystem | Design & Performance Characteristics |
| :--- | :--- |
| **Work-Stealing Directory Traversal** | Uses `rayon::scope_fifo` and closes OS directory descriptors (`ReadDir`) *before* spawning child tasks, preventing file-descriptor exhaustion (`EMFILE`) on deeply nested trees while automatically raising `RLIMIT_NOFILE` on Unix. |
| **Adaptive 3-Tier File Hashing** | Short-circuits `0`-byte files with a precomputed `EMPTY_SHA256` constant; hashes small files (`< 256 KiB`) in reusable thread-local buffers (`READ_BUF`) with zero heap allocations; transitions large files (`>= 256 KiB`) to zero-copy `mmap` with `MADV_SEQUENTIAL` kernel read-ahead hints. |
| **Strongly-Typed `ScanRecord` Enum** | Models filesystem objects via three dedicated variants (`ScanRecord::Directory`, `ScanRecord::Symlink`, `ScanRecord::File`), storing strictly the fields applicable to each entry kind without nullable padding columns. |
| **`delta-rs` Multi-Namespace Storage** | Streams `Directory`, `Symlink`, and `File` records into three separate Delta Lake table namespaces (`<root>/directories`, `<root>/symlinks`, `<root>/files`) using `RecordBatchWriter` with Zstd/Snappy/Gzip compression and commits a single atomic `_delta_log` transaction per namespace via `tokio::try_join!`. |
| **Parallel Row-Group Diff Engine** | Resolves active Parquet files from `_delta_log` in `< 1 ms` via `deltalake::open_table` (with optional time-travel version pinning), loads all row groups in parallel across Rayon workers into a 256-shard `FxHashMap` (`ShardedBaselineIndex`), and performs $O(1)$ remove-on-visit diff evaluation. |
| **Order-Independent Multiset Digests** | Folds every entry's SHA-256 digest into lock-free $4 \times 64$-bit wrapping-addition accumulators (`[AtomicU64; 4]`), guaranteeing deterministic aggregate tree digests regardless of thread scheduling order. |

## Project Module Layout

| File | Responsibility |
| :--- | :--- |
| `Cargo.toml` | Package manifest configuring `clap`, `sha2` (ASM), `rayon`, `crossbeam-channel`, `memmap2`, `arrow-*`, `parquet`, `deltalake`, and `tokio`. |
| `src/main.rs` | Binary entrypoint parsing CLI subcommands, executing the scan or comparison workflow, and rendering the summary report. |
| `src/lib.rs` | Top-level library coordinator wiring together the baseline Delta Lake loader, parallel scanner, snapshot comparator, and writer threads. |
| `src/config.rs` | `clap` subcommands (`scan`, `compare`, `compare-snapshots`), separate `--summary-only` / `--skip-summary` flags, and tuning constants. |
| `src/model.rs` | Domain types: `EntryKind`, the 3-variant `ScanRecord` enum (`Directory`, `Symlink`, `File`), `BaselineEntry`, `DiffStatus`, and `DiffRecord`. |
| `src/hasher.rs` | Hardware-accelerated SHA-256 routines for file contents, `OsStr` names/paths, POSIX modes (`st_mode`), and domain-separated composite digests. |
| `src/telemetry.rs` | Lock-free atomic counters and $4 \times 64$-bit commutative multiset accumulators for order-independent root digests. |
| `src/scanner.rs` | Lock-free Rayon FIFO traversal, single-`fstat` metadata extraction, adaptive 64-file task chunking, and 256-record thread-local batching. |
| `src/writer.rs` | Dedicated 8 MiB buffered single-consumer output loop for zero-allocation `tsv` and `jsonl` serialization and `delta-rs` dispatch. |
| `src/parquet_writer.rs` | Non-nullable Arrow & Delta Kernel schemas (`Directory`, `Symlink`, `File`) and streaming `delta-rs` `RecordBatchWriter` implementation. |
| `src/diff.rs` | Concurrent `delta-rs` namespace reader, 256-shard `ShardedBaselineIndex`, parallel row-group snapshot comparator, and diff writers. |

## Building from Source

Ensure you have a recent Rust toolchain (`rustc >= 1.78`) installed, then build with release optimizations and target-native SIMD instructions (`SHA-NI` on x86_64 or `SHA2` on AArch64):

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

The compiled binary will be located at `./target/release/whale`.

## Command-Line Interface Reference

`whale` provides three primary subcommands:

1. **`whale scan [ROOT] [OPTIONS]`**: Recursively scans a directory tree (or single file/symlink) and outputs per-entry SHA-256 digests and/or an aggregate summary report.
2. **`whale compare <BASELINE_DELTA_PATH> [TARGET] [OPTIONS]`** (alias: `whale diff`): Compares a previously indexed Delta Lake snapshot against a live directory tree (or against a second Delta Lake snapshot) and outputs only the added, deleted, and modified entries.
3. **`whale compare-snapshots <OLD_SNAPSHOT> <NEW_SNAPSHOT> [OPTIONS]`** (alias: `whale diff-snapshots`): Directly compares two Delta Lake snapshots in parallel across row groups without touching the live filesystem.

### Shared Options (`scan`, `compare`, `compare-snapshots`)

| Option / Flag | Default | Description |
| :--- | :--- | :--- |
| `-f, --format <FORMAT>` | `tsv` | Record output format: `tsv`, `jsonl`, or `parquet` (alias: `delta`). |
| `-o, --output <PATH>` | `stdout` | Write output to `<PATH>` instead of `stdout` (for `parquet`/`delta`, specifies the Delta Lake root directory). |
| `-s, --summary-only` | `false` | Emit only the summary statistics and aggregate SHA-256 digests (suppresses per-entry records; conflicts with `-S`). |
| `-S, --skip-summary` | `false` | Suppress the summary report at the end of the run (conflicts with `-s`). |
| `-j, --threads <N>` | `0` (all cores) | Number of Rayon worker threads (`0` uses all logical CPU cores). |
| `--mmap-threshold <BYTES>` | `262144` | Minimum file size in bytes before switching from thread-local buffered `read` to `mmap` (`256 KiB`). |
| `--include-relative-path` | `true` | Include the entry's relative path in its `composite_sha256` digest. |
| `--include-mode` | `true` | Include the entry's POSIX `st_mode` in its `composite_sha256` digest. |
| `--permission-bits-only` | `false` | Mask `st_mode` to permission bits (`mode & 0o7777`) prior to hashing and storage. |
| `--parquet-compression <CODEC>` | `zstd` | Compression codec for Delta Lake Parquet files: `zstd`, `snappy`, `gzip`, or `uncompressed`. |
| `--parquet-row-group-size <ROWS>` | `65536` | Number of rows buffered per Parquet row group (`RecordBatch`) before flushing to disk. |

### Comparison-Specific Options (`compare`, `compare-snapshots`)

| Option / Flag | Default | Description |
| :--- | :--- | :--- |
| `--snapshots` | `false` | Force `whale compare` to treat `TARGET` as a second Delta Lake snapshot directory rather than a live directory. |
| `--baseline-version <VERSION>` | Latest | Pin `BASELINE_DELTA_PATH` / `OLD_SNAPSHOT` to a specific Delta Lake transaction log version (`i64`). |
| `--target-version <VERSION>` | Latest | Pin `TARGET` / `NEW_SNAPSHOT` to a specific Delta Lake transaction log version (`i64`). |

## Detailed Usage Examples

### 1. Basic Directory Scanning (`tsv` & `jsonl`)

Scan the current working directory, streaming tab-separated records to `stdout` and printing the summary report to `stderr`:

```bash
whale scan .
```

Scan `/var/www` into a JSON Lines (`jsonl`) file while suppressing the summary report:

```bash
whale scan /var/www --format jsonl --output www_manifest.jsonl --skip-summary
```

Compute only the aggregate cryptographic tree hashes and summary telemetry (no per-file output) and save the summary to a file:

```bash
whale scan /data/models --summary-only --output models_summary.txt
```

### 2. Indexing into Delta Lake Multi-Namespace Storage (`--format delta`)

Index `/srv/dataset` into a Delta Lake root directory (`./snapshots/dataset_v1.delta`) using Zstandard compression:

```bash
whale scan /srv/dataset \
  --format delta \
  --output ./snapshots/dataset_v1.delta \
  --parquet-compression zstd \
  --parquet-row-group-size 65536
```

This creates three isolated, schema-enforced Delta Lake tables under `./snapshots/dataset_v1.delta`:

```text
snapshots/dataset_v1.delta/
├── directories/
│   ├── _delta_log/
│   │   └── 00000000000000000000.json
│   └── part-00000-...-c000.zstd.parquet
├── symlinks/
│   ├── _delta_log/
│   │   └── 00000000000000000000.json
│   └── part-00000-...-c000.zstd.parquet
└── files/
    ├── _delta_log/
    │   └── 00000000000000000000.json
    └── part-00000-...-c000.zstd.parquet
```

### 3. Live Directory vs. Delta Snapshot Comparison (`whale compare`)

Compare the live `/srv/dataset` directory tree against the baseline Delta Lake snapshot `./snapshots/dataset_v1.delta` and print all differences (`ADDED`, `DELETED`, `MODIFIED_CONTENT`, `MODIFIED_MODE`, `MODIFIED_CONTENT_AND_MODE`, `MODIFIED_TYPE`) as TSV to console:

```bash
whale compare ./snapshots/dataset_v1.delta /srv/dataset
```

Export all detected differences between the baseline snapshot and live filesystem into a JSONL audit log:

```bash
whale compare ./snapshots/dataset_v1.delta /srv/dataset \
  --format jsonl \
  --output ./audit_diffs.jsonl
```

Run an ultra-fast integrity check that only outputs the summary counts of added, deleted, and modified entries without streaming individual diff rows:

```bash
whale compare ./snapshots/dataset_v1.delta /srv/dataset --summary-only
```

### 4. Snapshot-to-Snapshot Diffing & Delta Lake Time-Travel

Compare two separate Delta Lake snapshot directories (`dataset_v1.delta` and `dataset_v2.delta`) in parallel across row groups and write the resulting diff records into a new Delta Lake table (`./diffs_v1_v2.delta/diffs`):

```bash
whale compare-snapshots ./snapshots/dataset_v1.delta ./snapshots/dataset_v2.delta \
  --format delta \
  --output ./diffs_v1_v2.delta
```

Because `whale` uses `delta-rs`, `whale compare` also auto-detects when the second argument is a Delta Lake root directory:

```bash
whale compare ./snapshots/dataset_v1.delta ./snapshots/dataset_v2.delta --format tsv -o changes.tsv
```

If you overwrite or append new versions to the *same* Delta Lake repository over time, you can compare historical versions using `--baseline-version` and `--target-version`:

```bash
whale compare-snapshots ./snapshots/prod.delta ./snapshots/prod.delta \
  --baseline-version 0 \
  --target-version 1 \
  --format jsonl \
  --output prod_v0_to_v1_diff.jsonl
```

### 5. Tuning Threads, Memory Mapping, and Permission Normalization

When comparing trees replicated across filesystems with different mount masks (where upper `st_mode` bits may vary), normalize modes to permission bits (`0o7777`) and use 16 worker threads with a 1 MiB `mmap` threshold:

```bash
whale scan /mnt/backup \
  --permission-bits-only \
  --threads 16 \
  --mmap-threshold 1048576 \
  --format delta \
  --output ./backup_snap.delta
```

### 6. Querying `whale` Delta Lake Namespaces with Python (`deltalake` / `duckdb`)

Because `whale` writes standard Delta Lake transaction logs (`_delta_log`), you can query any of the three namespaces directly using Python, DuckDB, Polars, or Apache Spark:

```python
from deltalake import DeltaTable
import pyarrow.compute as pc

# Open the 'files' namespace generated by whale
files_dt = DeltaTable("./snapshots/dataset_v1.delta/files")
df = files_dt.to_pyarrow_table()

# Find all files larger than 100 MiB
large_files = df.filter(pc.field("size_bytes") > 100 * 1024 * 1024)
print(large_files.select(["path", "size_bytes", "mode_octal", "content_sha256"]))
```

## Delta Lake Namespace Schemas (`parquet_writer.rs` & `diff.rs`)

Each filesystem object kind has its own strict, non-nullable schema inside its Delta Lake namespace:

### 1. `directories` Namespace (`<root>/directories`)

| Column Name | Arrow DataType | Delta PrimitiveType | Nullable | Description |
| :--- | :--- | :--- | :--- | :--- |
| `path` | `Utf8` | `String` | `false` | Path relative to the scan root (`.` for the root directory). |
| `mode_octal` | `Utf8` | `String` | `false` | 7-character octal representation of `mode` (e.g., `0040755`), dictionary-encoded. |
| `mode` | `UInt32` | `Integer` | `false` | Raw 32-bit POSIX `st_mode` (or `mode & 0o7777`). |
| `mode_sha256` | `Utf8` | `String` | `false` | 64-char hex SHA-256 of the 4-byte little-endian `mode`, dictionary-encoded. |
| `name_sha256` | `Utf8` | `String` | `false` | 64-char hex SHA-256 of the directory's basename (`file_name()`). |
| `path_sha256` | `Utf8` | `String` | `false` | 64-char hex SHA-256 of the directory's relative path bytes. |
| `composite_sha256` | `Utf8` | `String` | `false` | Domain-separated composite SHA-256 digest (`0x02` tag). |

### 2. `symlinks` Namespace (`<root>/symlinks`)

| Column Name | Arrow DataType | Delta PrimitiveType | Nullable | Description |
| :--- | :--- | :--- | :--- | :--- |
| `path` | `Utf8` | `String` | `false` | Path of the symlink relative to the scan root. |
| `symlink_target` | `Utf8` | `String` | `false` | Raw link target path read via `std::fs::read_link`. |
| `mode_octal` | `Utf8` | `String` | `false` | 7-character octal representation of `mode` (e.g., `0120777`), dictionary-encoded. |
| `mode` | `UInt32` | `Integer` | `false` | Raw 32-bit POSIX symlink `st_mode`. |
| `mode_sha256` | `Utf8` | `String` | `false` | 64-char hex SHA-256 of the 4-byte little-endian `mode`, dictionary-encoded. |
| `name_sha256` | `Utf8` | `String` | `false` | 64-char hex SHA-256 of the symlink's basename (`file_name()`). |
| `target_sha256` | `Utf8` | `String` | `false` | 64-char hex SHA-256 of the raw symlink target path bytes. |
| `composite_sha256` | `Utf8` | `String` | `false` | Domain-separated composite SHA-256 digest (`0x03` tag). |

### 3. `files` Namespace (`<root>/files`)

| Column Name | Arrow DataType | Delta PrimitiveType | Nullable | Description |
| :--- | :--- | :--- | :--- | :--- |
| `path` | `Utf8` | `String` | `false` | Path of the regular file relative to the scan root. |
| `size_bytes` | `UInt64` | `Long` | `false` | Exact file byte length (`u64`). |
| `mode_octal` | `Utf8` | `String` | `false` | 7-character octal representation of `mode` (e.g., `0100644`), dictionary-encoded. |
| `mode` | `UInt32` | `Integer` | `false` | Raw 32-bit POSIX file `st_mode`. |
| `mode_sha256` | `Utf8` | `String` | `false` | 64-char hex SHA-256 of the 4-byte little-endian `mode`, dictionary-encoded. |
| `name_sha256` | `Utf8` | `String` | `false` | 64-char hex SHA-256 of the file's basename (`file_name()`). |
| `content_sha256` | `Utf8` | `String` | `false` | 64-char hex SHA-256 of the file's full byte contents. |
| `composite_sha256` | `Utf8` | `String` | `false` | Domain-separated composite SHA-256 digest (`0x01` tag). |

### 4. `diffs` Namespace (`<diff_root>/diffs` in `compare` Mode)

| Column Name | Arrow DataType | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `status` | `Utf8` | `false` | `ADDED`, `DELETED`, `MODIFIED_CONTENT`, `MODIFIED_MODE`, `MODIFIED_CONTENT_AND_MODE`, or `MODIFIED_TYPE`. |
| `path` | `Utf8` | `false` | Relative path of the changed filesystem entry. |
| `old_kind` / `new_kind` | `Utf8` | `true` | Previous and current entry kind (`DIR`, `SYMLINK`, `FILE`). |
| `old_mode_octal` / `new_mode_octal` | `Utf8` | `true` | Previous and current 7-char octal mode string. |
| `old_mode` / `new_mode` | `UInt32` | `true` | Previous and current numeric `st_mode`. |
| `old_size_bytes` / `new_size_bytes` | `UInt64` | `true` | Previous and current file size in bytes (for regular files). |
| `old_payload_sha256` / `new_payload_sha256` | `Utf8` | `true` | Previous and current payload SHA-256 (`content_sha256`, `target_sha256`, or `path_sha256`). |
| `old_composite_sha256` / `new_composite_sha256` | `Utf8` | `true` | Previous and current domain-separated composite SHA-256 digest. |
| `old_symlink_target` / `new_symlink_target` | `Utf8` | `true` | Previous and current raw symlink target string (for symlinks). |
