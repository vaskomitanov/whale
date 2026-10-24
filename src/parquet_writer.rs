//! `parquet_writer.rs` — High-throughput `delta-rs` (`deltalake`) writer grouping `Directory`,
//! `Symlink`, and `File` records into three separate Delta Lake table namespaces under a single
//! root repository without sacrificing throughput.
//!
//! ### Namespace & Schema Architecture
//! Under a single target Delta root directory (`<root>/`):
//! 1. **Namespace `directories` (`<root>/directories`)**:
//!    - Arrow Schema: `build_directory_parquet_schema()`
//!    - Delta Kernel Schema: `build_directory_delta_fields()`
//!    - Columns: `path`, `mode_octal`, `mode`, `mode_sha256`, `name_sha256`, `path_sha256`, `composite_sha256`
//! 2. **Namespace `symlinks` (`<root>/symlinks`)**:
//!    - Arrow Schema: `build_symlink_parquet_schema()`
//!    - Delta Kernel Schema: `build_symlink_delta_fields()`
//!    - Columns: `path`, `symlink_target`, `mode_octal`, `mode`, `mode_sha256`, `name_sha256`, `target_sha256`, `composite_sha256`
//! 3. **Namespace `files` (`<root>/files`)**:
//!    - Arrow Schema: `build_file_parquet_schema()`
//!    - Delta Kernel Schema: `build_file_delta_fields()`
//!    - Columns: `path`, `size_bytes`, `mode_octal`, `mode`, `mode_sha256`, `name_sha256`, `content_sha256`, `composite_sha256`
//!
//! ### How High Performance is Preserved with `delta-rs`:
//! - **Zero Per-Batch Transaction Log Overhead**: Incoming `ScanRecord` batches are accumulated into
//!   pre-allocated Arrow columnar builders (`DirectoryColumnarBuffer`, `SymlinkColumnarBuffer`,
//!   `FileColumnarBuffer`). Whenever a buffer reaches `row_group_size` (65,536 rows),
//!   `RecordBatchWriter::write` streams a compressed Parquet data file directly into the namespace
//!   directory without writing to `_delta_log`.
//! - **Single Concurrent Atomic Commit (`tokio::try_join!`)**: Only after the entire scan finishes do
//!   the three `RecordBatchWriter` instances call `flush_and_commit(&mut table)` concurrently,
//!   committing a single atomic `_delta_log` entry per namespace!

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arrow_array::builder::{Int32Builder, Int64Builder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema};
use crossbeam_channel::Receiver;
use deltalake::kernel::{DataType as DeltaDataType, PrimitiveType, StructField};
use deltalake::operations::create::CreateBuilder;
use deltalake::protocol::SaveMode;
use deltalake::writer::{DeltaWriter, RecordBatchWriter};
use deltalake::DeltaTable;
use parquet::basic::{Compression, GzipLevel, ZstdLevel};
use parquet::file::properties::{EnabledStatistics, WriterProperties, WriterVersion};
use parquet::schema::types::ColumnPath;

use crate::config::ParquetCompression;
use crate::model::ScanRecord;
use crate::writer::{encode_hex_64, format_octal_mode};

/// 1. Dedicated Apache Arrow / Parquet schema for the **`directories`** Delta namespace (`ScanRecord::Directory`).
pub fn build_directory_parquet_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("path", DataType::Utf8, false),
        Field::new("mode_octal", DataType::Utf8, false),
        Field::new("mode", DataType::Int32, false),
        Field::new("mode_sha256", DataType::Utf8, false),
        Field::new("name_sha256", DataType::Utf8, false),
        Field::new("path_sha256", DataType::Utf8, false),
        Field::new("composite_sha256", DataType::Utf8, false),
    ]))
}

/// Delta Lake `StructField` schema definition for the **`directories`** namespace.
pub fn build_directory_delta_fields() -> Vec<StructField> {
    vec![
        StructField::new("path", DeltaDataType::Primitive(PrimitiveType::String), false),
        StructField::new("mode_octal", DeltaDataType::Primitive(PrimitiveType::String), false),
        StructField::new("mode", DeltaDataType::Primitive(PrimitiveType::Integer), false),
        StructField::new("mode_sha256", DeltaDataType::Primitive(PrimitiveType::String), false),
        StructField::new("name_sha256", DeltaDataType::Primitive(PrimitiveType::String), false),
        StructField::new("path_sha256", DeltaDataType::Primitive(PrimitiveType::String), false),
        StructField::new("composite_sha256", DeltaDataType::Primitive(PrimitiveType::String), false),
    ]
}

/// 2. Dedicated Apache Arrow / Parquet schema for the **`symlinks`** Delta namespace (`ScanRecord::Symlink`).
pub fn build_symlink_parquet_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("path", DataType::Utf8, false),
        Field::new("symlink_target", DataType::Utf8, false),
        Field::new("mode_octal", DataType::Utf8, false),
        Field::new("mode", DataType::Int32, false),
        Field::new("mode_sha256", DataType::Utf8, false),
        Field::new("name_sha256", DataType::Utf8, false),
        Field::new("target_sha256", DataType::Utf8, false),
        Field::new("composite_sha256", DataType::Utf8, false),
    ]))
}

/// Delta Lake `StructField` schema definition for the **`symlinks`** namespace.
pub fn build_symlink_delta_fields() -> Vec<StructField> {
    vec![
        StructField::new("path", DeltaDataType::Primitive(PrimitiveType::String), false),
        StructField::new("symlink_target", DeltaDataType::Primitive(PrimitiveType::String), false),
        StructField::new("mode_octal", DeltaDataType::Primitive(PrimitiveType::String), false),
        StructField::new("mode", DeltaDataType::Primitive(PrimitiveType::Integer), false),
        StructField::new("mode_sha256", DeltaDataType::Primitive(PrimitiveType::String), false),
        StructField::new("name_sha256", DeltaDataType::Primitive(PrimitiveType::String), false),
        StructField::new("target_sha256", DeltaDataType::Primitive(PrimitiveType::String), false),
        StructField::new("composite_sha256", DeltaDataType::Primitive(PrimitiveType::String), false),
    ]
}

/// 3. Dedicated Apache Arrow / Parquet schema for the **`files`** Delta namespace (`ScanRecord::File`).
pub fn build_file_parquet_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("path", DataType::Utf8, false),
        Field::new("size_bytes", DataType::Int64, false),
        Field::new("mode_octal", DataType::Utf8, false),
        Field::new("mode", DataType::Int32, false),
        Field::new("mode_sha256", DataType::Utf8, false),
        Field::new("name_sha256", DataType::Utf8, false),
        Field::new("content_sha256", DataType::Utf8, false),
        Field::new("composite_sha256", DataType::Utf8, false),
    ]))
}

/// Delta Lake `StructField` schema definition for the **`files`** namespace.
pub fn build_file_delta_fields() -> Vec<StructField> {
    vec![
        StructField::new("path", DeltaDataType::Primitive(PrimitiveType::String), false),
        StructField::new("size_bytes", DeltaDataType::Primitive(PrimitiveType::Long), false),
        StructField::new("mode_octal", DeltaDataType::Primitive(PrimitiveType::String), false),
        StructField::new("mode", DeltaDataType::Primitive(PrimitiveType::Integer), false),
        StructField::new("mode_sha256", DeltaDataType::Primitive(PrimitiveType::String), false),
        StructField::new("name_sha256", DeltaDataType::Primitive(PrimitiveType::String), false),
        StructField::new("content_sha256", DeltaDataType::Primitive(PrimitiveType::String), false),
        StructField::new("composite_sha256", DeltaDataType::Primitive(PrimitiveType::String), false),
    ]
}

/// Groups the three Delta Lake table namespaces (`directories`, `symlinks`, `files`) under a single
/// root Delta directory (`root_dir`).
#[derive(Debug, Clone)]
pub struct DeltaNamespacePaths {
    pub root_dir: PathBuf,
    pub directories_ns: PathBuf,
    pub symlinks_ns: PathBuf,
    pub files_ns: PathBuf,
}

impl DeltaNamespacePaths {
    pub fn from_base_path(base: &Path) -> Self {
        Self {
            root_dir: base.to_path_buf(),
            directories_ns: base.join("directories"),
            symlinks_ns: base.join("symlinks"),
            files_ns: base.join("files"),
        }
    }

    pub fn ensure_directories_exist(&self) -> io::Result<()> {
        fs::create_dir_all(&self.directories_ns)?;
        fs::create_dir_all(&self.symlinks_ns)?;
        fs::create_dir_all(&self.files_ns)?;
        Ok(())
    }
}

/// Configures Apache Parquet `WriterProperties` for `RecordBatchWriter` with dictionary encoding
/// on low-cardinality mode columns (`mode_octal`, `mode_sha256`) and user-selected page compression.
pub fn build_writer_properties(
    compression: ParquetCompression,
    row_group_size: usize,
) -> WriterProperties {
    let codec = match compression {
        ParquetCompression::Zstd => {
            Compression::ZSTD(ZstdLevel::try_new(3).unwrap_or_default())
        }
        ParquetCompression::Snappy => Compression::SNAPPY,
        ParquetCompression::Gzip => Compression::GZIP(GzipLevel::default()),
        ParquetCompression::Uncompressed => Compression::UNCOMPRESSED,
    };

    WriterProperties::builder()
        .set_writer_version(WriterVersion::PARQUET_2_0)
        .set_compression(codec)
        .set_max_row_group_size(row_group_size.max(1024))
        .set_dictionary_enabled(false)
        .set_column_dictionary_enabled(ColumnPath::from("mode_octal"), true)
        .set_column_dictionary_enabled(ColumnPath::from("mode_sha256"), true)
        .set_statistics_enabled(EnabledStatistics::Chunk)
        .build()
}

/// Columnar batch builder for `ScanRecord::Directory` matching `build_directory_parquet_schema()`.
struct DirectoryColumnarBuffer {
    len: usize,
    path_col: StringBuilder,
    mode_octal_col: StringBuilder,
    mode_col: Int32Builder,
    mode_sha256_col: StringBuilder,
    name_sha256_col: StringBuilder,
    path_sha256_col: StringBuilder,
    composite_sha256_col: StringBuilder,
}

impl DirectoryColumnarBuffer {
    fn with_capacity(cap: usize) -> Self {
        Self {
            len: 0,
            path_col: StringBuilder::with_capacity(cap, cap * 48),
            mode_octal_col: StringBuilder::with_capacity(cap, cap * 7),
            mode_col: Int32Builder::with_capacity(cap),
            mode_sha256_col: StringBuilder::with_capacity(cap, cap * 64),
            name_sha256_col: StringBuilder::with_capacity(cap, cap * 64),
            path_sha256_col: StringBuilder::with_capacity(cap, cap * 64),
            composite_sha256_col: StringBuilder::with_capacity(cap, cap * 64),
        }
    }

    #[inline]
    fn push(
        &mut self,
        path: &Path,
        mode: u32,
        mode_sha256: &[u8; 32],
        name_sha256: &[u8; 32],
        path_sha256: &[u8; 32],
        composite_sha256: &[u8; 32],
        octal_buf: &mut [u8; 7],
        hex_buf: &mut [u8; 64],
    ) {
        self.path_col.append_value(path.to_string_lossy().as_ref());

        format_octal_mode(mode, octal_buf);
        self.mode_octal_col
            .append_value(unsafe { std::str::from_utf8_unchecked(octal_buf) });
        self.mode_col.append_value(mode as i32);

        encode_hex_64(mode_sha256, hex_buf);
        self.mode_sha256_col
            .append_value(unsafe { std::str::from_utf8_unchecked(hex_buf) });

        encode_hex_64(name_sha256, hex_buf);
        self.name_sha256_col
            .append_value(unsafe { std::str::from_utf8_unchecked(hex_buf) });

        encode_hex_64(path_sha256, hex_buf);
        self.path_sha256_col
            .append_value(unsafe { std::str::from_utf8_unchecked(hex_buf) });

        encode_hex_64(composite_sha256, hex_buf);
        self.composite_sha256_col
            .append_value(unsafe { std::str::from_utf8_unchecked(hex_buf) });

        self.len += 1;
    }

    fn flush_batch(&mut self, schema: &Arc<Schema>) -> io::Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.path_col.finish()),
            Arc::new(self.mode_octal_col.finish()),
            Arc::new(self.mode_col.finish()),
            Arc::new(self.mode_sha256_col.finish()),
            Arc::new(self.name_sha256_col.finish()),
            Arc::new(self.path_sha256_col.finish()),
            Arc::new(self.composite_sha256_col.finish()),
        ];
        self.len = 0;
        RecordBatch::try_new(Arc::clone(schema), columns)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Columnar batch builder for `ScanRecord::Symlink` matching `build_symlink_parquet_schema()`.
struct SymlinkColumnarBuffer {
    len: usize,
    path_col: StringBuilder,
    symlink_target_col: StringBuilder,
    mode_octal_col: StringBuilder,
    mode_col: Int32Builder,
    mode_sha256_col: StringBuilder,
    name_sha256_col: StringBuilder,
    target_sha256_col: StringBuilder,
    composite_sha256_col: StringBuilder,
}

impl SymlinkColumnarBuffer {
    fn with_capacity(cap: usize) -> Self {
        Self {
            len: 0,
            path_col: StringBuilder::with_capacity(cap, cap * 48),
            symlink_target_col: StringBuilder::with_capacity(cap, cap * 48),
            mode_octal_col: StringBuilder::with_capacity(cap, cap * 7),
            mode_col: Int32Builder::with_capacity(cap),
            mode_sha256_col: StringBuilder::with_capacity(cap, cap * 64),
            name_sha256_col: StringBuilder::with_capacity(cap, cap * 64),
            target_sha256_col: StringBuilder::with_capacity(cap, cap * 64),
            composite_sha256_col: StringBuilder::with_capacity(cap, cap * 64),
        }
    }

    #[inline]
    fn push(
        &mut self,
        path: &Path,
        symlink_target: &Path,
        mode: u32,
        mode_sha256: &[u8; 32],
        name_sha256: &[u8; 32],
        target_sha256: &[u8; 32],
        composite_sha256: &[u8; 32],
        octal_buf: &mut [u8; 7],
        hex_buf: &mut [u8; 64],
    ) {
        self.path_col.append_value(path.to_string_lossy().as_ref());
        self.symlink_target_col
            .append_value(symlink_target.to_string_lossy().as_ref());

        format_octal_mode(mode, octal_buf);
        self.mode_octal_col
            .append_value(unsafe { std::str::from_utf8_unchecked(octal_buf) });
        self.mode_col.append_value(mode as i32);

        encode_hex_64(mode_sha256, hex_buf);
        self.mode_sha256_col
            .append_value(unsafe { std::str::from_utf8_unchecked(hex_buf) });

        encode_hex_64(name_sha256, hex_buf);
        self.name_sha256_col
            .append_value(unsafe { std::str::from_utf8_unchecked(hex_buf) });

        encode_hex_64(target_sha256, hex_buf);
        self.target_sha256_col
            .append_value(unsafe { std::str::from_utf8_unchecked(hex_buf) });

        encode_hex_64(composite_sha256, hex_buf);
        self.composite_sha256_col
            .append_value(unsafe { std::str::from_utf8_unchecked(hex_buf) });

        self.len += 1;
    }

    fn flush_batch(&mut self, schema: &Arc<Schema>) -> io::Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.path_col.finish()),
            Arc::new(self.symlink_target_col.finish()),
            Arc::new(self.mode_octal_col.finish()),
            Arc::new(self.mode_col.finish()),
            Arc::new(self.mode_sha256_col.finish()),
            Arc::new(self.name_sha256_col.finish()),
            Arc::new(self.target_sha256_col.finish()),
            Arc::new(self.composite_sha256_col.finish()),
        ];
        self.len = 0;
        RecordBatch::try_new(Arc::clone(schema), columns)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Columnar batch builder for `ScanRecord::File` matching `build_file_parquet_schema()`.
struct FileColumnarBuffer {
    len: usize,
    path_col: StringBuilder,
    size_bytes_col: Int64Builder,
    mode_octal_col: StringBuilder,
    mode_col: Int32Builder,
    mode_sha256_col: StringBuilder,
    name_sha256_col: StringBuilder,
    content_sha256_col: StringBuilder,
    composite_sha256_col: StringBuilder,
}

impl FileColumnarBuffer {
    fn with_capacity(cap: usize) -> Self {
        Self {
            len: 0,
            path_col: StringBuilder::with_capacity(cap, cap * 48),
            size_bytes_col: Int64Builder::with_capacity(cap),
            mode_octal_col: StringBuilder::with_capacity(cap, cap * 7),
            mode_col: Int32Builder::with_capacity(cap),
            mode_sha256_col: StringBuilder::with_capacity(cap, cap * 64),
            name_sha256_col: StringBuilder::with_capacity(cap, cap * 64),
            content_sha256_col: StringBuilder::with_capacity(cap, cap * 64),
            composite_sha256_col: StringBuilder::with_capacity(cap, cap * 64),
        }
    }

    #[inline]
    fn push(
        &mut self,
        path: &Path,
        size_bytes: u64,
        mode: u32,
        mode_sha256: &[u8; 32],
        name_sha256: &[u8; 32],
        content_sha256: &[u8; 32],
        composite_sha256: &[u8; 32],
        octal_buf: &mut [u8; 7],
        hex_buf: &mut [u8; 64],
    ) {
        self.path_col.append_value(path.to_string_lossy().as_ref());
        self.size_bytes_col.append_value(size_bytes as i64);

        format_octal_mode(mode, octal_buf);
        self.mode_octal_col
            .append_value(unsafe { std::str::from_utf8_unchecked(octal_buf) });
        self.mode_col.append_value(mode as i32);

        encode_hex_64(mode_sha256, hex_buf);
        self.mode_sha256_col
            .append_value(unsafe { std::str::from_utf8_unchecked(hex_buf) });

        encode_hex_64(name_sha256, hex_buf);
        self.name_sha256_col
            .append_value(unsafe { std::str::from_utf8_unchecked(hex_buf) });

        encode_hex_64(content_sha256, hex_buf);
        self.content_sha256_col
            .append_value(unsafe { std::str::from_utf8_unchecked(hex_buf) });

        encode_hex_64(composite_sha256, hex_buf);
        self.composite_sha256_col
            .append_value(unsafe { std::str::from_utf8_unchecked(hex_buf) });

        self.len += 1;
    }

    fn flush_batch(&mut self, schema: &Arc<Schema>) -> io::Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.path_col.finish()),
            Arc::new(self.size_bytes_col.finish()),
            Arc::new(self.mode_octal_col.finish()),
            Arc::new(self.mode_col.finish()),
            Arc::new(self.mode_sha256_col.finish()),
            Arc::new(self.name_sha256_col.finish()),
            Arc::new(self.content_sha256_col.finish()),
            Arc::new(self.composite_sha256_col.finish()),
        ];
        self.len = 0;
        RecordBatch::try_new(Arc::clone(schema), columns)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Initializes a `DeltaTable` at `namespace_dir` with the specified `table_name` and `fields`.
pub async fn init_delta_namespace_table(
    namespace_dir: &Path,
    table_name: &str,
    fields: Vec<StructField>,
) -> io::Result<DeltaTable> {
    fs::create_dir_all(namespace_dir)?;
    let abs_dir = fs::canonicalize(namespace_dir)?;
    let uri = url::Url::from_directory_path(&abs_dir).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid directory path for Delta namespace: {}", abs_dir.display()),
        )
    })?;

    CreateBuilder::new()
        .with_location(uri.as_str())
        .with_table_name(table_name)
        .with_columns(fields)
        .with_save_mode(SaveMode::Overwrite)
        .await
        .map_err(io::Error::other)
}

/// Dedicated single-consumer streaming `delta-rs` writer loop that routes `ScanRecord::Directory`,
/// `ScanRecord::Symlink`, and `ScanRecord::File` into their three respective Delta Lake namespaces
/// (`<root>/directories`, `<root>/symlinks`, `<root>/files`) and commits all three transaction logs
/// concurrently upon completion.
pub fn run_parquet_writer_loop(
    rx: Receiver<Vec<ScanRecord>>,
    base_output_path: &Path,
    compression: ParquetCompression,
    row_group_size: usize,
) -> io::Result<()> {
    let ns_paths = DeltaNamespacePaths::from_base_path(base_output_path);
    ns_paths.ensure_directories_exist()?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;

    rt.block_on(async move {
        // Initialize all 3 Delta Lake namespace tables concurrently
        let (mut dir_table, mut sym_table, mut file_table) = tokio::try_join!(
            init_delta_namespace_table(
                &ns_paths.directories_ns,
                "directories",
                build_directory_delta_fields()
            ),
            init_delta_namespace_table(
                &ns_paths.symlinks_ns,
                "symlinks",
                build_symlink_delta_fields()
            ),
            init_delta_namespace_table(&ns_paths.files_ns, "files", build_file_delta_fields()),
        )?;

        let dir_schema = build_directory_parquet_schema();
        let sym_schema = build_symlink_parquet_schema();
        let file_schema = build_file_parquet_schema();

        let dir_props = build_writer_properties(compression, row_group_size);
        let sym_props = build_writer_properties(compression, row_group_size);
        let file_props = build_writer_properties(compression, row_group_size);

        let mut dir_writer = RecordBatchWriter::for_table(&dir_table)
            .map_err(io::Error::other)?
            .with_writer_properties(dir_props);
        let mut sym_writer = RecordBatchWriter::for_table(&sym_table)
            .map_err(io::Error::other)?
            .with_writer_properties(sym_props);
        let mut file_writer = RecordBatchWriter::for_table(&file_table)
            .map_err(io::Error::other)?
            .with_writer_properties(file_props);

        let batch_rows = row_group_size.max(1024);
        let mut dir_buf = DirectoryColumnarBuffer::with_capacity(batch_rows.min(16_384));
        let mut sym_buf = SymlinkColumnarBuffer::with_capacity(batch_rows.min(4_096));
        let mut file_buf = FileColumnarBuffer::with_capacity(batch_rows);

        let mut octal_buf = [0u8; 7];
        let mut hex_buf = [0u8; 64];

        for batch in rx {
            for rec in batch {
                match rec {
                    ScanRecord::Directory {
                        ref path,
                        mode,
                        ref mode_sha256,
                        ref name_sha256,
                        ref path_sha256,
                        ref composite_sha256,
                    } => {
                        dir_buf.push(
                            path,
                            mode,
                            mode_sha256,
                            name_sha256,
                            path_sha256,
                            composite_sha256,
                            &mut octal_buf,
                            &mut hex_buf,
                        );
                        if dir_buf.len >= batch_rows {
                            let rb = dir_buf.flush_batch(&dir_schema)?;
                            dir_writer
                                .write(rb)
                                .await
                                .map_err(io::Error::other)?;
                        }
                    }
                    ScanRecord::Symlink {
                        ref path,
                        ref symlink_target,
                        mode,
                        ref mode_sha256,
                        ref name_sha256,
                        ref target_sha256,
                        ref composite_sha256,
                    } => {
                        sym_buf.push(
                            path,
                            symlink_target,
                            mode,
                            mode_sha256,
                            name_sha256,
                            target_sha256,
                            composite_sha256,
                            &mut octal_buf,
                            &mut hex_buf,
                        );
                        if sym_buf.len >= batch_rows {
                            let rb = sym_buf.flush_batch(&sym_schema)?;
                            sym_writer
                                .write(rb)
                                .await
                                .map_err(io::Error::other)?;
                        }
                    }
                    ScanRecord::File {
                        ref path,
                        size_bytes,
                        mode,
                        ref mode_sha256,
                        ref name_sha256,
                        ref content_sha256,
                        ref composite_sha256,
                    } => {
                        file_buf.push(
                            path,
                            size_bytes,
                            mode,
                            mode_sha256,
                            name_sha256,
                            content_sha256,
                            composite_sha256,
                            &mut octal_buf,
                            &mut hex_buf,
                        );
                        if file_buf.len >= batch_rows {
                            let rb = file_buf.flush_batch(&file_schema)?;
                            file_writer
                                .write(rb)
                                .await
                                .map_err(io::Error::other)?;
                        }
                    }
                }
            }
        }

        if dir_buf.len > 0 {
            let rb = dir_buf.flush_batch(&dir_schema)?;
            dir_writer
                .write(rb)
                .await
                .map_err(io::Error::other)?;
        }
        if sym_buf.len > 0 {
            let rb = sym_buf.flush_batch(&sym_schema)?;
            sym_writer
                .write(rb)
                .await
                .map_err(io::Error::other)?;
        }
        if file_buf.len > 0 {
            let rb = file_buf.flush_batch(&file_schema)?;
            file_writer
                .write(rb)
                .await
                .map_err(io::Error::other)?;
        }

        // Commit all three Delta Lake namespace transaction logs concurrently
        let commit_dir = async {
            dir_writer
                .flush_and_commit(&mut dir_table)
                .await
                .map_err(io::Error::other)
        };
        let commit_sym = async {
            sym_writer
                .flush_and_commit(&mut sym_table)
                .await
                .map_err(io::Error::other)
        };
        let commit_file = async {
            file_writer
                .flush_and_commit(&mut file_table)
                .await
                .map_err(io::Error::other)
        };

        tokio::try_join!(commit_dir, commit_sym, commit_file)?;
        Ok(())
    })
}