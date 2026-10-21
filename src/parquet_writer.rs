//! `parquet_writer.rs` — Streaming Apache Parquet columnar writer for `whale`.
//!
//! Accumulates incoming `ScanRecord` batches into pre-allocated columnar builders and flushes
//! bounded row groups (default 65,536 rows per row group) to disk with ZSTD or Snappy compression.
//! This keeps memory usage strictly O(row_group_size) even when exporting 50+ million files.

use std::io::{self, BufWriter, Write};
use std::sync::Arc;

use arrow_array::builder::{StringBuilder, UInt32Builder, UInt64Builder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema};
use crossbeam_channel::Receiver;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, GzipLevel, ZstdLevel};
use parquet::file::properties::{EnabledStatistics, WriterProperties, WriterVersion};
use parquet::schema::types::ColumnPath;

use crate::config::ParquetCompression;
use crate::model::ScanRecord;
use crate::writer::{encode_hex_64, format_octal_mode};

/// Builds the canonical Apache Arrow schema for `whale` Parquet files.
pub fn build_parquet_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("kind", DataType::Utf8, false),
        Field::new("mode_octal", DataType::Utf8, false),
        Field::new("mode", DataType::UInt32, false),
        Field::new("mode_sha256", DataType::Utf8, false),
        Field::new("name_sha256", DataType::Utf8, false),
        Field::new("payload_sha256", DataType::Utf8, false),
        Field::new("composite_sha256", DataType::Utf8, false),
        Field::new("size_bytes", DataType::UInt64, false),
        Field::new("path", DataType::Utf8, false),
        Field::new("symlink_target", DataType::Utf8, true),
    ]))
}

/// Configures Apache Parquet `WriterProperties` with dictionary encoding on low-cardinality
/// columns (`kind`, `mode_octal`, `mode_sha256`) and user-selected page compression.
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
        // Enable dictionary encoding specifically for low-cardinality columns
        .set_column_dictionary_enabled(ColumnPath::from("kind"), true)
        .set_column_dictionary_enabled(ColumnPath::from("mode_octal"), true)
        .set_column_dictionary_enabled(ColumnPath::from("mode_sha256"), true)
        .set_statistics_enabled(EnabledStatistics::Chunk)
        .build()
}

/// Reusable columnar batch buffer that converts `ScanRecord` items into an Arrow `RecordBatch`.
struct ColumnarBatchBuffer {
    len: usize,
    kind_col: StringBuilder,
    mode_octal_col: StringBuilder,
    mode_col: UInt32Builder,
    mode_sha256_col: StringBuilder,
    name_sha256_col: StringBuilder,
    payload_sha256_col: StringBuilder,
    composite_sha256_col: StringBuilder,
    size_bytes_col: UInt64Builder,
    path_col: StringBuilder,
    symlink_target_col: StringBuilder,
}

impl ColumnarBatchBuffer {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            len: 0,
            kind_col: StringBuilder::with_capacity(capacity, capacity * 5),
            mode_octal_col: StringBuilder::with_capacity(capacity, capacity * 7),
            mode_col: UInt32Builder::with_capacity(capacity),
            mode_sha256_col: StringBuilder::with_capacity(capacity, capacity * 64),
            name_sha256_col: StringBuilder::with_capacity(capacity, capacity * 64),
            payload_sha256_col: StringBuilder::with_capacity(capacity, capacity * 64),
            composite_sha256_col: StringBuilder::with_capacity(capacity, capacity * 64),
            size_bytes_col: UInt64Builder::with_capacity(capacity),
            path_col: StringBuilder::with_capacity(capacity, capacity * 48),
            symlink_target_col: StringBuilder::with_capacity(capacity, capacity * 16),
        }
    }

    #[inline]
    fn push(
        &mut self,
        rec: &ScanRecord,
        mode_octal: &mut [u8; 7],
        mode_hex: &mut [u8; 64],
        name_hex: &mut [u8; 64],
        payload_hex: &mut [u8; 64],
        comp_hex: &mut [u8; 64],
    ) {
        format_octal_mode(rec.mode, mode_octal);
        encode_hex_64(&rec.mode_sha256, mode_hex);
        encode_hex_64(&rec.name_sha256, name_hex);
        encode_hex_64(&rec.payload_sha256, payload_hex);
        encode_hex_64(&rec.composite_sha256, comp_hex);

        // SAFETY: `format_octal_mode` and `encode_hex_64` only write ASCII hex/octal digits (`0..=9`, `a..=f`).
        let octal_str = unsafe { std::str::from_utf8_unchecked(mode_octal) };
        let mode_hex_str = unsafe { std::str::from_utf8_unchecked(mode_hex) };
        let name_hex_str = unsafe { std::str::from_utf8_unchecked(name_hex) };
        let payload_hex_str = unsafe { std::str::from_utf8_unchecked(payload_hex) };
        let comp_hex_str = unsafe { std::str::from_utf8_unchecked(comp_hex) };

        self.kind_col.append_value(rec.kind.as_str());
        self.mode_octal_col.append_value(octal_str);
        self.mode_col.append_value(rec.mode);
        self.mode_sha256_col.append_value(mode_hex_str);
        self.name_sha256_col.append_value(name_hex_str);
        self.payload_sha256_col.append_value(payload_hex_str);
        self.composite_sha256_col.append_value(comp_hex_str);
        self.size_bytes_col.append_value(rec.size_bytes);
        self.path_col.append_value(rec.path.to_string_lossy().as_ref());

        match rec.symlink_target {
            Some(ref target) => self
                .symlink_target_col
                .append_value(target.to_string_lossy().as_ref()),
            None => self.symlink_target_col.append_null(),
        }

        self.len += 1;
    }

    fn flush_batch(&mut self, schema: &Arc<Schema>) -> io::Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.kind_col.finish()),
            Arc::new(self.mode_octal_col.finish()),
            Arc::new(self.mode_col.finish()),
            Arc::new(self.mode_sha256_col.finish()),
            Arc::new(self.name_sha256_col.finish()),
            Arc::new(self.payload_sha256_col.finish()),
            Arc::new(self.composite_sha256_col.finish()),
            Arc::new(self.size_bytes_col.finish()),
            Arc::new(self.path_col.finish()),
            Arc::new(self.symlink_target_col.finish()),
        ];
        self.len = 0;
        RecordBatch::try_new(Arc::clone(schema), columns)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Dedicated single-consumer streaming Apache Parquet writer loop.
pub fn run_parquet_writer_loop(
    rx: Receiver<Vec<ScanRecord>>,
    sink: BufWriter<Box<dyn Write + Send>>,
    compression: ParquetCompression,
    row_group_size: usize,
) -> io::Result<()> {
    let schema = build_parquet_schema();
    let props = build_writer_properties(compression, row_group_size);

    let mut arrow_writer = ArrowWriter::try_new(sink, Arc::clone(&schema), Some(props))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let batch_rows = row_group_size.max(1024);
    let mut col_buf = ColumnarBatchBuffer::with_capacity(batch_rows);

    let mut mode_octal = [0u8; 7];
    let mut mode_hex = [0u8; 64];
    let mut name_hex = [0u8; 64];
    let mut payload_hex = [0u8; 64];
    let mut comp_hex = [0u8; 64];

    for batch in rx {
        for rec in batch {
            col_buf.push(
                &rec,
                &mut mode_octal,
                &mut mode_hex,
                &mut name_hex,
                &mut payload_hex,
                &mut comp_hex,
            );

            if col_buf.len >= batch_rows {
                let record_batch = col_buf.flush_batch(&schema)?;
                arrow_writer
                    .write(&record_batch)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            }
        }
    }

    if col_buf.len > 0 {
        let record_batch = col_buf.flush_batch(&schema)?;
        arrow_writer
            .write(&record_batch)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    }

    arrow_writer
        .close()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    Ok(())
}
