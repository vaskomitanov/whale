//! `writer.rs` — Dedicated 8 MiB buffered output dispatcher for TSV, JSONL, and Apache Parquet.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use crossbeam_channel::Receiver;

use crate::config::{OutputFormat, ParquetCompression, WRITER_BUF_CAPACITY};
use crate::model::ScanRecord;
use crate::parquet_writer::run_parquet_writer_loop;

/// Formats a 32-byte digest into a 64-byte stack-allocated lowercase hex buffer.
#[inline]
pub fn encode_hex_64(digest: &[u8; 32], out: &mut [u8; 64]) {
    let _ = faster_hex::hex_encode(digest, out);
}

/// Converts a 32-byte SHA-256 digest into an owned 64-character hex `String`.
pub fn format_hex_string(digest: &[u8; 32]) -> String {
    let mut buf = [0u8; 64];
    encode_hex_64(digest, &mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Formats a 32-bit `mode` into a stack-allocated 7-byte octal ASCII buffer (e.g. `0100644` or `0040755`).
#[inline]
pub fn format_octal_mode(mut mode: u32, out: &mut [u8; 7]) {
    for i in (0..7).rev() {
        out[i] = b'0' + ((mode & 0o7) as u8);
        mode >>= 3;
    }
}

/// Escapes path strings minimally for valid JSON output.
pub fn write_json_escaped(out: &mut impl Write, s: &str) -> io::Result<()> {
    out.write_all(b"\"")?;
    for ch in s.chars() {
        match ch {
            '"' => out.write_all(b"\\\"")?,
            '\\' => out.write_all(b"\\\\")?,
            '\n' => out.write_all(b"\\n")?,
            '\r' => out.write_all(b"\\r")?,
            '\t' => out.write_all(b"\\t")?,
            c if (c as u32) < 0x20 => {
                write!(out, "\\u{:04x}", c as u32)?;
            }
            c => {
                let mut buf = [0u8; 4];
                out.write_all(c.encode_utf8(&mut buf).as_bytes())?;
            }
        }
    }
    out.write_all(b"\"")
}

/// Dedicated single-consumer buffered writer loop that dispatches `OutputFormat::Parquet` to the
/// three-schema Parquet writer (`Directory`, `Symlink`, `File`) or formats `ScanRecord` enum
/// variants as TSV / JSONL with zero heap allocation.
pub fn run_writer_loop(
    rx: Receiver<Vec<ScanRecord>>,
    record_output_path: Option<PathBuf>,
    format: OutputFormat,
    parquet_compression: ParquetCompression,
    parquet_row_group_size: usize,
) -> io::Result<()> {
    if format == OutputFormat::Parquet {
        let base_path = record_output_path.unwrap_or_else(|| PathBuf::from("whale_output.parquet"));
        return run_parquet_writer_loop(rx, &base_path, parquet_compression, parquet_row_group_size);
    }

    let sink: Box<dyn Write + Send> = match record_output_path {
        Some(ref p) => Box::new(File::create(p)?),
        None => Box::new(io::stdout()),
    };
    let mut writer = BufWriter::with_capacity(WRITER_BUF_CAPACITY, sink);

    if format == OutputFormat::Tsv {
        writer.write_all(
            b"# KIND\tMODE_OCTAL\tMODE_SHA256\tNAME_SHA256\tPAYLOAD_SHA256\tCOMPOSITE_SHA256\tSIZE_BYTES\tPATH\tSYMLINK_TARGET\n",
        )?;
    }

    let mut mode_octal = [0u8; 7];
    let mut mode_hex = [0u8; 64];
    let mut name_hex = [0u8; 64];
    let mut payload_hex = [0u8; 64];
    let mut comp_hex = [0u8; 64];
    let mut int_buf = itoa::Buffer::new();

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
                    format_octal_mode(mode, &mut mode_octal);
                    encode_hex_64(mode_sha256, &mut mode_hex);
                    encode_hex_64(name_sha256, &mut name_hex);
                    encode_hex_64(path_sha256, &mut payload_hex);
                    encode_hex_64(composite_sha256, &mut comp_hex);

                    match format {
                        OutputFormat::Tsv => {
                            writer.write_all(b"DIR\t")?;
                            writer.write_all(&mode_octal)?;
                            writer.write_all(b"\t")?;
                            writer.write_all(&mode_hex)?;
                            writer.write_all(b"\t")?;
                            writer.write_all(&name_hex)?;
                            writer.write_all(b"\t")?;
                            writer.write_all(&payload_hex)?;
                            writer.write_all(b"\t")?;
                            writer.write_all(&comp_hex)?;
                            writer.write_all(b"\t-\t")?;
                            writer.write_all(path.to_string_lossy().as_bytes())?;
                            writer.write_all(b"\t-\n")?;
                        }
                        OutputFormat::Jsonl => {
                            writer.write_all(b"{\"kind\":\"DIR\",\"mode_octal\":\"")?;
                            writer.write_all(&mode_octal)?;
                            writer.write_all(b"\",\"mode\":")?;
                            writer.write_all(int_buf.format(mode).as_bytes())?;
                            writer.write_all(b",\"mode_sha256\":\"")?;
                            writer.write_all(&mode_hex)?;
                            writer.write_all(b"\",\"name_sha256\":\"")?;
                            writer.write_all(&name_hex)?;
                            writer.write_all(b"\",\"path_sha256\":\"")?;
                            writer.write_all(&payload_hex)?;
                            writer.write_all(b"\",\"composite_sha256\":\"")?;
                            writer.write_all(&comp_hex)?;
                            writer.write_all(b"\",\"path\":")?;
                            write_json_escaped(&mut writer, &path.to_string_lossy())?;
                            writer.write_all(b"}\n")?;
                        }
                        OutputFormat::Parquet => {}
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
                    format_octal_mode(mode, &mut mode_octal);
                    encode_hex_64(mode_sha256, &mut mode_hex);
                    encode_hex_64(name_sha256, &mut name_hex);
                    encode_hex_64(target_sha256, &mut payload_hex);
                    encode_hex_64(composite_sha256, &mut comp_hex);

                    match format {
                        OutputFormat::Tsv => {
                            writer.write_all(b"SYMLINK\t")?;
                            writer.write_all(&mode_octal)?;
                            writer.write_all(b"\t")?;
                            writer.write_all(&mode_hex)?;
                            writer.write_all(b"\t")?;
                            writer.write_all(&name_hex)?;
                            writer.write_all(b"\t")?;
                            writer.write_all(&payload_hex)?;
                            writer.write_all(b"\t")?;
                            writer.write_all(&comp_hex)?;
                            writer.write_all(b"\t-\t")?;
                            writer.write_all(path.to_string_lossy().as_bytes())?;
                            writer.write_all(b"\t")?;
                            writer.write_all(symlink_target.to_string_lossy().as_bytes())?;
                            writer.write_all(b"\n")?;
                        }
                        OutputFormat::Jsonl => {
                            writer.write_all(b"{\"kind\":\"SYMLINK\",\"mode_octal\":\"")?;
                            writer.write_all(&mode_octal)?;
                            writer.write_all(b"\",\"mode\":")?;
                            writer.write_all(int_buf.format(mode).as_bytes())?;
                            writer.write_all(b",\"mode_sha256\":\"")?;
                            writer.write_all(&mode_hex)?;
                            writer.write_all(b"\",\"name_sha256\":\"")?;
                            writer.write_all(&name_hex)?;
                            writer.write_all(b"\",\"target_sha256\":\"")?;
                            writer.write_all(&payload_hex)?;
                            writer.write_all(b"\",\"composite_sha256\":\"")?;
                            writer.write_all(&comp_hex)?;
                            writer.write_all(b"\",\"path\":")?;
                            write_json_escaped(&mut writer, &path.to_string_lossy())?;
                            writer.write_all(b",\"symlink_target\":")?;
                            write_json_escaped(&mut writer, &symlink_target.to_string_lossy())?;
                            writer.write_all(b"}\n")?;
                        }
                        OutputFormat::Parquet => {}
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
                    format_octal_mode(mode, &mut mode_octal);
                    encode_hex_64(mode_sha256, &mut mode_hex);
                    encode_hex_64(name_sha256, &mut name_hex);
                    encode_hex_64(content_sha256, &mut payload_hex);
                    encode_hex_64(composite_sha256, &mut comp_hex);

                    match format {
                        OutputFormat::Tsv => {
                            writer.write_all(b"FILE\t")?;
                            writer.write_all(&mode_octal)?;
                            writer.write_all(b"\t")?;
                            writer.write_all(&mode_hex)?;
                            writer.write_all(b"\t")?;
                            writer.write_all(&name_hex)?;
                            writer.write_all(b"\t")?;
                            writer.write_all(&payload_hex)?;
                            writer.write_all(b"\t")?;
                            writer.write_all(&comp_hex)?;
                            writer.write_all(b"\t")?;
                            writer.write_all(int_buf.format(size_bytes).as_bytes())?;
                            writer.write_all(b"\t")?;
                            writer.write_all(path.to_string_lossy().as_bytes())?;
                            writer.write_all(b"\t-\n")?;
                        }
                        OutputFormat::Jsonl => {
                            writer.write_all(b"{\"kind\":\"FILE\",\"mode_octal\":\"")?;
                            writer.write_all(&mode_octal)?;
                            writer.write_all(b"\",\"mode\":")?;
                            writer.write_all(int_buf.format(mode).as_bytes())?;
                            writer.write_all(b",\"mode_sha256\":\"")?;
                            writer.write_all(&mode_hex)?;
                            writer.write_all(b"\",\"name_sha256\":\"")?;
                            writer.write_all(&name_hex)?;
                            writer.write_all(b"\",\"content_sha256\":\"")?;
                            writer.write_all(&payload_hex)?;
                            writer.write_all(b"\",\"composite_sha256\":\"")?;
                            writer.write_all(&comp_hex)?;
                            writer.write_all(b"\",\"size_bytes\":")?;
                            writer.write_all(int_buf.format(size_bytes).as_bytes())?;
                            writer.write_all(b",\"path\":")?;
                            write_json_escaped(&mut writer, &path.to_string_lossy())?;
                            writer.write_all(b"}\n")?;
                        }
                        OutputFormat::Parquet => {}
                    }
                }
            }
        }
    }

    writer.flush()?;
    Ok(())
}