//! 尾部 descriptor 的格式、完整性与占用区间回归。

use super::*;
use std::io::{Cursor, Write};
use std::ops::Range;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

fn fixture(database: Vec<u8>, zip64: bool) -> Vec<u8> {
    let mut writer = ZipWriter::new_stream(Vec::new());
    for (name, payload) in [
        ("collection.anki2", database),
        ("media", br#"{"0":"picture.png"}"#.to_vec()),
        ("0", b"\x89PNG\r\n\x1a\nimage".to_vec()),
    ] {
        writer
            .start_file(
                name,
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated).large_file(zip64),
            )
            .unwrap();
        writer.write_all(&payload).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn descriptor(bytes: &[u8], index: usize, zip64: bool) -> Range<usize> {
    let mut zip = ZipArchive::new(Cursor::new(bytes)).unwrap();
    let entry = zip.by_index(index).unwrap();
    assert!(entry.flags().is_using_data_descriptor());
    let start = (entry.data_start().unwrap() + entry.compressed_size()) as usize;
    assert_eq!(&bytes[start..start + 4], b"PK\x07\x08");
    start..start + if zip64 { 24 } else { 16 }
}

// 只替换 descriptor，并修正后续本地偏移和 EOCD，避免其他损坏掩盖待测路径。
fn replace_descriptor(bytes: &[u8], range: Range<usize>, replacement: &[u8]) -> Vec<u8> {
    let zip = ZipArchive::new(Cursor::new(bytes)).unwrap();
    let headers: Vec<_> = (0..zip.len())
        .map(|i| {
            let entry = zip.by_index_data(i).unwrap();
            (entry.central_header_start() as usize, entry.header_start() as usize)
        })
        .collect();
    let shift = replacement.len() as isize - range.len() as isize;
    let shifted = |offset: usize| offset.checked_add_signed(shift).unwrap();
    let mut changed = bytes.to_vec();
    changed.splice(range.clone(), replacement.iter().copied());
    for (central, local) in headers {
        let central = shifted(central);
        let local = if local >= range.end { shifted(local) } else { local };
        changed[central + 42..central + 46].copy_from_slice(&(local as u32).to_le_bytes());
    }
    let end = changed.len() - 22;
    changed[end + 16..end + 20]
        .copy_from_slice(&(shifted(zip.central_directory_start() as usize) as u32).to_le_bytes());
    changed
}

#[test]
fn apkg_accepts_signed_and_unsigned_descriptors_for_every_entry() {
    for zip64 in [false, true] {
        for signed in [false, true] {
            let mut bytes = fixture(b"database payload".to_vec(), zip64);
            for index in 0..3 {
                let range = descriptor(&bytes, index, zip64);
                if !signed {
                    let unsigned = bytes[range.start + 4..range.end].to_vec();
                    bytes = replace_descriptor(&bytes, range, &unsigned);
                }
            }
            let package = archive::read(bytes).unwrap();
            assert_eq!(package.database, b"database payload");
            assert_eq!(package.media["picture.png"], b"\x89PNG\r\n\x1a\nimage");
        }
    }
}

#[test]
fn apkg_rejects_missing_truncated_and_conflicting_descriptors_for_every_entry() {
    for zip64 in [false, true] {
        let bytes = fixture(b"database payload".to_vec(), zip64);
        for index in 0..3 {
            let range = descriptor(&bytes, index, zip64);
            for signed in [false, true] {
                let fields = &bytes[range.start + if signed { 0 } else { 4 }..range.end];
                let reject = |replacement: &[u8], case: &str| {
                    let changed = replace_descriptor(&bytes, range.clone(), replacement);
                    let mut zip = ZipArchive::new(Cursor::new(&changed)).unwrap();
                    zip.validate_header_consistency().unwrap();
                    let error =
                        archive::read(changed).err().expect("invalid descriptor unexpectedly accepted").to_string();
                    assert!(
                        error.contains("ZIP data descriptor"),
                        "{case}, entry {index}, ZIP64 {zip64}, signed {signed}: {error}"
                    );
                };
                // 长度为零是缺失，其余前缀覆盖每个截断位置，含尾部紧邻中央目录的条目。
                for len in 0..fields.len() {
                    reject(&fields[..len], "missing/truncated");
                }
                let mut delayed = vec![0];
                delayed.extend_from_slice(fields);
                reject(&delayed, "descriptor not immediately after payload");
                let crc = if signed { 4 } else { 0 };
                let width = if zip64 { 8 } else { 4 };
                for offset in [crc, crc + 4, crc + 4 + width] {
                    let mut conflicting = fields.to_vec();
                    conflicting[offset] ^= 1;
                    reject(&conflicting, "conflicting CRC/size");
                }
                if zip64 {
                    for offset in [crc + 8, crc + 16] {
                        let mut conflicting = fields.to_vec();
                        conflicting[offset] ^= 1;
                        reject(&conflicting, "conflicting ZIP64 high size bits");
                    }
                }
            }
        }
    }
}

#[test]
fn apkg_unsigned_descriptor_crc_can_equal_optional_signature() {
    // 固定四字节载荷的 CRC-32 为 0x08074b50，不能把该 CRC 无条件吞作签名。
    let database = vec![0xac, 0x0a, 0x7a, 0xd5];
    for zip64 in [false, true] {
        let bytes = fixture(database.clone(), zip64);
        let range = descriptor(&bytes, 0, zip64);
        assert_eq!(&bytes[range.start + 4..range.start + 8], b"PK\x07\x08");
        let unsigned = &bytes[range.start + 4..range.end];
        let changed = replace_descriptor(&bytes, range, unsigned);
        assert_eq!(archive::read(changed).unwrap().database, database);
    }
}

#[test]
fn apkg_zip64_descriptor_width_can_be_declared_only_in_local_header() {
    let mut bytes = fixture(b"database payload".to_vec(), true);
    let zip = ZipArchive::new(Cursor::new(&bytes)).unwrap();
    let entries: Vec<_> = (0..zip.len())
        .map(|i| {
            let entry = zip.by_index_data(i).unwrap();
            (entry.central_header_start() as usize, entry.compressed_size() as u32, entry.size() as u32)
        })
        .collect();
    let count = entries.len();
    // 小文件可仅在本地头预留 ZIP64；中央目录使用实际的普通大小。
    for (central, compressed, size) in entries.into_iter().rev() {
        let name_len = u16::from_le_bytes(bytes[central + 28..central + 30].try_into().unwrap()) as usize;
        let extra = central + 46 + name_len;
        assert_eq!(&bytes[extra..extra + 4], &[1, 0, 16, 0]);
        assert_eq!(&bytes[central + 30..central + 32], &[20, 0]);
        bytes[central + 20..central + 24].copy_from_slice(&compressed.to_le_bytes());
        bytes[central + 24..central + 28].copy_from_slice(&size.to_le_bytes());
        bytes[central + 30..central + 32].fill(0);
        bytes.drain(extra..extra + 20);
    }
    let end = bytes.len() - 22;
    let directory_size = u32::from_le_bytes(bytes[end + 12..end + 16].try_into().unwrap()) - (20 * count) as u32;
    bytes[end + 12..end + 16].copy_from_slice(&directory_size.to_le_bytes());
    for index in 0..count {
        let range = descriptor(&bytes, index, true);
        let unsigned = bytes[range.start + 4..range.end].to_vec();
        bytes = replace_descriptor(&bytes, range, &unsigned);
    }
    assert_eq!(archive::read(bytes).unwrap().database, b"database payload");
}

#[test]
fn apkg_descriptor_bytes_cannot_overlap_another_local_header() {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, payload) in [("collection.anki2", b"".as_slice()), ("media", b"{}".as_slice())] {
        writer.start_file(name, SimpleFileOptions::default().compression_method(CompressionMethod::Stored)).unwrap();
        writer.write_all(payload).unwrap();
    }
    let mut bytes = writer.finish().unwrap().into_inner();
    let zip = ZipArchive::new(Cursor::new(&bytes)).unwrap();
    let first = zip.by_index_data(0).unwrap();
    let local = first.header_start() as usize;
    let central = first.central_header_start() as usize;
    let second = zip.by_index_data(1).unwrap();
    let next_local = second.header_start() as usize;
    let next_central = second.central_header_start() as usize;
    // 下一本地头的前十二字节同时伪装为无签名 descriptor；CRC 检查前必须发现重叠。
    bytes[local + 6] |= 8;
    bytes[central + 8] |= 8;
    bytes[central + 16..central + 20].copy_from_slice(b"PK\x03\x04");
    bytes[next_local + 4..next_local + 12].fill(0);
    bytes[next_central + 6..next_central + 8].fill(0);
    bytes[next_central + 12..next_central + 14].fill(0);
    let mut zip = ZipArchive::new(Cursor::new(&bytes)).unwrap();
    zip.validate_header_consistency().unwrap();
    assert!(!zip.has_overlapping_entries().unwrap());
    let error = archive::read(bytes).err().unwrap().to_string();
    assert!(error.contains("overlapping ZIP entries"), "{error}");
}

#[tokio::test]
async fn apkg_streaming_descriptors_preserve_import_assertions() {
    let _guard = IMPORT_TEST.lock().await;
    let (svc, _, _) = service().await;
    let principal = Principal::local_owner("test");
    let db = support::database("basic", "Front<img src=\"picture.png\">\x1fBack", &[0]).await;
    for zip64 in [false, true] {
        let prepared = svc.prepare_apkg(&principal, fixture(db.clone(), zip64), ApkgOptions::default()).await.unwrap();
        assert_eq!(prepared.cards.len(), 1);
        assert_eq!(text(&prepared.cards[0].front), "Front");
        assert_eq!(text(&prepared.cards[0].back), "Front Back");
        assert_eq!(prepared.report.media_imported, 1);
    }
}
