//! 原始文件名和 UnicodePath 的解析器歧义回归。

use super::*;
use std::io::Cursor;
use zip::ZipArchive;

const NAMES: [&[u8]; 3] = [b"collection.anki2", b"media", b"0"];

fn crc32(bytes: &[u8]) -> u32 {
    let bytes = support::zip(vec![("0", bytes.to_vec())]);
    let zip = ZipArchive::new(Cursor::new(bytes)).unwrap();
    zip.by_index_data(0).unwrap().crc32()
}

fn unicode(name: &[u8], content: &[u8]) -> Vec<u8> {
    let mut field = vec![0x75, 0x70];
    field.extend_from_slice(&((5 + content.len()) as u16).to_le_bytes());
    field.push(1);
    field.extend_from_slice(&crc32(name).to_le_bytes());
    field.extend_from_slice(content);
    field
}

// 重建普通 ZIP 的头和目录，保留真实压缩载荷及 CRC，避免偏移损坏掩盖名称歧义。
fn fixture(index: usize, local_name: &[u8], central_name: &[u8], local_extra: &[u8], central_extra: &[u8]) -> Vec<u8> {
    let source = support::zip(vec![
        ("collection.anki2", b"database payload".to_vec()),
        ("media", br#"{"0":"picture.png"}"#.to_vec()),
        ("0", b"media payload".to_vec()),
    ]);
    let mut zip = ZipArchive::new(Cursor::new(&source)).unwrap();
    let mut bytes = Vec::new();
    let mut offsets = Vec::new();
    for (i, default_name) in NAMES.into_iter().enumerate() {
        let entry = zip.by_index(i).unwrap();
        let name = if i == index { local_name } else { default_name };
        let extra = if i == index { local_extra } else { &[] };
        let local = entry.header_start() as usize;
        let data = entry.data_start().unwrap() as usize;
        let mut header = source[local..local + 30].to_vec();
        header[26..28].copy_from_slice(&(name.len() as u16).to_le_bytes());
        header[28..30].copy_from_slice(&(extra.len() as u16).to_le_bytes());
        offsets.push(bytes.len());
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(extra);
        bytes.extend_from_slice(&source[data..data + entry.compressed_size() as usize]);
    }
    let directory = bytes.len();
    for (i, offset) in offsets.into_iter().enumerate() {
        let entry = zip.by_index_data(i).unwrap();
        let name = if i == index { central_name } else { NAMES[i] };
        let extra = if i == index { central_extra } else { &[] };
        let central = entry.central_header_start() as usize;
        let mut header = source[central..central + 46].to_vec();
        assert_eq!(&header[32..34], &[0, 0]);
        header[28..30].copy_from_slice(&(name.len() as u16).to_le_bytes());
        header[30..32].copy_from_slice(&(extra.len() as u16).to_le_bytes());
        header[42..46].copy_from_slice(&(offset as u32).to_le_bytes());
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(extra);
    }
    let mut end = source[source.len() - 22..].to_vec();
    end[12..16].copy_from_slice(&((bytes.len() - directory) as u32).to_le_bytes());
    end[16..20].copy_from_slice(&(directory as u32).to_le_bytes());
    bytes.extend_from_slice(&end);
    bytes
}

#[test]
fn apkg_rejects_crc_collision_unicode_path_cloaking() {
    let central = b"collection.anki2";
    let local = b"../escape-32-WoM;";
    assert_eq!(crc32(central), 0x0665_ea48);
    assert_eq!(crc32(local), 0x0665_ea48);
    let extra = unicode(central, central);
    let bytes = fixture(0, local, central, &extra, &extra);
    let mut zip = ZipArchive::new(Cursor::new(&bytes)).unwrap();
    zip.validate_header_consistency().unwrap();
    assert_eq!(zip.by_index(0).unwrap().name().unwrap(), "collection.anki2");
    let error = archive::read(bytes).err().expect("CRC collision cloaking unexpectedly accepted").to_string();
    assert!(error.contains("header inconsistency") && error.contains("raw filename"), "{error}");
}

#[test]
fn apkg_accepts_matching_unicode_path_for_every_entry() {
    for (index, name) in NAMES.into_iter().enumerate() {
        let extra = unicode(name, name);
        let package = archive::read(fixture(index, name, name, &extra, &extra)).unwrap();
        assert_eq!(package.database, b"database payload");
        assert_eq!(package.media["picture.png"], b"media payload");
    }
}

#[test]
fn apkg_rejects_unicode_path_substitution_even_when_raw_headers_match() {
    for (index, name) in NAMES.into_iter().enumerate() {
        // 两份原始名称相同；即使两份扩展也相同，上游仍会替换名称并通过头一致性校验。
        let extra = unicode(name, b"1");
        let bytes = fixture(index, name, name, &extra, &extra);
        let mut zip = ZipArchive::new(Cursor::new(&bytes)).unwrap();
        zip.validate_header_consistency().unwrap();
        let error = archive::read(bytes).err().expect("UnicodePath substitution unexpectedly accepted").to_string();
        assert!(error.contains("UnicodePath extra field"), "entry {index}: {error}");
    }
}

#[test]
fn apkg_rejects_ignored_and_duplicate_unicode_path_fields_in_either_header() {
    for (index, name) in NAMES.into_iter().enumerate() {
        let good = unicode(name, name);
        let mut bad_crc = unicode(name, b"../escape");
        bad_crc[5] ^= 1;
        let invalid_utf8 = unicode(name, &[0xff]);
        let mut unknown_version = good.clone();
        unknown_version[4] = 2;
        for extra in [
            bad_crc.clone(),
            invalid_utf8,
            unknown_version,
            [good.clone(), bad_crc.clone()].concat(),
            [bad_crc, good].concat(),
        ] {
            for (local, central) in [(&extra[..], &[][..]), (&[][..], &extra[..]), (&extra[..], &extra[..])] {
                let bytes = fixture(index, name, name, local, central);
                let mut zip = ZipArchive::new(Cursor::new(&bytes)).unwrap();
                if !local.is_empty() && !central.is_empty() {
                    zip.validate_header_consistency().unwrap();
                }
                let error =
                    archive::read(bytes).err().expect("ambiguous extra field unexpectedly accepted").to_string();
                assert!(error.contains("UnicodePath"), "entry {index}: {error}");
            }
        }
    }
}
