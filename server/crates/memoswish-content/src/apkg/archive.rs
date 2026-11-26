//! 有界 ZIP 读取与旧版包格式选择。

use std::collections::{BTreeMap, HashSet};
use std::io::{Cursor, Read};

use memoswish_core::{CoreError, CoreResult};
use prost::Message;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use zip::{CompressionMethod, ZipArchive};

use super::{ApkgLimits, invalid};

pub const MODERN: &str = "This Anki package uses an unsupported modern format. Re-export it from Anki with \"Support older Anki versions\" enabled, then import the exported .apkg file.";

#[derive(Message)]
struct Metadata {
    #[prost(int32, tag = "1")]
    version: i32,
}

pub struct Package {
    pub database: Vec<u8>,
    pub media: BTreeMap<String, Vec<u8>>,
}

// 保留重复键检测，避免 serde_json 默认覆盖导致媒体映射歧义。
struct Manifest(BTreeMap<String, String>);

impl<'de> Deserialize<'de> for Manifest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MapVisitor;
        impl<'de> Visitor<'de> for MapVisitor {
            type Value = Manifest;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a unique numeric media map")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut access: M) -> Result<Self::Value, M::Error> {
                let mut map = BTreeMap::new();
                let mut names = HashSet::new();
                while let Some((key, value)) = access.next_entry::<String, String>()? {
                    if !numeric(&key)
                        || value.is_empty()
                        || value.len() > 1024
                        || map.contains_key(&key)
                        || !names.insert(value.clone())
                    {
                        return Err(serde::de::Error::custom("invalid or duplicate media mapping"));
                    }
                    map.insert(key, value);
                }
                Ok(Manifest(map))
            }
        }
        deserializer.deserialize_map(MapVisitor)
    }
}

fn numeric(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 10
        && name.bytes().all(|b| b.is_ascii_digit())
        && (name == "0" || !name.starts_with('0'))
}

// zip 会在内部按名称覆盖重复条目，因此先检查有界的普通 ZIP 中央目录。
// 中央目录只支持普通 EOCD，不支持 ZIP64 EOCD 或分卷；小条目仍可使用 ZIP64 大小字段。
fn directory(bytes: &[u8]) -> CoreResult<(usize, usize)> {
    let malformed = || CoreError::invalid("invalid APKG ZIP directory; ZIP64 and split archives are unsupported");
    let end = (bytes.len().saturating_sub(65_557)..bytes.len().saturating_sub(21))
        .rev()
        .find(|&i| {
            bytes.get(i..i + 4) == Some(b"PK\x05\x06")
                && i + 22 + u16::from_le_bytes([bytes[i + 20], bytes[i + 21]]) as usize == bytes.len()
        })
        .ok_or_else(malformed)?;
    let u16_at = |i| u16::from_le_bytes([bytes[end + i], bytes[end + i + 1]]) as usize;
    let u32_at = |i| u32::from_le_bytes(bytes[end + i..end + i + 4].try_into().unwrap()) as usize;
    let count = u16_at(10);
    let start = u32_at(16);
    if u16_at(4) != 0
        || u16_at(6) != 0
        || u16_at(8) != count
        || count > ApkgLimits::ENTRIES
        || start.checked_add(u32_at(12)) != Some(end)
    {
        return Err(malformed());
    }
    let mut offset = start;
    let mut names = HashSet::new();
    for _ in 0..count {
        crate::processing::checkpoint(1)?;
        let header = bytes.get(offset..offset.checked_add(46).ok_or_else(malformed)?).ok_or_else(malformed)?;
        if &header[..4] != b"PK\x01\x02" {
            return Err(malformed());
        }
        let name_len = u16::from_le_bytes([header[28], header[29]]) as usize;
        let extra_len = u16::from_le_bytes([header[30], header[31]]) as usize;
        let comment_len = u16::from_le_bytes([header[32], header[33]]) as usize;
        let name_start = offset + 46;
        let name = bytes.get(name_start..name_start + name_len).ok_or_else(malformed)?;
        if name_len > 64 || !names.insert(name) {
            return Err(CoreError::invalid("duplicate or oversized ZIP entry name"));
        }
        offset = name_start + name_len + extra_len + comment_len;
        if offset > end {
            return Err(malformed());
        }
    }
    if offset != end {
        return Err(malformed());
    }
    Ok((count, start))
}

// 上游会先应用 UnicodePath 再比较名称，必须从归档字节单独核对原始名称。
fn raw_names<R: Read>(bytes: &[u8], entry: &zip::read::ZipFile<'_, R>, directory_start: usize) -> CoreResult<()> {
    let malformed = || CoreError::invalid("ZIP header inconsistency: raw filename or extra field");
    let local = usize::try_from(entry.header_start()).map_err(|_| malformed())?;
    let central = usize::try_from(entry.central_header_start()).map_err(|_| malformed())?;
    let local = bytes[..directory_start].get(local..).ok_or_else(malformed)?;
    let central = bytes
        .get(directory_start..)
        .and_then(|tail| tail.get(central.checked_sub(directory_start)?..))
        .ok_or_else(malformed)?;
    let fields = |tail: &[u8], fixed: usize, lengths: usize| -> CoreResult<(usize, usize)> {
        let header = tail.get(..fixed).ok_or_else(malformed)?;
        Ok((
            u16::from_le_bytes(header[lengths..lengths + 2].try_into().unwrap()) as usize,
            u16::from_le_bytes(header[lengths + 2..lengths + 4].try_into().unwrap()) as usize,
        ))
    };
    let (local_name_len, local_extra_len) = fields(local, 30, 26)?;
    let (central_name_len, central_extra_len) = fields(central, 46, 28)?;
    if !local.starts_with(b"PK\x03\x04") || !central.starts_with(b"PK\x01\x02") {
        return Err(malformed());
    }
    let local_name = local.get(30..30 + local_name_len).ok_or_else(malformed)?;
    let central_name = central.get(46..46 + central_name_len).ok_or_else(malformed)?;
    if local_name != central_name {
        return Err(malformed());
    }
    for (tail, start, len) in
        [(local, 30 + local_name_len, local_extra_len), (central, 46 + central_name_len, central_extra_len)]
    {
        let mut extra = tail.get(start..start + len).ok_or_else(malformed)?;
        while !extra.is_empty() {
            let header = extra.get(..4).ok_or_else(malformed)?;
            let len = u16::from_le_bytes(header[2..4].try_into().unwrap()) as usize;
            let field = extra.get(4..4 + len).ok_or_else(malformed)?;
            // zip 9.0.5 只有 0x7075 会改写文件名；逐个检查，包括重复及 CRC 不匹配的字段。
            if header[..2] == [0x75, 0x70]
                && (field.first() != Some(&1)
                    || field.get(5..) != Some(local_name)
                    || std::str::from_utf8(field.get(5..).ok_or_else(malformed)?).is_err())
            {
                return Err(CoreError::invalid("ZIP UnicodePath extra field must match the raw filename"));
            }
            extra = &extra[4 + len..];
        }
    }
    Ok(())
}

// 上游 descriptor API 只接受带签名格式；这里按中央值构造有界字节串，同时支持无签名格式。
// ZIP64 扩展可只出现在本地头，因此不能仅按中央大小或中央扩展决定字段宽度。
fn descriptor_end<R: Read>(bytes: &[u8], entry: &zip::read::ZipFile<'_, R>, payload_end: usize) -> CoreResult<usize> {
    let malformed = || CoreError::invalid("missing, truncated or inconsistent ZIP data descriptor");
    let local = usize::try_from(entry.header_start()).map_err(|_| malformed())?;
    let header = bytes.get(local..local + 30).ok_or_else(malformed)?;
    let name_len = u16::from_le_bytes(header[26..28].try_into().unwrap()) as usize;
    let extra_len = u16::from_le_bytes(header[28..30].try_into().unwrap()) as usize;
    let extra_start = local + 30 + name_len;
    let mut extra = bytes.get(extra_start..extra_start + extra_len).ok_or_else(malformed)?;
    let mut zip64 = entry.compressed_size() >= u32::MAX as u64
        || entry.size() >= u32::MAX as u64
        || entry.extra_data_fields().any(|field| matches!(field, zip::ExtraField::Zip64ExtendedInformation(_)));
    while !extra.is_empty() {
        let field = extra.get(..4).ok_or_else(malformed)?;
        let len = u16::from_le_bytes(field[2..4].try_into().unwrap()) as usize;
        zip64 |= field[..2] == [1, 0];
        extra = extra.get(4 + len..).ok_or_else(malformed)?;
    }
    let mut expected = Vec::with_capacity(20);
    expected.extend_from_slice(&entry.crc32().to_le_bytes());
    if zip64 {
        expected.extend_from_slice(&entry.compressed_size().to_le_bytes());
        expected.extend_from_slice(&entry.size().to_le_bytes());
    } else {
        expected.extend_from_slice(&(entry.compressed_size() as u32).to_le_bytes());
        expected.extend_from_slice(&(entry.size() as u32).to_le_bytes());
    }
    let tail = bytes.get(payload_end..).ok_or_else(malformed)?;
    // 先匹配完整带签名形式，再匹配无签名形式；CRC 本身等于签名时仍可正确读取。
    let signature_len = if tail.starts_with(b"PK\x07\x08") && tail[4..].starts_with(&expected) { 4 } else { 0 };
    if !tail[signature_len..].starts_with(&expected) {
        return Err(malformed());
    }
    Ok(payload_end + signature_len + expected.len())
}

pub fn read(bytes: Vec<u8>) -> CoreResult<Package> {
    if bytes.len() > ApkgLimits::ARCHIVE {
        return Err(CoreError::invalid("APKG upload exceeds 10 MiB"));
    }
    let archive_size = bytes.len() as u64;
    let (count, directory_start) = directory(&bytes)?;
    let mut zip = ZipArchive::new(Cursor::new(bytes.as_slice())).map_err(invalid)?;
    if zip.len() != count || zip.central_directory_start() != directory_start as u64 || zip.offset() != 0 {
        return Err(CoreError::invalid("duplicate, overlapping or inconsistent ZIP entries"));
    }
    if zip.len() > ApkgLimits::ENTRIES {
        return Err(CoreError::invalid("APKG has more than 4096 ZIP entries"));
    }
    // 在读取任何载荷前核对全部本地头与中央目录，拒绝 ZIP 伪装及双头歧义。
    zip.validate_header_consistency().map_err(invalid)?;
    let mut names = HashSet::new();
    let mut total = 0u64;
    let mut ranges = Vec::with_capacity(count);
    for i in 0..zip.len() {
        crate::processing::checkpoint(1)?;
        let entry = zip.by_index(i).map_err(invalid)?;
        raw_names(&bytes, &entry, directory_start)?;
        if entry.compressed_size() > archive_size
            || entry
                .data_start()
                .and_then(|start| start.checked_add(entry.compressed_size()))
                .is_none_or(|end| end > directory_start as u64)
        {
            return Err(CoreError::invalid("ZIP entry data extends beyond the archive payload"));
        }
        let payload_end = (entry.data_start().unwrap() + entry.compressed_size()) as usize;
        let end = if entry.flags().is_using_data_descriptor() {
            descriptor_end(&bytes[..directory_start], &entry, payload_end)?
        } else {
            payload_end
        };
        ranges.push(entry.header_start()..end as u64);
        let name = entry.name().map_err(invalid)?;
        let name = name.as_ref();
        if name.is_empty()
            || name.len() > 64
            || name.contains(['/', '\\', ':', '\0'])
            || name == "."
            || name == ".."
            || !names.insert(name.to_string())
            || entry.is_dir()
            || entry.encrypted()
            || entry.unix_mode().is_some_and(|m| m & 0o170000 != 0 && m & 0o170000 != 0o100000)
            || !matches!(entry.compression(), CompressionMethod::Stored | CompressionMethod::Deflated)
        {
            return Err(CoreError::invalid("unsafe, duplicate, encrypted or unsupported ZIP entry"));
        }
        if name == "collection.anki21b" {
            return Err(CoreError::invalid(MODERN));
        }
        // 显式拒绝 SQLite 旁路文件；后续仍仅在内存中读取白名单条目。
        if ["-wal", "-shm", "-journal"].iter().any(|suffix| name.to_ascii_lowercase().ends_with(suffix)) {
            return Err(CoreError::invalid("SQLite sidecar entries are unsupported"));
        }
        let limit = match name {
            "collection.anki2" | "collection.anki21" | "collection.anki21b" => ApkgLimits::DATABASE,
            "media" => ApkgLimits::MANIFEST,
            "meta" => 4096,
            _ if numeric(name) => ApkgLimits::MEDIA,
            _ => return Err(CoreError::invalid("unexpected APKG entry name")),
        };
        total = total.checked_add(entry.size()).ok_or_else(|| CoreError::invalid("ZIP size overflow"))?;
        if entry.size() > limit as u64 || total > ApkgLimits::EXPANDED as u64 {
            return Err(CoreError::invalid("APKG expanded data or entry exceeds size limit"));
        }
    }
    ranges.sort_unstable_by_key(|range| range.start);
    if ranges.windows(2).any(|pair| pair[0].end > pair[1].start) || zip.has_overlapping_files().map_err(invalid)? {
        return Err(CoreError::invalid("overlapping ZIP entries"));
    }
    let mut entries = BTreeMap::new();
    let mut actual = 0usize;
    for i in 0..zip.len() {
        crate::processing::checkpoint(1)?;
        let mut entry = zip.by_index(i).map_err(invalid)?;
        let mut bytes = Vec::new();
        let advertised = entry.size() as usize;
        let mut limited = (&mut entry).take(advertised as u64 + 1);
        loop {
            crate::processing::checkpoint(0)?;
            let mut chunk = [0; 64 * 1024];
            let n = limited.read(&mut chunk).map_err(invalid)?;
            if n == 0 {
                break;
            }
            crate::processing::checkpoint(n)?;
            bytes.extend_from_slice(&chunk[..n]);
        }
        actual += bytes.len();
        if bytes.len() != advertised || actual > ApkgLimits::EXPANDED {
            return Err(CoreError::invalid("APKG expanded size mismatch"));
        }
        entries.insert(entry.name().map_err(invalid)?.into_owned(), bytes);
    }
    let selected = if let Some(meta) = entries.get("meta") {
        match Metadata::decode(meta.as_slice()).map_err(invalid)?.version {
            1 => "collection.anki2",
            2 => "collection.anki21",
            _ => return Err(CoreError::invalid(MODERN)),
        }
    } else if entries.contains_key("collection.anki21") {
        "collection.anki21"
    } else {
        "collection.anki2"
    };
    let database = entries.remove(selected).ok_or_else(|| CoreError::invalid("missing authoritative collection"))?;
    let manifest = entries.remove("media").ok_or_else(|| CoreError::invalid("missing JSON media map"))?;
    if manifest.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Err(CoreError::invalid(MODERN));
    }
    let manifest: Manifest = serde_json::from_slice(&manifest).map_err(invalid)?;
    let mut media = BTreeMap::new();
    for (index, filename) in manifest.0 {
        let bytes =
            entries.remove(&index).ok_or_else(|| CoreError::invalid("media map references missing ZIP entry"))?;
        media.insert(filename, bytes);
    }
    Ok(Package { database, media })
}
