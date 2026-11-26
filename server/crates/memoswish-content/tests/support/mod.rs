//! 在测试期间生成 SQLite 集合与 ZIP 包，不依赖二进制夹具。

use serde_json::json;
use sqlx::{Connection, SqliteConnection};
use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;

pub async fn database(kind: &str, fields: &str, ordinals: &[i64]) -> Vec<u8> {
    let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
    sqlx::raw_sql(
        "CREATE TABLE col (models TEXT, decks TEXT);
        CREATE TABLE notes (id INTEGER PRIMARY KEY, mid INTEGER, guid TEXT, tags TEXT, flds TEXT);
        CREATE TABLE cards (id INTEGER PRIMARY KEY, nid INTEGER, did INTEGER, odid INTEGER, ord INTEGER);",
    )
    .execute(&mut conn)
    .await
    .unwrap();
    let (number, templates) = match kind {
        "cloze" => (1, json!([{"ord":0,"qfmt":"{{cloze:正面}}","afmt":"{{cloze:正面}}<br>{{背面}}"}])),
        "reversed" => (
            0,
            json!([
            {"ord":0,"qfmt":"{{正面}}","afmt":"{{FrontSide}}<hr>{{背面}}"},
            {"ord":1,"qfmt":"{{背面}}","afmt":"{{正面}}"}]),
        ),
        "conditional" => (0, json!([{"ord":0,"qfmt":"{{#正面}}{{正面}}{{/正面}}","afmt":"{{背面}}"}])),
        _ => (0, json!([{"ord":0,"qfmt":"{{正面}}","afmt":"{{FrontSide}}<hr>{{背面}}"}])),
    };
    let models = json!({"10":{"name":kind,"type":number,
        "flds":[{"name":"正面","ord":0},{"name":"背面","ord":1}],"tmpls":templates}});
    sqlx::query("INSERT INTO col VALUES (?, ?)")
        .bind(models.to_string())
        .bind(json!({"1":{"name":"Biology::Cells"}}).to_string())
        .execute(&mut conn)
        .await
        .unwrap();
    sqlx::query("INSERT INTO notes VALUES (100, 10, 'guid-100', ' biology::cells test test ', ?)")
        .bind(fields)
        .execute(&mut conn)
        .await
        .unwrap();
    for (i, ord) in ordinals.iter().enumerate() {
        sqlx::query("INSERT INTO cards VALUES (?,100,1,0,?)")
            .bind(200 + i as i64)
            .bind(ord)
            .execute(&mut conn)
            .await
            .unwrap();
    }
    conn.serialize(None).await.unwrap().to_vec()
}

pub fn zip(entries: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in entries {
        zip.start_file(name, SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated))
            .unwrap();
        zip.write_all(&bytes).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

pub async fn basic() -> Vec<u8> {
    zip(vec![("collection.anki2", database("basic", "Question\x1fAnswer", &[0]).await), ("media", b"{}".to_vec())])
}
