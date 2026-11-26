//! 指纹参考来自基线 2.13 Rust 模型和原始 SHA-256 元组算法，不能由当前模型重建期望。
use memoswish_content::imports::fingerprint;
use memoswish_protocol::{DeckPack, PortableDeckPack};

#[test]
fn legacy_shapes_match_frozen_213_serialization_and_fingerprints() {
    let reference: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/legacy-identities-213.json")).unwrap();
    assert_eq!(reference["baseline"], "bae52d24295975cee128bef91ab80a33efdef9ce");
    assert_eq!(reference["cases"].as_array().unwrap().len(), 8);
    for case in reference["cases"].as_array().unwrap() {
        let format = case["format"].as_str().unwrap();
        for null_revision in [false, true] {
            let mut input = case["input"].clone();
            if null_revision {
                let content = if format == "deckpack" { &mut input } else { &mut input["content"] };
                content["deck"]["revision"] = serde_json::Value::Null;
            }
            let (bytes, plain, tts) = if format == "deckpack" {
                let pack: DeckPack = serde_json::from_value(input).unwrap();
                (
                    serde_json::to_string(&pack).unwrap(),
                    fingerprint(format, &pack, false).unwrap(),
                    fingerprint(format, &pack, true).unwrap(),
                )
            } else {
                let pack: PortableDeckPack = serde_json::from_value(input).unwrap();
                (
                    serde_json::to_string(&pack).unwrap(),
                    fingerprint(format, &pack, false).unwrap(),
                    fingerprint(format, &pack, true).unwrap(),
                )
            };
            assert_eq!(bytes, case["serialized"].as_str().unwrap(), "{}", case["name"]);
            assert_eq!(plain, case["fingerprint"], "{}", case["name"]);
            assert_eq!(tts, case["fingerprint_auto_tts"], "{}", case["name"]);
            assert_ne!(plain, tts);
        }
    }
}
