use learntok_protocol_frozen::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
fn record<T: serde::Serialize>(name: &str, format: &str, raw: Value, pack: T) -> Value {
    let bytes = serde_json::to_vec(&pack).unwrap();
    let hash = |tts| format!("{:x}", Sha256::digest(serde_json::to_vec(&(format, &pack, tts)).unwrap()));
    json!({"name":name,"format":format,"input":raw,"serialized":String::from_utf8(bytes).unwrap(),"fingerprint":hash(false),"fingerprint_auto_tts":hash(true)})
}
fn main() {
    let root = std::env::args().nth(1).unwrap();
    let read = |name| {
        serde_json::from_slice::<Value>(
            &std::fs::read(format!("{root}/compatibility/history/2.13.0/protocol/fixtures/{name}.json")).unwrap(),
        )
        .unwrap()
    };
    let mut out = vec![];
    for (format, fixture) in [("deckpack", "deck-pack"), ("portable-deckpack", "portable-deck-pack")] {
        for shape in ["fixture", "text", "empty", "defaults"] {
            let mut raw = read(fixture);
            let pack = if format == "deckpack" { &mut raw } else { &mut raw["content"] };
            if shape != "fixture" {
                for card in pack["cards"].as_array_mut().unwrap() {
                    card.as_object_mut().unwrap().remove("tts");
                    card.as_object_mut().unwrap().remove("bgm");
                    card["visual"].as_object_mut().unwrap().remove("image");
                    card["front"] = json!({"title":"Legacy question","blocks":[{"type":"text","text":"Legacy body"}]});
                    card["back"] = json!({"title":"Legacy answer","blocks":[]});
                }
                if shape == "empty" {
                    pack["cards"] = json!([]);
                    pack["deck"]["card_count"] = json!(0);
                }
                if shape == "defaults" {
                    for name in ["description", "tags"] {
                        pack["deck"].as_object_mut().unwrap().remove(name);
                    }
                }
            }
            if format == "portable-deckpack" && shape != "fixture" {
                raw["media"] = json!([]);
            }
            let name = format!("{fixture}-{shape}");
            out.push(if format == "deckpack" {
                record(&name, format, raw.clone(), serde_json::from_value::<DeckPack>(raw).unwrap())
            } else {
                record(&name, format, raw.clone(), serde_json::from_value::<PortableDeckPack>(raw).unwrap())
            });
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"baseline":"bae52d24295975cee128bef91ab80a33efdef9ce","protocol":"2.13.0","cases":out})
        )
        .unwrap()
    );
}
