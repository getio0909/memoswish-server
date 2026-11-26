#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(wire) = serde_json::from_slice::<serde_json::Value>(data) {
        let result = memoswish_content::deckpack::validate_input(&wire);
        if data == include_bytes!("../corpus/json/portable.json") {
            assert!(result.is_ok());
        }
    }
    let result = memoswish_media::tts::http::parse_response(data, "Hello world", "application/json");
    if data == include_bytes!("../corpus/json/speech.json") {
        assert!(result.is_ok());
    }
});
