#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok((text, duration, words)) =
        serde_json::from_slice::<(String, u32, Vec<memoswish_protocol::WordTimestamp>)>(data)
    {
        let _ = memoswish_media::tts::validate_timestamps(&text, &words, duration);
    }
});
