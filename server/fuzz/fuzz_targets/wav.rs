#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(info) = memoswish_media::wav::pcm_info(data) {
        assert!(info.frames > 0 && info.frames <= info.sample_rate * 300);
        if info.frames <= 4096 {
            let (clipped, actual) = memoswish_media::wav::clip_pcm(data, 0, info.frames).unwrap();
            assert_eq!(memoswish_media::wav::pcm_info(&clipped).unwrap().frames, actual.frames);
        }
    }
});
