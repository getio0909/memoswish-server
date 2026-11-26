#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    static RUNTIME: std::sync::LazyLock<tokio::runtime::Runtime> =
        std::sync::LazyLock::new(|| tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap());
    let result = RUNTIME.block_on(memoswish_content::apkg::fuzz_prepare(data));
    if data == include_bytes!("../corpus/apkg/basic.apkg") {
        assert!(result.is_ok(), "valid APKG seed must reach conversion: {result:?}");
    }
});
