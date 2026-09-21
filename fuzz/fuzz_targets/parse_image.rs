//! Crash-only fuzz target: feed arbitrary bytes through the full parser
//! pipeline — detect() → mount() → walk() → read_file(). No assertions
//! beyond "must not panic / hang / OOB"; the interesting oracle is the
//! absence of crashes on hostile input.
//!
//! Run with:  cargo +nightly fuzz run parse_image -- -max_total_time=300

#![no_main]

use libfuzzer_sys::fuzz_target;
use sutram_fs::FsParser;
use sutram_io::ByteSource;

/// Cap on walk/read work per input so a degenerate image can't burn the
/// whole budget in one case.
const MAX_ENTRIES: usize = 2048;

fuzz_target!(|data: &[u8]| {
    let src = sutram_io::into_arc(data.to_vec());
    let parser = sutram_f2fs::F2fsParser;
    let _ = parser.detect(src.as_ref() as &dyn ByteSource);
    if let Ok(fs) = parser.mount(src) {
        let _ = fs.info();
        let _ = fs.unallocated_ranges();
        for item in fs.walk().take(MAX_ENTRIES) {
            if let Ok(e) = item {
                if let Ok(mut r) = fs.read_file(&e) {
                    let _ = std::io::copy(&mut r, &mut std::io::sink());
                }
                let _ = e;
            }
        }
    }
});
