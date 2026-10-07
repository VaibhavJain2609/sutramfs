//! Crash-only fuzz target: feed arbitrary bytes through the whole
//! partition-layer pipeline — analyze(), LP metadata, sparse decode,
//! vbmeta and crypt_ftr detection. No assertions beyond "must not panic /
//! hang / OOB"; the oracle is the absence of crashes on hostile input.
//!
//! Run with:  cargo +nightly fuzz run parse_image -- -max_total_time=300

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let src = sutram_io::into_arc(data.to_vec());
    // The single-call entry point exercises every layer.
    if let Ok(layout) = sutram_part::analyze(src.clone()) {
        // Bounded reads through the decoded partition views.
        for p in layout.partitions.iter().take(64) {
            let mut buf = [0u8; 4096];
            let _ = p.source.read_at(0, &mut buf);
        }
    }
    // The lower-level decoders see the raw bytes too.
    let _ = sutram_part::read_geometry(src.as_ref());
    let _ = sutram_part::read_metadata(src.as_ref());
    let _ = sutram_part::inspect_sparse(src.clone());
    let _ = sutram_part::find_vbmeta(src.as_ref());
    let _ = sutram_part::fbe::find_crypt_footer(src.as_ref());
});
