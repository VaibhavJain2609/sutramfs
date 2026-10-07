// Debug probe: mount a device and dump slot state for record numbers.
// Usage: probe <image> <recno> [recno...]
use std::sync::Arc;
use sutram_fs::ByteSource;

fn main() {
    let mut a = std::env::args().skip(1);
    let img = a.next().expect("image path");
    let recnos: Vec<u64> = a.map(|s| s.parse().unwrap()).collect();

    let src: Arc<dyn ByteSource> =
        Arc::new(sutram_io::FileSource::open(&img).expect("open"));
    let fs = sutram_ntfs::NtfsFs::mount(src, sutram_fs::MountOptions::default())
        .expect("mount");
    eprintln!("mounted: {} slots", fs.slot_count());
    for rn in recnos {
        eprintln!("rec {} -> {}", rn, fs.debug_slot(rn));
        eprintln!("{}", fs.debug_attrs(rn));
    }
}
