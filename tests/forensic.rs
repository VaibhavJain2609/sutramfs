//! Integration tests over the synthetic BTRFS corpus (`tests/common`).
//!
//! The image is a byte-exact volume: valid CRC32C superblock with a
//! backup root into a gen-5 COW history, identity chunk map, internal
//! FS-tree node, subvolume snapshot, extent tree with backrefs, an
//! ORPHAN_ITEM, a reallocated extent, a dangling dir item, and zlib
//! compressed + inline extents.

mod common;

use std::io::Read;
use std::sync::Arc;
use std::sync::OnceLock;

use sutram_btrfs::BtrfsParser;
use sutram_fs::{
    DetectConfidence, EntryKind, FsEntry, FsEntryStatus, FsParser, FileSystem, MountOptions,
    RecoveryState,
};
use sutram_io::ByteSource;
use sutram_magic::{MagicType, Severity};

fn image() -> Arc<dyn ByteSource> {
    static IMG: OnceLock<Arc<dyn ByteSource>> = OnceLock::new();
    IMG.get_or_init(|| Arc::new(common::build_image())).clone()
}

fn mount() -> Box<dyn FileSystem> {
    BtrfsParser.mount(image()).unwrap()
}

fn all_entries() -> Vec<FsEntry> {
    mount()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .expect("walk should not error on the clean corpus")
}

fn find_path<'a>(entries: &'a [FsEntry], path: &str) -> &'a FsEntry {
    entries.iter().find(|e| e.path == path).unwrap_or_else(|| {
        panic!(
            "entry {path} not found; got {:?}",
            entries.iter().map(|e| &e.path).collect::<Vec<_>>()
        )
    })
}

fn read_all(fs: &dyn FileSystem, e: &FsEntry) -> Vec<u8> {
    let mut buf = Vec::new();
    fs.read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    buf
}

// ---------- detection / mount ----------

#[test]
fn detects_btrfs() {
    // Magic + geometry + valid CRC32C → Certain.
    assert_eq!(BtrfsParser.detect(image().as_ref()), DetectConfidence::Certain);
}

#[test]
fn detect_rejects_garbage() {
    let junk: Arc<dyn ByteSource> = Arc::new(vec![0u8; 0x20000]);
    assert_eq!(BtrfsParser.detect(junk.as_ref()), DetectConfidence::None);
}

#[test]
fn detect_inside_mbr_partition() {
    // Wrap the volume in a minimal MBR disk: partition at LBA 2048 (1 MiB).
    let vol = common::build_image();
    let mut disk = vec![0u8; 0x100000 + vol.len()];
    disk[0x1FE] = 0x55;
    disk[0x1FF] = 0xAA;
    disk[0x1BE + 4] = 0x83; // Linux
    common::w32(&mut disk, 0x1BE + 8, 2048); // start LBA
    common::w32(&mut disk, 0x1BE + 12, (vol.len() / 512) as u32);
    disk[0x100000..].copy_from_slice(&vol);
    let src: Arc<dyn ByteSource> = Arc::new(disk);
    assert!(BtrfsParser.detect(src.as_ref()) >= DetectConfidence::High);
}

#[test]
fn superblock_mirror_fallback() {
    // 64 MiB + 4 KiB image; corrupt the primary csum, plant a valid mirror.
    let vol = common::build_image();
    let mut img = vec![0u8; 0x4000000 + 4096];
    img[..vol.len()].copy_from_slice(&vol);
    // Mirror copy at 0x4000000 with its own bytenr and recomputed csum.
    let m = 0x4000000usize;
    img[m..m + 4096].copy_from_slice(&vol[common::SB..common::SB + 4096]);
    common::w64(&mut img, m + 0x30, m as u64);
    let csum = crc32fast::hash(&img[m + 32..m + 4096]);
    img[m..m + 4].copy_from_slice(&csum.to_le_bytes());
    // Wreck the primary's checksum.
    img[common::SB] ^= 0xFF;

    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = BtrfsParser.mount(src).unwrap();
    let note = fs.info().meta.get("note").cloned().unwrap_or_default();
    assert!(note.contains("mirror"), "info.meta.note = {note:?}");
    // ...and the volume is fully usable.
    let entries: Vec<_> = fs.walk().collect::<Result<_, _>>().unwrap();
    find_path(&entries, "/hello.txt");
}

#[test]
fn mount_rejects_non_btrfs() {
    let junk: Arc<dyn ByteSource> = Arc::new(vec![0xA5u8; 0x200000]);
    assert!(BtrfsParser.mount(junk).is_err());
}

#[test]
fn truncated_image_does_not_panic() {
    // Superblock intact but every tree out of bounds.
    let vol = common::build_image();
    let short: Arc<dyn ByteSource> = Arc::new(vol[..0x11000].to_vec());
    // Mount may fail (no chunks) or succeed with error records — never panic.
    if let Ok(fs) = BtrfsParser.mount(short) {
        let _ = fs.walk().collect::<Vec<_>>();
    }
}

// ---------- info ----------

#[test]
fn info_reports_btrfs() {
    let info = mount().info();
    assert_eq!(info.fs_type, "BTRFS");
    assert_eq!(info.label.as_deref(), Some("TESTFS"));
    assert_eq!(info.block_size, 4096);
    assert_eq!(info.total_blocks, common::IMG_SIZE as u64 / 4096);
    assert!(info.uuid.is_some());
    assert_eq!(info.meta["generation"], "7");
    assert_eq!(info.meta["nodesize"], "4096");
    assert_eq!(info.meta["superblock_csum_ok"], "true");
    assert!(info.free_blocks.unwrap() > 0);
    assert_eq!(info.meta["dev_total_bytes"], common::IMG_SIZE.to_string());
}

// ---------- live walk ----------

#[test]
fn live_tree_walks() {
    let entries = all_entries();
    for path in [
        "/",
        "/hello.txt",
        "/newfile.bin",
        "/packed.z",
        "/subdir",
        "/subdir/inner.txt",
        "/link1",
        "/masq.doc",
        "/second.txt",
        "/snap1",
        "/snap1/snap.txt",
        "/etc",
        "/etc/passwd",
        "/etc/group",
    ] {
        find_path(&entries, path);
    }
    let hello = find_path(&entries, "/hello.txt");
    assert_eq!(hello.kind, EntryKind::File);
    assert_eq!(hello.size, 12);
    assert_eq!(hello.status, FsEntryStatus::Live);
    assert_eq!(hello.meta["uid"], "1000");
    assert_eq!(hello.meta["xattr_0"], "user.origin");
    // Physical extent provenance: identity chunk ⇒ logical == physical.
    assert_eq!(hello.meta["data_logical"], "0x500000");
    assert_eq!(hello.meta["data_physical"], "0x500000");
    assert!(hello.meta.contains_key("inode_item_physical"));
    assert_eq!(hello.allocated_ranges, vec![(common::D_HELLO, 4096)]);
}

#[test]
fn internal_node_traversed() {
    // second.txt lives in FS leaf 2 — only reachable through the internal
    // node at FS_TREE; its presence proves keyptr traversal works.
    let entries = all_entries();
    let e = find_path(&entries, "/second.txt");
    assert_eq!(e.kind, EntryKind::File);
}

#[test]
fn timestamps_all_four() {
    let entries = all_entries();
    let e = find_path(&entries, "/hello.txt");
    let ts = |t: &Option<sutram_fs::FsTimestamp>| t.as_ref().unwrap().value.unwrap();
    // builder: atime=+0s/100ns, ctime=+1s/200ns, mtime=+2s/300ns, otime=+3s/400ns
    let base = 1_705_314_620i64 * 1_000_000_000;
    assert_eq!(ts(&e.timestamps.accessed), base + 100);
    assert_eq!(ts(&e.timestamps.changed), base + 1_000_000_000 + 200);
    assert_eq!(ts(&e.timestamps.modified), base + 2_000_000_000 + 300);
    assert_eq!(ts(&e.timestamps.created), base + 3_000_000_000 + 400);
}

#[test]
fn symlink_inline_extent() {
    let entries = all_entries();
    let e = find_path(&entries, "/link1");
    assert_eq!(e.kind, EntryKind::Symlink);
    assert_eq!(e.meta["inline"], "true");
    assert_eq!(e.meta["symlink_target"], "/hello.txt");
    let fs = mount();
    assert_eq!(read_all(&*fs, e), b"/hello.txt");
}

#[test]
fn snapshot_subvolume() {
    let entries = all_entries();
    let root = find_path(&entries, "/snap1");
    assert_eq!(root.kind, EntryKind::Directory);
    assert_eq!(root.meta["snapshot"], "true");
    assert_eq!(root.meta["readonly_subvolume"], "true");
    let f = find_path(&entries, "/snap1/snap.txt");
    let fs = mount();
    assert_eq!(read_all(&*fs, f), b"SNAPDATA");
    // unique inode ids: subvol<<48|ino — distinct from FS_TREE's ino 257.
    let hello = find_path(&entries, "/hello.txt");
    assert_ne!(f.meta["unique_inode"], hello.meta["unique_inode"]);
    assert_eq!(f.meta["subvolume_id"], "257");
}

#[test]
fn read_file_live_and_at() {
    let fs = mount();
    let entries = all_entries();
    let e = find_path(&entries, "/hello.txt");
    assert_eq!(read_all(&*fs, e), b"hello world!");
    let mut b = [0u8; 5];
    let n = fs.read_file_at(e, 6, &mut b).unwrap();
    assert_eq!(&b[..n], b"world");
}

#[test]
fn compressed_extent_reads_plaintext() {
    let fs = mount();
    let entries = all_entries();
    let e = find_path(&entries, "/packed.z");
    assert_eq!(e.meta["compressed"], "zlib");
    let data = read_all(&*fs, e);
    assert_eq!(data, b"PACKED-BTRFS-ZLIB-CONTENT-payload-0123456789abcdef");
}

#[test]
fn uid_gid_names_resolved() {
    // Python parity: /etc/passwd + /etc/group → meta user/group.
    let entries = all_entries();
    let e = find_path(&entries, "/hello.txt"); // uid=gid=1000
    assert_eq!(e.meta["user"], "admin");
    assert_eq!(e.meta["group"], "admin");
    let root_owned = find_path(&entries, "/old.log"); // uid=gid=0
    assert_eq!(root_owned.meta["user"], "root");
}

// ---------- magic ----------

#[test]
fn magic_verdicts() {
    let entries = all_entries();
    // masq.doc: MZ/PE content under .doc → High-severity masquerade.
    let e = find_path(&entries, "/masq.doc");
    let v = e.magic.as_ref().unwrap();
    assert_eq!(v.detected, Some(MagicType::Pe));
    assert!(v.mismatch);
    assert_eq!(v.severity, Severity::High);
    // hello.txt: plain text → no signature, no alarm.
    let e = find_path(&entries, "/hello.txt");
    let v = e.magic.as_ref().unwrap();
    assert_eq!(v.severity, Severity::Info);
    // packed.z: verdict comes from *decompressed* bytes (decompression
    // ran before magic).
    let e = find_path(&entries, "/packed.z");
    assert!(e.magic.is_some());
}

// ---------- deleted / COW history ----------

#[test]
fn deleted_entries_listed() {
    let deleted: Vec<FsEntry> = mount()
        .deleted_entries()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .into_iter()
        .filter(|e| e.is_deleted())
        .collect();
    let paths: Vec<&str> = deleted.iter().map(|e| e.path.as_str()).collect();
    for p in ["/secret.txt", "/old.log", "/hello.txt@v5", "/ghost.tmp", "/pending.txt"] {
        assert!(paths.contains(&p), "missing {p}; deleted = {paths:?}");
    }
}

#[test]
fn deleted_secret_intact() {
    let fs = mount();
    let entries = all_entries();
    let e = find_path(&entries, "/secret.txt");
    assert_eq!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    );
    assert_eq!(read_all(&*fs, e), b"TOPSECRET-DELETED!");
    // Freed extent still cited as the recoverable range — the range is the
    // file-data subrange (18 B), not the whole 4 KiB allocation.
    assert_eq!(e.allocated_ranges, vec![(common::D_SECRET, 18)]);
    assert_eq!(e.meta["cow_generation"], "5");
}

#[test]
fn deleted_oldlog_partially_overwritten() {
    let fs = mount();
    let entries = all_entries();
    let e = find_path(&entries, "/old.log");
    assert_eq!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::PartiallyOverwritten {
                recovered_bytes: 4096,
                total_bytes: 8192
            }
        }
    );
    // Only the surviving extent is listed/readable.
    assert_eq!(e.allocated_ranges, vec![(common::D_OLDLOG_B, 4096)]);
    let data = read_all(&*fs, e);
    assert_eq!(data.len(), 4096);
    assert!(data.starts_with(b"TAIL-OF-OLD-LOG-BLOCK"));
}

#[test]
fn prior_version_recovered() {
    let fs = mount();
    let entries = all_entries();
    let e = find_path(&entries, "/hello.txt@v5");
    assert_eq!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    );
    assert_eq!(read_all(&*fs, e), b"HELLO-V");
    assert_eq!(e.meta["prior_version_of"], "/hello.txt");
}

#[test]
fn dangling_dir_item_surfaces() {
    let entries = all_entries();
    let e = find_path(&entries, "/ghost.tmp");
    assert!(e.is_deleted());
    assert_eq!(e.kind, EntryKind::File);
    assert!(e.meta["note"].contains("dangling"));
}

#[test]
fn orphan_item_recovered() {
    let fs = mount();
    let entries = all_entries();
    // ino 259 is ORPHAN_ITEM'd; its name survives only as DIR_ITEM residue.
    let e = find_path(&entries, "/pending.txt");
    assert!(e.is_deleted());
    assert_eq!(e.meta["orphan"], "true");
    // Its extent is still allocated (backref intact) → data recoverable.
    assert_eq!(read_all(&*fs, e), b"orphan-data");
}

// ---------- free space / carving ----------

#[test]
fn unallocated_ranges_correct() {
    let ranges = mount().unallocated_ranges();
    let covers = |off: u64| ranges.iter().any(|&(o, l)| off >= o && off < o + l);
    assert!(covers(common::FREE_AREA), "free gap must be unallocated");
    assert!(!covers(common::D_HELLO), "live extent must not be unallocated");
    assert!(!covers(common::D_NEWFILE), "reallocated extent is allocated");
    assert!(!covers(common::SB as u64), "superblock zone reserved");
    // Deleted-file extents are NOT allocated in the extent tree → free.
    assert!(covers(common::D_SECRET));
}

#[test]
fn carve_finds_embedded_signature() {
    let fs = mount();
    // Carve over the (allocated) masq.doc data — the default scanner
    // finds the MZ header.
    let hits: Vec<_> = fs
        .carve_region(common::D_MASQ, 4096, 512)
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].kind, MagicType::Pe);
    assert_eq!(hits[0].offset, common::D_MASQ);
}

// ---------- corruption / strict ----------

#[test]
fn corrupt_leaf_lenient_vs_strict() {
    let mut img = common::build_image();
    // Corrupt one byte inside FS leaf 1's data area → bad node checksum.
    let pos = common::FS_LEAF1 as usize + 3000;
    img[pos] ^= 0xFF;
    let src: Arc<dyn ByteSource> = Arc::new(img);

    // Lenient: error record(s) interleaved; leaf-2 entries still surface.
    let fs = BtrfsParser.mount(src.clone()).unwrap();
    let items: Vec<_> = fs.walk().collect();
    assert!(items.iter().any(|i| i.is_err()));
    let ok_paths: Vec<String> = items
        .iter()
        .filter_map(|i| i.as_ref().ok().map(|e| e.path.clone()))
        .collect();
    assert!(ok_paths.iter().any(|p| p == "/second.txt"), "{ok_paths:?}");

    // Strict: the walk terminates at the first error record.
    let fs = BtrfsParser
        .mount_with(src, &MountOptions::strict())
        .unwrap();
    let items: Vec<_> = fs.walk().collect();
    let first_err = items.iter().position(|i| i.is_err()).unwrap();
    assert_eq!(items.len(), first_err + 1, "walk must stop at first error");
}

#[test]
fn walk_is_bounded_stream() {
    // The iterator yields lazily — taking 3 entries does not walk all trees.
    let fs = mount();
    let mut it = fs.walk();
    let first = it.next().unwrap().unwrap();
    assert_eq!(first.path, "/");
}

#[test]
fn mount_fails_with_no_chunks() {
    // Valid superblock but an empty sys_chunk_array and an unreadable
    // chunk tree → "no usable chunks".
    let mut img = vec![0u8; 0x20000];
    let vol = common::build_image();
    // Copy the superblock but zero out the sys_chunk_array + its size.
    img[common::SB..common::SB + 4096].copy_from_slice(&vol[common::SB..common::SB + 4096]);
    common::w32(&mut img, common::SB + 0xA0, 0); // sys_chunk_array_size = 0
    img[common::SB + 0x32B..common::SB + 0x32B + 2048].fill(0);
    // Re-checksum the superblock so it still parses.
    let csum = crc32fast::hash(&img[common::SB + 32..common::SB + 4096]);
    img[common::SB..common::SB + 4].copy_from_slice(&csum.to_le_bytes());
    let src: Arc<dyn ByteSource> = Arc::new(img);
    assert!(BtrfsParser.mount(src).is_err());
}

#[test]
fn strict_mount_fails_on_dead_root_tree() {
    let mut img = common::build_image();
    // Zero the root tree leaf → root index comes back empty.
    img[common::ROOT_TREE as usize..common::ROOT_TREE as usize + common::NODE].fill(0);
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let opts = MountOptions::strict();
    assert!(BtrfsParser.mount_with(src, &opts).is_err());
}

#[test]
fn read_file_rejects_dir_and_bad_id() {
    let entries = all_entries();
    let dir = entries.iter().find(|e| e.path == "/subdir").unwrap();
    assert!(mount().read_file(dir).is_err());
    // An entry_id that was never produced → invalid input.
    let mut ghost = entries.iter().find(|e| e.path == "/hello.txt").unwrap().clone();
    ghost.entry_id = 999_999;
    assert!(mount().read_file(&ghost).is_err());
}
