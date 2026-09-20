//! End-to-end tests over the synthetic in-memory F2FS image.

mod common;

use std::io::Read;
use std::sync::Arc;

use common::*;
use sutram_f2fs::F2fsParser;
use sutram_fs::{
    DetectConfidence, EntryKind, FileSystem, FsEntry, FsEntryStatus, FsParser, MountOptions,
    RecoveryState,
};

fn mount() -> Box<dyn FileSystem> {
    let src: Arc<dyn sutram_io::ByteSource> = image();
    F2fsParser.mount(src).unwrap()
}

fn entries(fs: &dyn FileSystem) -> Vec<FsEntry> {
    fs.walk().map(|r| r.expect("walk error")).collect()
}

fn by_path<'a>(entries: &'a [FsEntry], path: &str) -> &'a FsEntry {
    entries
        .iter()
        .find(|e| e.path == path)
        .unwrap_or_else(|| panic!("no entry at {path}"))
}

// ---------------------------------------------------------------------------
// Detection / mount
// ---------------------------------------------------------------------------

#[test]
fn detect_valid_image() {
    let src = image();
    assert_eq!(F2fsParser.detect(src.as_ref()), DetectConfidence::Certain);
}

#[test]
fn detect_garbage_and_foreign() {
    let zeros = vec![0u8; 64 * 1024];
    assert_eq!(F2fsParser.detect(&zeros.as_slice()), DetectConfidence::None);
    // FAT-like signature at the usual places is not F2FS.
    let mut fat = vec![0u8; 64 * 1024];
    fat[0x52..0x5a].copy_from_slice(b"FAT32   ");
    assert_eq!(F2fsParser.detect(&fat.as_slice()), DetectConfidence::None);
    // Wrong magic at 0x400.
    let mut img = image().as_ref().clone();
    img[0x400] ^= 0xFF;
    img[0x1400] ^= 0xFF;
    assert_eq!(F2fsParser.detect(&img.as_slice()), DetectConfidence::None);
}

#[test]
fn mount_info() {
    let fs = mount();
    let info = fs.info();
    assert_eq!(info.fs_type, "F2FS");
    assert_eq!(info.block_size, 4096);
    assert_eq!(info.total_blocks, TOTAL_BLOCKS);
    assert_eq!(info.label.as_deref(), Some("f2fs-test"));
    assert_eq!(info.meta["checkpoint_ver"], "5");
    assert_eq!(info.meta["checkpoint_crc_ok"], "true");
    assert_eq!(info.meta["clean_unmount"], "true");
    assert_eq!(info.meta["orphan_inodes"], "1");
    assert_eq!(info.meta["encryption_feature"], "true");
}

// ---------------------------------------------------------------------------
// Live tree
// ---------------------------------------------------------------------------

#[test]
fn live_tree_walks() {
    let fs = mount();
    let es = entries(&*fs);
    let paths: Vec<&str> = es.iter().map(|e| e.path.as_str()).collect();
    for p in [
        "/",
        "/hello.txt",
        "/subdir",
        "/subdir/deep.txt",
        "/subdir/a_longer_name.txt",
        "/vault",
        "/secret.bin",
        "/inline.dat",
        "/link",
    ] {
        assert!(paths.contains(&p), "missing {p} in {paths:?}");
    }
}

#[test]
fn live_entry_shapes() {
    let fs = mount();
    let es = entries(&*fs);
    let root = by_path(&es, "/");
    assert_eq!(root.kind, EntryKind::Directory);
    assert_eq!(root.status, FsEntryStatus::Live);
    let hello = by_path(&es, "/hello.txt");
    assert_eq!(hello.kind, EntryKind::File);
    assert_eq!(hello.size as usize, HELLO_CONTENT.len());
    // disk_offset is the dentry record, inside the root dentry block.
    assert!(hello.disk_offset >= ROOT_DENTRY_BLK * BLK as u64);
    assert!(hello.disk_offset < (ROOT_DENTRY_BLK + 1) * BLK as u64);
    assert_eq!(hello.meta["nid"], "4");
    assert_eq!(hello.meta["uid"], "1000");
    let link = by_path(&es, "/link");
    assert_eq!(link.kind, EntryKind::Symlink);
    assert_eq!(link.meta["symlink_target"], LINK_TARGET);
}

#[test]
fn file_read_roundtrip() {
    let fs = mount();
    let es = entries(&*fs);
    for (path, want) in [
        ("/hello.txt", HELLO_CONTENT),
        ("/subdir/deep.txt", DEEP_CONTENT),
        ("/subdir/a_longer_name.txt", LONGER_CONTENT),
    ] {
        let e = by_path(&es, path);
        let mut buf = Vec::new();
        fs.read_file(e).unwrap().read_to_end(&mut buf).unwrap();
        assert_eq!(buf, want, "content mismatch at {path}");
        // allocated_ranges carry the data block provenance.
        assert!(!e.allocated_ranges.is_empty());
    }
}

#[test]
fn inline_data_reads() {
    let fs = mount();
    let es = entries(&*fs);
    let e = by_path(&es, "/inline.dat");
    assert_eq!(e.meta.get("inline_data").map(String::as_str), Some("true"));
    // The extent lives inside the inode node block.
    assert_eq!(e.allocated_ranges.len(), 1);
    let (off, len) = e.allocated_ranges[0];
    assert!(off >= INLINE_INODE_BLK * BLK as u64 && off < (INLINE_INODE_BLK + 1) * BLK as u64);
    assert_eq!(len, INLINE_CONTENT.len() as u64);
    let mut buf = Vec::new();
    fs.read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, INLINE_CONTENT);
}

#[test]
fn symlink_target_and_read() {
    let fs = mount();
    let es = entries(&*fs);
    let e = by_path(&es, "/link");
    let mut buf = Vec::new();
    fs.read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, LINK_TARGET.as_bytes());
}

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

#[test]
fn timestamps_decode() {
    let fs = mount();
    let es = entries(&*fs);
    let e = by_path(&es, "/hello.txt");
    let want = MTIME_SEC as i64 * 1_000_000_000 + MTIME_NSEC as i64;
    assert_eq!(e.timestamps.modified.as_ref().unwrap().value, Some(want));
    assert_eq!(e.timestamps.accessed.as_ref().unwrap().value, Some(want));
    assert_eq!(e.timestamps.changed.as_ref().unwrap().value, Some(want));
    assert_eq!(
        e.timestamps.modified.as_ref().unwrap().raw_encoding,
        "f2fs-sec-nsec"
    );
    assert_eq!(
        e.timestamps.modified.as_ref().unwrap().granularity,
        std::time::Duration::from_nanos(1)
    );
    // crtime present on the EXTRA_ATTR inode (secret.bin).
    let s = by_path(&es, "/secret.bin");
    let crtime = CRTIME_SEC as i64 * 1_000_000_000 + CRTIME_NSEC as i64;
    assert_eq!(s.timestamps.created.as_ref().unwrap().value, Some(crtime));
    // hello has no EXTRA_ATTR → no crtime.
    assert!(e.timestamps.created.is_none());
}

// ---------------------------------------------------------------------------
// Encryption awareness
// ---------------------------------------------------------------------------

#[test]
fn encryption_flags() {
    let fs = mount();
    let es = entries(&*fs);
    let s = by_path(&es, "/secret.bin");
    assert_eq!(s.meta.get("encrypted").map(String::as_str), Some("fscrypt"));
    // the inline-xattr fscrypt context was parsed (v2, XTS contents).
    assert_eq!(
        s.meta.get("fscrypt_context").map(String::as_str),
        Some("v2 (28 bytes)")
    );
    let vault = by_path(&es, "/vault");
    assert_eq!(
        vault.meta.get("encrypted").map(String::as_str),
        Some("fscrypt")
    );
    // vault keeps its dentries inline inside the inode block.
    assert_eq!(
        vault.meta.get("inline_dentry").map(String::as_str),
        Some("true")
    );
    // children of an encrypted dir are marked; their (ciphertext) names
    // still surface sanitised.
    let child = es
        .iter()
        .find(|e| e.meta.get("encrypted_name").map(String::as_str) == Some("true"));
    assert!(child.is_some(), "no encrypted-name child emitted");
}

// ---------------------------------------------------------------------------
// Deleted recovery
// ---------------------------------------------------------------------------

#[test]
fn deleted_intact_via_residue_and_stale_nat() {
    let fs = mount();
    let es = entries(&*fs);
    let dead = es
        .iter()
        .find(|e| e.name == "dead.txt" && e.is_deleted())
        .expect("dead.txt residue missing");
    assert_eq!(dead.path, "/dead.txt");
    assert_eq!(
        dead.meta.get("dentry_residue").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        dead.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    );
    let mut buf = Vec::new();
    fs.read_file(dead).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, DEAD_CONTENT);
    // provenance: the inode node block we recovered it from.
    assert_eq!(dead.disk_offset, DEAD_INODE_BLK * BLK as u64);
}

#[test]
fn deleted_partial_overwrite() {
    let fs = mount();
    let es = entries(&*fs);
    let p = es
        .iter()
        .find(|e| e.name == "partial.bin")
        .expect("partial.bin missing");
    match p.status {
        FsEntryStatus::Deleted {
            recovery:
                RecoveryState::PartiallyOverwritten {
                    recovered_bytes,
                    total_bytes,
                },
        } => {
            assert_eq!(recovered_bytes, BLK as u64);
            assert_eq!(total_bytes, 2 * BLK as u64);
        }
        other => panic!("expected PartiallyOverwritten, got {other:?}"),
    }
    // Only the surviving extent is listed/readable.
    assert_eq!(p.allocated_ranges.len(), 1);
    assert_eq!(p.allocated_ranges[0].0, PARTIAL_SURV_BLK * BLK as u64);
    let mut buf = Vec::new();
    fs.read_file(p).unwrap().read_to_end(&mut buf).unwrap();
    assert!(buf.starts_with(b"surviving half"));
    // the reallocated block's new owner is cited via SSA.
    let note = p
        .meta
        .iter()
        .find(|(k, _)| k.starts_with("recovery_note"))
        .map(|(_, v)| v.clone());
    assert!(note.unwrap_or_default().contains("reallocated"));
}

#[test]
fn deleted_fully_overwritten() {
    let fs = mount();
    let es = entries(&*fs);
    let g = es
        .iter()
        .find(|e| e.name == "gone.bin")
        .expect("gone.bin missing");
    assert_eq!(
        g.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unrecoverable
        }
    );
    assert!(g.allocated_ranges.is_empty());
    let mut buf = Vec::new();
    fs.read_file(g).unwrap().read_to_end(&mut buf).unwrap();
    assert!(buf.is_empty());
}

#[test]
fn nid_reuse_flagged() {
    let fs = mount();
    let es = entries(&*fs);
    let g = es
        .iter()
        .find(|e| e.name == "ghost.txt" && e.is_deleted())
        .expect("ghost.txt residue missing");
    assert_eq!(g.path, "/subdir/ghost.txt");
    assert_eq!(g.meta.get("nid_reused").map(String::as_str), Some("true"));
}

#[test]
fn orphan_inode_recovered() {
    let fs = mount();
    let es = entries(&*fs);
    let o = es
        .iter()
        .find(|e| e.meta.get("orphan").map(String::as_str) == Some("true"))
        .expect("no orphan entry");
    assert!(o.is_deleted());
    assert!(o.path.starts_with("/$ORPHANED/"));
    assert_eq!(o.entry_id, ORPHAN_NID as u64);
}

#[test]
fn prior_version_recovered() {
    let fs = mount();
    let es = entries(&*fs);
    let prior: Vec<&FsEntry> = es
        .iter()
        .filter(|e| e.meta.contains_key("prior_version"))
        .collect();
    assert!(!prior.is_empty(), "no prior-version entries");
    let hello_old = prior
        .iter()
        .find(|e| e.name == format!("nid_{HELLO_NID}_v{OLD_CKPT_VER}"))
        .expect("hello prior version missing");
    let mut buf = Vec::new();
    fs.read_file(hello_old)
        .unwrap()
        .read_to_end(&mut buf)
        .unwrap();
    assert_eq!(buf, OLD_HELLO);
}

#[test]
fn stale_dentry_block_names() {
    let fs = mount();
    let es = entries(&*fs);
    // gone.txt: only the name survives — no inode in either NAT copy.
    let g = es
        .iter()
        .find(|e| e.name == "gone.txt" && e.is_deleted())
        .expect("gone.txt residue missing");
    assert_eq!(
        g.meta.get("stale_dentry_block").map(String::as_str),
        Some(STALE_DENTRY_BLK.to_string().as_str())
    );
    assert_eq!(
        g.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unrecoverable
        }
    );
}

// ---------------------------------------------------------------------------
// Magic verdicts / unallocated / leniency
// ---------------------------------------------------------------------------

#[test]
fn magic_verdicts() {
    let fs = mount();
    let es = entries(&*fs);
    // hello.txt content is plain text → Consistent or Info at worst;
    // just assert the field was populated (check_magic on).
    let hello = by_path(&es, "/hello.txt");
    assert!(hello.magic.is_some());
    // check_magic=false → no verdicts.
    let src: Arc<dyn sutram_io::ByteSource> = image();
    let fs2 = F2fsParser
        .mount_with(
            src,
            &MountOptions {
                check_magic: false,
                ..Default::default()
            },
        )
        .unwrap();
    let es2: Vec<FsEntry> = fs2.walk().map(|r| r.unwrap()).collect();
    assert!(es2.iter().all(|e| e.magic.is_none()));
}

#[test]
fn unallocated_ranges_cover_free_segments() {
    let fs = mount();
    let ranges = fs.unallocated_ranges();
    assert!(!ranges.is_empty());
    // seg 1 (blocks 5120..5632) is entirely free.
    let seg1_start = 5120 * BLK as u64;
    let seg1_end = 5632 * BLK as u64;
    assert!(
        ranges
            .iter()
            .any(|&(o, l)| o <= seg1_start && o + l >= seg1_end),
        "seg 1 not covered: {ranges:?}"
    );
    // A live data block must NOT be in a free range.
    let live_off = HELLO_DATA_BLK * BLK as u64;
    assert!(!ranges
        .iter()
        .any(|&(o, l)| live_off >= o && live_off < o + l));
    // …but the partially-deleted surviving block IS free space.
    let surv = PARTIAL_SURV_BLK * BLK as u64;
    assert!(ranges.iter().any(|&(o, l)| surv >= o && surv < o + l));
}

#[test]
fn strict_and_lenient_walk() {
    // Corrupt one live dentry's name_len — the bitmap still marks it.
    let mut img = image().as_ref().clone();
    let de_off = ROOT_DENTRY_BLK as usize * BLK + 30 + 2 * 11; // slot 2 dentry
    img[de_off + 8] = 0xFF;
    img[de_off + 9] = 0xFF; // name_len = 0xFFFF — insane
    let src: Arc<dyn sutram_io::ByteSource> = Arc::new(img.clone());
    // Lenient: emits an Err record but keeps walking.
    let fs = F2fsParser.mount(src).unwrap();
    let mut saw_err = false;
    let mut saw_live = 0;
    for item in fs.walk() {
        match item {
            Ok(_) => saw_live += 1,
            Err(_) => saw_err = true,
        }
    }
    assert!(saw_err, "lenient walk should emit an error record");
    assert!(saw_live > 3, "walk should continue past the corrupt dentry");
    // Strict: first error terminates.
    let src2: Arc<dyn sutram_io::ByteSource> = Arc::new(img);
    let fs2 = F2fsParser
        .mount_with(src2, &MountOptions::strict())
        .unwrap();
    let mut last = None;
    for item in fs2.walk() {
        last = Some(item);
    }
    assert!(
        matches!(last, Some(Err(_))),
        "strict walk should end in Err"
    );
}

#[test]
fn read_file_at() {
    let fs = mount();
    let es = entries(&*fs);
    let e = by_path(&es, "/hello.txt");
    let mut buf = [0u8; 6];
    let n = fs.read_file_at(e, 6, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"F2FS f");
}
