//! jbd2 journal-forensics integration tests over patched corpus images.
//!
//! The base corpus (`common::build_ext4`) carries a small 8-block journal
//! at fs blocks 30-37 (superblock + 7 log blocks). These tests rewrite the
//! log region to exercise the exotic corners: 64-bit tags, escape and
//! deleted tag flags, mid-log superblock copies, fast-commit and unknown
//! block types, 64-bit revoke entries, tags whose trailers run past the
//! block end, descriptors claiming blocks past `s_maxlen`, truncated
//! reads, and journal-file extent shortfalls.

mod common;

use std::sync::Arc;

use sutram_ext4::{Ext4Fs, Ext4Parser, JournalEventKind};
use sutram_fs::{FileSystem, FsEntry, FsError, FsParser, MountOptions, RecoveryState};
use sutram_io::ByteSource;

fn mount(img: Vec<u8>) -> Box<dyn sutram_fs::FileSystem> {
    Ext4Parser.mount(Arc::new(img) as Arc<dyn ByteSource>).unwrap()
}

fn mount_opts(img: Vec<u8>, opts: MountOptions) -> Box<dyn sutram_fs::FileSystem> {
    Ext4Parser
        .mount_with(Arc::new(img) as Arc<dyn ByteSource>, &opts)
        .unwrap()
}

fn events(img: Vec<u8>) -> Vec<Result<sutram_ext4::JournalEvent, FsError>> {
    Ext4Fs::mount(
        Arc::new(img) as Arc<dyn ByteSource>,
        MountOptions::default(),
    )
    .unwrap()
    .journal_events()
    .collect()
}

fn entries(fs: &dyn sutram_fs::FileSystem) -> Vec<FsEntry> {
    fs.journal_entries()
        .collect::<Result<Vec<_>, _>>()
        .expect("journal parse should not error")
}

/// Rewrite the 7-block log region (fs blocks 31..37) with exotic jbd2
/// structures. Requires `feature_incompat = 0x02` (64-bit) already set so
/// tags are 12 bytes.
fn write_exotic_journal(img: &mut [u8]) {
    let f = |b: u32| common::blk_off(b);
    for b in 31..=37u32 {
        img[f(b)..f(b) + common::BLK].fill(0);
    }

    // blk 1 (fs 31): descriptor tx 0x200 — one 12-byte tag targeting the
    // inode table (fs 5) with ESCAPE|SAME_UUID|DELETED|LAST; the escape
    // word follows the tag.
    common::jbd2_header(img, 31, 1, 0x200);
    common::jbd2_tag64(img, 31, 12, 5, 0xF); // ESCAPE|SAME_UUID|DELETED|LAST
    common::wj(img, f(31) + 24, 0xDEAD_BEEF); // escaped first word

    // blk 2 (fs 32): journaled copy payload.
    common::put_data(img, 32, b"JOURNALED-64BIT-COPY");

    // blk 3 (fs 33): a mid-log journal superblock v1 copy (blocktype 3).
    common::jbd2_header(img, 33, 3, 0x200);

    // blk 4 (fs 34): fast-commit block (type 6 — TLV log, not decoded).
    common::jbd2_header(img, 34, 6, 0x201);

    // blk 5 (fs 35): revoke tx 0x200 with 64-bit (8-byte) entries —
    // 126 entries, enough to overflow the 64-entry meta listing.
    common::jbd2_header(img, 35, 5, 0x200);
    let n = 126usize;
    common::wj(img, f(35) + 0x0C, (0x10 + n * 8) as u32); // r_count
    for i in 0..n {
        img[f(35) + 0x10 + i * 8..f(35) + 0x18 + i * 8]
            .copy_from_slice(&(100u64 + i as u64).to_be_bytes());
    }

    // blk 6 (fs 36): descriptor tx 0x202 whose tail never carries LAST —
    // zero tags cascade until a crafted tag at offset 1012 truncates its
    // escape word at the block end.
    common::jbd2_header(img, 36, 1, 0x202);
    // tag @12: fs 44, ESCAPE|SAME_UUID|DELETED (used = 12+4).
    common::jbd2_tag64(img, 36, 12, 44, 0x7);
    common::wj(img, f(36) + 24, 0xABAD_CAFE);
    // tag @28: a 64-bit fs block far past the volume (5 << 32).
    common::jbd2_tag64(img, 36, 28, 5u64 << 32, 0x3); // ESCAPE|SAME_UUID
    common::wj(img, f(36) + 44, 0x1234_5678);
    // tag @44: fs 61, ESCAPE|SAME_UUID|DELETED (used = 16).
    common::jbd2_tag64(img, 36, 44, 61, 0x7);
    common::wj(img, f(36) + 56, 0xFFFF_0000);
    // Positions 60..1012 (stride 28: zero tag + 16B uuid) land on 1012 —
    // plant a tag whose escape word would cross the block end.
    common::jbd2_tag64(img, 36, 1012, 99, 0x3);

    // blk 7 (fs 37): journaled copy payload for the fs-44 tag.
    common::put_data(img, 37, b"JOURNALED-COPY-FS44");
}

#[test]
fn journal_64bit_tags_and_exotic_blocks() {
    let mut img = common::build_ext4();
    common::jbd2_set_feature_incompat(&mut img, 0x02); // INCOMPAT_64BIT
    write_exotic_journal(&mut img);

    let evs = events(img.clone())
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    // superblock + (desc,tag) + super-v1 + fastcommit + revoke
    // + (desc, 38 tags) = 44.
    assert_eq!(evs.len(), 44, "{evs:#?}");
    assert!(matches!(
        evs[0].kind,
        JournalEventKind::Superblock { version: 2 }
    ));
    assert!(matches!(evs[1].kind, JournalEventKind::Descriptor { tags: 1 }));
    // Mid-log superblock v1 copy, fast-commit and revoke all parsed.
    assert!(evs.iter().any(|e| matches!(
        e.kind,
        JournalEventKind::Superblock { version: 1 }
    )));
    assert!(evs
        .iter()
        .any(|e| matches!(e.kind, JournalEventKind::FastCommit)));
    let JournalEventKind::Revoke { ref blocks } = evs[5].kind else {
        panic!("event 5 should be the revoke: {:?}", evs[5].kind)
    };
    assert_eq!(blocks.len(), 126);
    assert_eq!(blocks[0], 100);
    // 64-bit tag: fs block 5<<32 classifies out-of-volume.
    assert!(evs.iter().any(|e| matches!(
        &e.kind,
        JournalEventKind::JournaledBlock(t)
            if t.fs_block == (5u64 << 32)
                && matches!(t.target, sutram_ext4::JournalTarget::OutOfVolume)
    )));
    // Tags beyond the journal file's extents get no data_offset.
    assert!(evs.iter().any(|e| matches!(
        &e.kind,
        JournalEventKind::JournaledBlock(t) if t.data_offset.is_none()
    )));

    let fs = mount(img);
    let es = entries(fs.as_ref());
    let find = |n: &str| -> &FsEntry {
        es.iter()
            .find(|e| e.name == n)
            .unwrap_or_else(|| panic!("{n} missing: {:?}", es.iter().map(|e| &e.name).collect::<Vec<_>>()))
    };
    // fs 5 tag: escaped + deleted + prior inode-table state.
    let b5 = find("block_5");
    assert_eq!(b5.meta["jbd2_escaped"], "true");
    assert_eq!(b5.meta["jbd2_tag_deleted"], "true");
    assert_eq!(b5.meta["jbd2_target"], "inode_table_g0");
    assert!(b5.meta.contains_key("note"));
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut fs.read_file(b5).unwrap(), &mut buf).unwrap();
    assert!(buf.starts_with(b"JOURNALED-64BIT-COPY"));
    // The 64-bit out-of-volume tag.
    let far = find(&format!("block_{}", 5u64 << 32));
    assert_eq!(far.meta["jbd2_target"], "out_of_volume");
    assert_eq!(far.meta["jbd2_target_allocated"], "true");
    // The >64-entry revoke list is truncated with an ellipsis.
    let rv = find("revoke_5");
    assert_eq!(rv.meta["jbd2_revoked_count"], "126");
    assert!(rv.meta["jbd2_revoked_blocks"].ends_with(",…"));
    // A tag with no reachable data copy is Unrecoverable.
    let nodata = find("block_0");
    assert!(matches!(
        nodata.status,
        sutram_fs::FsEntryStatus::Deleted {
            recovery: RecoveryState::Unrecoverable
        }
    ));
    assert!(nodata.allocated_ranges.is_empty());
}

#[test]
fn journal_unknown_blocktype() {
    let mut img = common::build_ext4();
    // Rewrite log block 1 as a recognised header with a bogus type.
    for b in 31..=37u32 {
        img[common::blk_off(b)..common::blk_off(b) + common::BLK].fill(0);
    }
    common::jbd2_header(&mut img, 31, 9, 0x77);
    common::jbd2_header(&mut img, 32, 2, 0x77);
    let evs = events(img)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(evs.iter().any(|e| matches!(
        e.kind,
        JournalEventKind::Unknown { blocktype: 9 }
    )));
    assert!(evs
        .iter()
        .any(|e| matches!(e.kind, JournalEventKind::Commit { .. })));
}

#[test]
fn journal_truncated_scan_lenient_and_strict() {
    let mut img = common::build_ext4();
    // Cut the image inside journal block 6 (fs 36): the scan reads that
    // block in the main loop (descriptor), so the read truncates. The
    // final block (fs 37) is also gone — two error records.
    img.truncate(common::blk_off(36) + 512);

    // Lenient: error items are emitted, earlier events still delivered.
    let fs = mount(img.clone());
    let items: Vec<_> = fs.journal_entries().collect();
    assert_eq!(items.iter().filter(|i| i.is_err()).count(), 2);
    assert!(items.iter().any(|i| i.is_ok()));
    // The FsInfo summary counts the parse errors.
    let info = fs.info();
    assert_eq!(info.meta["jbd2_parse_errors"], "2");

    // Strict: first error ends the stream.
    let fs = mount_opts(img, MountOptions::strict());
    let items: Vec<_> = fs.journal_entries().collect();
    assert!(items.last().unwrap().is_err());
    assert_eq!(items.iter().filter(|i| i.is_err()).count(), 1);
}

#[test]
fn journal_extent_shortfall_errors_not_panics() {
    let mut img = common::build_ext4();
    // The journal inode maps blocks 30-37 but the log claims maxlen 8.
    // Shrink the extent to 3 blocks: journal blocks ≥ 3 are beyond the
    // journal file's extents.
    let e = common::inode_off(8) + 0x28;
    // extent root: magic/entries/max/depth then first entry at +12:
    // ee_len at entry+4 → set run length to 3.
    common::w16(&mut img, e + 12 + 4, 3);
    let fs = mount(img);
    let items: Vec<_> = fs.journal_entries().collect();
    let errs: Vec<_> = items.iter().filter(|i| i.is_err()).collect();
    // Journal blocks 4..8 all resolve past the shrunken extent map.
    assert_eq!(errs.len(), 4, "{errs:?}");
    let msg = errs[0].as_ref().err().unwrap().to_string();
    assert!(msg.contains("beyond journal file extents"), "{msg}");
}

#[test]
fn journal_summary_capped_for_huge_log() {
    let mut img = common::build_ext4();
    // Advertise a journal longer than the 65536-block summary bound —
    // FsInfo must emit the bounded-summary note instead of scanning.
    common::wj(&mut img, common::blk_off(30) + 0x10, 70_000);
    let fs = mount(img);
    let info = fs.info();
    assert!(info.meta.contains_key("jbd2_summary"));
    assert!(!info.meta.contains_key("jbd2_descriptor_blocks"));
}

#[test]
fn journal_block_size_zero_falls_back() {
    let mut img = common::build_ext4();
    // A zero jbd2 s_blocksize is nonsense — the probe falls back to the
    // filesystem block size and the log still parses.
    common::wj(&mut img, common::blk_off(30) + 0x0C, 0);
    let fs = mount(img);
    let info = fs.info();
    assert_eq!(info.meta["jbd2_block_size"], "1024");
    assert_eq!(info.meta["jbd2_commit_blocks"], "1");
}

#[test]
fn journal_tag_trailer_truncation() {
    // 32-bit journal (feature_incompat = 0 → 8-byte tags): a descriptor
    // whose first tag does not set LAST cascades over zeroed "tags"
    // (each costs tag+uuid = 24 B) until a tag's uuid trailer would run
    // past the block end — parsing must stop quietly.
    let mut img = common::build_ext4();
    common::jbd2_set_feature_incompat(&mut img, 0);
    for b in 31..=37u32 {
        img[common::blk_off(b)..common::blk_off(b) + common::BLK].fill(0);
    }
    common::jbd2_header(&mut img, 31, 1, 0x50);
    // tag @12: fs 7, SAME_UUID (no LAST) → stride-24 cascade from pos 20.
    common::jbd2_tag(&mut img, 31, 12, 7, 0x2);
    // Positions land at 20+24k; at pos 1004 plant ESCAPE|SAME_UUID
    // (used 8+4 → pos 1016) and at 1016 another whose escape word
    // crosses the block end → tag_at returns None, loop stops.
    common::jbd2_tag(&mut img, 31, 1004, 42, 0x3);
    common::jbd2_tag(&mut img, 31, 1016, 42, 0x3);
    let evs = events(img)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    // superblock + descriptor + (1 real + 41 cascade + 1 crafted) tags.
    assert!(matches!(evs[0].kind, JournalEventKind::Superblock { .. }));
    assert!(matches!(evs[1].kind, JournalEventKind::Descriptor { .. }));
    let desc = evs.iter().find_map(|e| match e.kind {
        JournalEventKind::Descriptor { tags } => Some(tags),
        _ => None,
    });
    assert_eq!(desc.unwrap(), 43);
}

#[test]
fn no_journal_streams_empty() {
    // The ext2 corpus has no journal inode — both surfaces are empty.
    let src: Arc<dyn ByteSource> = Arc::new(common::build_ext2());
    let fs = Ext4Fs::mount(src, MountOptions::default()).unwrap();
    assert_eq!(fs.journal_events().count(), 0);
    assert_eq!(fs.journal_entries().count(), 0);
    assert!(!fs.info().meta.contains_key("jbd2_journal_blocks"));
}

#[test]
fn clean_journal_needs_no_replay() {
    let mut img = common::build_ext4();
    // s_start = 0 → clean journal.
    common::wj(&mut img, common::blk_off(30) + 0x1C, 0);
    let fs = mount(img);
    assert_eq!(fs.info().meta["jbd2_needs_replay"], "false");
}
