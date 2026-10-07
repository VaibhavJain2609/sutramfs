//! Synthetic F2FS image builder — everything is built in memory, no fixtures.
//!
//! Geometry (4 KiB blocks, 512 blocks/segment):
//!
//! ```text
//! blocks 0..512     reserved — superblock copies at 0x400 / 0x1400
//! segs  0..1        checkpoint area  (cp_blkaddr 512, packs at 512 & 1024)
//! segs  2..3        SIT copies       (sit_blkaddr 1536)
//! segs  4..5        NAT copies       (nat_blkaddr 2560)
//! segs  6..7        SSA              (ssa_blkaddr 3584)
//! segs  8..23       main area        (main_blkaddr 4608, 16 segs)
//! ```
//!
//! Main-area contents:
//!
//! * seg 0 — live: root dir, `hello.txt`, `subdir/` (+`deep.txt`,
//!   `a_longer_name.txt`), `vault/` (encrypted, `hidden.dat` inside),
//!   `secret.bin` (encrypted file), `inline.dat` (inline data), `link`
//!   (symlink), plus a live-but-unlinked inode at nid 8 (nid reuse).
//! * seg 1 — SIT-free residue: old inode for `dead.txt` (nid 6) + data,
//!   a stale dentry block (old names incl. `gone.txt` nid 14), the
//!   *prior version* of `hello.txt`'s inode (nid 4, older cp_ver) + data,
//!   and the orphan inode (nid 13).
//! * seg 2 — partially overwritten: `partial.bin` (nid 11) and `gone.bin`
//!   (nid 12) inodes survive via stale NAT; some extents reallocated
//!   (SIT-valid) — exercising `PartiallyOverwritten`/`Unrecoverable`.
//! * segs 3..15 — empty (free) for `unallocated_ranges`.
//!
//! Builders and constants are shared by several test targets; not every
//! target uses every helper.
#![allow(dead_code)]

use std::sync::Arc;

pub const BLK: usize = 4096;
pub const SEG: usize = 512; // blocks per segment

pub const SEG0_BLKADDR: u64 = 512;
pub const CP_BLKADDR: u64 = 512;
pub const SIT_BLKADDR: u64 = 1536;
pub const NAT_BLKADDR: u64 = 2560;
pub const SSA_BLKADDR: u64 = 3584;
pub const MAIN_BLKADDR: u64 = 4608;
pub const MAIN_SEGS: u32 = 16;
pub const TOTAL_BLOCKS: u64 = 512 + 24 * SEG as u64; // 12800

pub const ROOT_NID: u32 = 3;
pub const HELLO_NID: u32 = 4;
pub const SUBDIR_NID: u32 = 5;
pub const DEAD_NID: u32 = 6;
pub const DEEP_NID: u32 = 7;
pub const GHOST_NID: u32 = 8; // nid reused: live inode at 4618
pub const SECRET_NID: u32 = 10;
pub const PARTIAL_NID: u32 = 11;
pub const GONE_NID: u32 = 12;
pub const ORPHAN_NID: u32 = 13;
pub const GONE_NAME_NID: u32 = 14; // name-only residue, no inode survives
pub const INLINE_NID: u32 = 15;
pub const LINK_NID: u32 = 16;
pub const LONGER_NID: u32 = 17;
pub const VAULT_NID: u32 = 18;
pub const HIDDEN_NID: u32 = 19;

// Live seg-0 block offsets (main-relative blk = 4608 + off).
pub const ROOT_INODE_BLK: u64 = 4608;
pub const ROOT_DENTRY_BLK: u64 = 4609;
pub const HELLO_INODE_BLK: u64 = 4610;
pub const HELLO_DATA_BLK: u64 = 4611;
pub const SUBDIR_INODE_BLK: u64 = 4612;
pub const SUBDIR_DENTRY_BLK: u64 = 4613;
pub const DEEP_INODE_BLK: u64 = 4614;
pub const DEEP_DATA_BLK: u64 = 4615;
pub const VAULT_INODE_BLK: u64 = 4616;
// blk 4617 is left allocated-but-unreferenced (vault uses INLINE_DENTRY).
pub const GHOST_LIVE_INODE_BLK: u64 = 4618; // nid 8 reused
pub const SECRET_INODE_BLK: u64 = 4619;
pub const SECRET_DATA_BLK: u64 = 4620;
pub const INLINE_INODE_BLK: u64 = 4621;
pub const LINK_INODE_BLK: u64 = 4622;
pub const LINK_DATA_BLK: u64 = 4623;
pub const LONGER_INODE_BLK: u64 = 4624;
pub const LONGER_DATA_BLK: u64 = 4625;
pub const HIDDEN_INODE_BLK: u64 = 4626;
pub const HIDDEN_DATA_BLK: u64 = 4627;

// seg 1 (free per SIT) residue blocks.
pub const DEAD_INODE_BLK: u64 = 5120;
pub const DEAD_DATA_BLK: u64 = 5121;
pub const STALE_DENTRY_BLK: u64 = 5122;
pub const HELLO_OLD_INODE_BLK: u64 = 5123;
pub const HELLO_OLD_DATA_BLK: u64 = 5124;
pub const ORPHAN_INODE_BLK: u64 = 5125;

// seg 2 (partially live).
pub const PARTIAL_INODE_BLK: u64 = 5632;
pub const PARTIAL_LOST_BLK: u64 = 5633;
pub const PARTIAL_SURV_BLK: u64 = 5634;
pub const GONE_INODE_BLK: u64 = 5636;
pub const GONE_DATA_BLK: u64 = 5637;
pub const GHOST_OLD_INODE_BLK: u64 = 5638;

pub const CKPT_VER: u64 = 5;
pub const OLD_CKPT_VER: u64 = 1;

// Fixed timestamps for the corpus (nsec-granularity).
pub const MTIME_SEC: u64 = 1_700_000_000;
pub const MTIME_NSEC: u32 = 123_456_789;
pub const CRTIME_SEC: u64 = 1_699_000_000;
pub const CRTIME_NSEC: u32 = 987_654_321;

pub const HELLO_CONTENT: &[u8] = b"Hello F2FS forensic world!\n";
pub const DEAD_CONTENT: &[u8] = b"deleted-but-recoverable\n";
pub const OLD_HELLO: &[u8] = b"HELLO-OLD-VERSION";
pub const INLINE_CONTENT: &[u8] = b"tiny inline payload";
pub const LINK_TARGET: &str = "/subdir/deep.txt";
pub const DEEP_CONTENT: &[u8] = b"deep file content";
pub const LONGER_CONTENT: &[u8] = b"multi-slot name file";

fn put(b: &mut [u8], off: usize, bytes: &[u8]) {
    b[off..off + bytes.len()].copy_from_slice(bytes);
}
fn put_u16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// f2fs CRC-32 (zlib convention, seed = sb magic). Mirrors src/crc32.rs.
fn crc32(seed: u32, data: &[u8]) -> u32 {
    let mut c = !seed;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// Mutable image under construction.
pub struct Img {
    pub bytes: Vec<u8>,
}

impl Img {
    pub fn new() -> Img {
        Img {
            bytes: vec![0u8; TOTAL_BLOCKS as usize * BLK],
        }
    }

    fn blk(&mut self, n: u64) -> &mut [u8] {
        let s = n as usize * BLK;
        &mut self.bytes[s..s + BLK]
    }

    /// Write the two superblock copies.
    fn superblocks(&mut self) {
        for base in [0x400usize, 0x1400] {
            let sb = &mut self.bytes[base..base + 0xC00];
            put_u32(sb, 0, 0xF2F5_2010);
            put_u16(sb, 4, 1); // major
            put_u16(sb, 6, 15); // minor
            put_u32(sb, 8, 9); // log_sectorsize (512)
            put_u32(sb, 12, 3); // log_sectors_per_block
            put_u32(sb, 16, 12); // log_blocksize
            put_u32(sb, 20, 9); // log_blocks_per_seg
            put_u32(sb, 24, 1); // segs_per_sec
            put_u32(sb, 28, 1); // secs_per_zone
            put_u32(sb, 32, 3068); // checksum_offset (SB_CHKSUM pos)
            put_u64(sb, 36, TOTAL_BLOCKS); // block_count
            put_u32(sb, 44, 24); // section_count
            put_u32(sb, 48, 24); // segment_count
            put_u32(sb, 52, 2); // segment_count_ckpt
            put_u32(sb, 56, 2); // segment_count_sit
            put_u32(sb, 60, 2); // segment_count_nat
            put_u32(sb, 64, 2); // segment_count_ssa
            put_u32(sb, 68, MAIN_SEGS); // segment_count_main
            put_u32(sb, 72, SEG0_BLKADDR as u32);
            put_u32(sb, 76, CP_BLKADDR as u32);
            put_u32(sb, 80, SIT_BLKADDR as u32);
            put_u32(sb, 84, NAT_BLKADDR as u32);
            put_u32(sb, 88, SSA_BLKADDR as u32);
            put_u32(sb, 92, MAIN_BLKADDR as u32);
            put_u32(sb, 96, ROOT_NID);
            put_u32(sb, 100, 1); // node_ino
            put_u32(sb, 104, 2); // meta_ino
                                 // uuid @108 (16 B) — distinctive bytes.
            for i in 0..16 {
                sb[108 + i] = 0xA0 + i as u8;
            }
            // volume_name @124, UTF-16LE "f2fs-test".
            for (i, c) in "f2fs-test".encode_utf16().enumerate() {
                put_u16(sb, 124 + i * 2, c);
            }
            put_u32(sb, 1148, 1); // extension_count
            put_u32(sb, 1664, 0); // cp_payload
            put(sb, 1668, b"Linux version 6.1-synthetic"); // version
            put_u32(
                sb,
                2180,
                0x0001 | 0x0008 | 0x0100 | 0x0800 | 0x1000 | 0x2000,
            );
            // feature: ENCRYPT|EXTRA_ATTR|INODE_CRTIME|SB_CHKSUM|CASEFOLD|COMPRESSION
            // superblock CRC at checksum_offset (3068).
            let crc = crc32(0xF2F5_2010, &sb[..3068]);
            put_u32(sb, 3068, crc);
        }
    }

    /// One checkpoint block (`ver`) — both copies inside a pack are the
    /// same block content.
    fn cp_block(&mut self, blk: u64, ver: u64, flags: u32, start_sum: u32, total: u32) {
        let b = self.blk(blk);
        put_u64(b, 0, ver);
        put_u64(b, 8, MAIN_SEGS as u64 * SEG as u64); // user_block_count
        put_u64(b, 16, 20); // valid_block_count
        put_u32(b, 28, 0); // overprov_segment_count
        put_u32(b, 32, 13); // free_segment_count
        put_u32(b, 132, flags);
        put_u32(b, 136, total);
        put_u32(b, 140, start_sum);
        put_u32(b, 144, 20); // valid_node_count
        put_u32(b, 148, 12); // valid_inode_count
        put_u32(b, 152, 20); // next_free_nid
        put_u32(b, 156, 64); // sit_ver_bitmap_bytesize
        put_u32(b, 160, 256); // nat_ver_bitmap_bytesize
        let cso = 512u32; // checksum lands just past the bitmaps
        put_u32(b, 164, cso); // checksum_offset
        put_u64(b, 168, 12_345); // elapsed_time
                                 // sit_nat_version_bitmap @192: sit[64] then nat[256] — all zeros
                                 // (every current copy is copy A).
                                 // CRC: prefix to checksum_offset, then tail past the field.
        let crc = {
            let c = crc32(0xF2F5_2010, &b[..cso as usize]);
            crc32(c, &b[cso as usize + 4..])
        };
        put_u32(b, cso as usize, crc);
    }

    /// Both checkpoint packs. Pack 0 (blk 512) is newer and carries the
    /// orphan list; pack 1 (blk 1024) is older and minimal.
    fn checkpoints(&mut self) {
        let orphan_present = 0x0002u32;
        // pack 0: [cp][orphan][cp copy] — ver 5
        self.cp_block(512, CKPT_VER, 0x0001 | orphan_present, 2, 3);
        let orphan = self.blk(513);
        put_u32(orphan, 0, ORPHAN_NID);
        let tail = BLK - 16;
        put_u16(orphan, tail + 4, 0); // blk_addr
        put_u16(orphan, tail + 6, 1); // blk_count
        put_u32(orphan, tail + 8, 1); // entry_count
        self.cp_block(514, CKPT_VER, 0x0001 | orphan_present, 2, 3);
        // pack 1: [cp][cp copy] — ver 4, no orphans.
        self.cp_block(1024, 4, 0x0001, 1, 2);
        self.cp_block(1025, 4, 0x0001, 1, 2);
    }

    /// SIT entries for all 16 main segments, written to both copies
    /// (blk 1536 copy A, blk 2048 copy B). Entry i at byte i*74.
    fn sit(&mut self) {
        for base in [SIT_BLKADDR, SIT_BLKADDR + SEG as u64] {
            let b = self.blk(base);
            // seg 0: 20 live blocks (blkoffs 0..19).
            let e = &mut b[..74];
            put_u16(e, 0, 20);
            for i in 0..20usize {
                e[2 + i / 8] |= 1 << (i % 8);
            }
            put_u64(e, 66, 100); // mtime
                                 // seg 1: free (all zeros).
                                 // seg 2: partial — blkoffs 1 and 5 live.
            let e = &mut b[2 * 74..3 * 74];
            put_u16(e, 0, 2);
            e[2] |= 1 << 1; // blkoff 1
            e[2] |= 1 << 5; // blkoff 5
            put_u64(e, 66, 90);
        }
    }

    /// A 9-byte NAT entry.
    fn nat_ent(b: &mut [u8], nid: u32, ino: u32, blk: u32, ver: u8) {
        let o = nid as usize * 9;
        b[o] = ver;
        put_u32(b, o + 1, ino);
        put_u32(b, o + 5, blk);
    }

    /// NAT copies: A at seg 4 (blk 2560) current, B at seg 5 (3072) stale.
    fn nat(&mut self) {
        {
            let a = self.blk(NAT_BLKADDR);
            Self::nat_ent(a, ROOT_NID, ROOT_NID, ROOT_INODE_BLK as u32, 1);
            Self::nat_ent(a, HELLO_NID, HELLO_NID, HELLO_INODE_BLK as u32, 2);
            Self::nat_ent(a, SUBDIR_NID, SUBDIR_NID, SUBDIR_INODE_BLK as u32, 1);
            Self::nat_ent(a, DEEP_NID, DEEP_NID, DEEP_INODE_BLK as u32, 1);
            Self::nat_ent(a, GHOST_NID, GHOST_NID, GHOST_LIVE_INODE_BLK as u32, 1);
            Self::nat_ent(a, SECRET_NID, SECRET_NID, SECRET_INODE_BLK as u32, 1);
            Self::nat_ent(a, ORPHAN_NID, ORPHAN_NID, ORPHAN_INODE_BLK as u32, 1);
            Self::nat_ent(a, INLINE_NID, INLINE_NID, INLINE_INODE_BLK as u32, 1);
            Self::nat_ent(a, LINK_NID, LINK_NID, LINK_INODE_BLK as u32, 1);
            Self::nat_ent(a, LONGER_NID, LONGER_NID, LONGER_INODE_BLK as u32, 1);
            Self::nat_ent(a, VAULT_NID, VAULT_NID, VAULT_INODE_BLK as u32, 1);
            Self::nat_ent(a, HIDDEN_NID, HIDDEN_NID, HIDDEN_INODE_BLK as u32, 1);
        }
        {
            let b = self.blk(NAT_BLKADDR + SEG as u64);
            Self::nat_ent(b, ROOT_NID, ROOT_NID, ROOT_INODE_BLK as u32, 1);
            // nid 4 older copy points at the prior-version inode block.
            Self::nat_ent(b, HELLO_NID, HELLO_NID, HELLO_OLD_INODE_BLK as u32, 1);
            Self::nat_ent(b, SUBDIR_NID, SUBDIR_NID, SUBDIR_INODE_BLK as u32, 1);
            Self::nat_ent(b, DEAD_NID, DEAD_NID, DEAD_INODE_BLK as u32, 1);
            Self::nat_ent(b, DEEP_NID, DEEP_NID, DEEP_INODE_BLK as u32, 1);
            Self::nat_ent(b, GHOST_NID, GHOST_NID, GHOST_OLD_INODE_BLK as u32, 1);
            Self::nat_ent(b, SECRET_NID, SECRET_NID, SECRET_INODE_BLK as u32, 1);
            Self::nat_ent(b, PARTIAL_NID, PARTIAL_NID, PARTIAL_INODE_BLK as u32, 1);
            Self::nat_ent(b, GONE_NID, GONE_NID, GONE_INODE_BLK as u32, 1);
            Self::nat_ent(b, ORPHAN_NID, ORPHAN_NID, ORPHAN_INODE_BLK as u32, 1);
            Self::nat_ent(b, INLINE_NID, INLINE_NID, INLINE_INODE_BLK as u32, 1);
            Self::nat_ent(b, LINK_NID, LINK_NID, LINK_INODE_BLK as u32, 1);
            Self::nat_ent(b, LONGER_NID, LONGER_NID, LONGER_INODE_BLK as u32, 1);
            Self::nat_ent(b, VAULT_NID, VAULT_NID, VAULT_INODE_BLK as u32, 1);
            Self::nat_ent(b, HIDDEN_NID, HIDDEN_NID, HIDDEN_INODE_BLK as u32, 1);
        }
    }

    /// SSA summaries: `entries[i]` = summary for main-block main_blkaddr+i.
    /// Only entries the tests consult are populated.
    fn ssa(&mut self) {
        // seg 0 summary at ssa_blkaddr + 0.
        let b = self.blk(SSA_BLKADDR);
        let mut ent = |off_in_seg: usize, nid: u32, ofs: u16| {
            let o = off_in_seg * 7;
            put_u32(b, o, nid);
            b[o + 4] = 1; // version
            put_u16(b, o + 5, ofs);
        };
        ent(1, ROOT_NID, 0); // root dentry block
        ent(3, HELLO_NID, 0); // hello data
        ent(5, SUBDIR_NID, 0); // subdir dentry
        ent(7, DEEP_NID, 0);
        ent(9, VAULT_NID, 0); // vault dentry
        ent(12, SECRET_NID, 0);
        ent(15, LINK_NID, 0);
        ent(17, LONGER_NID, 0);
        ent(19, HIDDEN_NID, 0);
        // seg 2 summary at ssa_blkaddr + 2: the reallocated blocks claim
        // new owners (hello.txt and secret.bin extents).
        let b = self.blk(SSA_BLKADDR + 2);
        put_u32(b, 7, HELLO_NID);
        b[11] = 2;
        put_u16(b, 12, 0);
        put_u32(b, 35, SECRET_NID);
        b[39] = 1;
        put_u16(b, 40, 0);
    }

    /// Node footer at the tail of a node block.
    fn footer(b: &mut [u8], nid: u32, ino: u32, cp_ver: u64) {
        put_u32(b, BLK - 24, nid);
        put_u32(b, BLK - 20, ino);
        put_u32(b, BLK - 16, 0); // flag
        put_u64(b, BLK - 12, cp_ver);
        put_u32(b, BLK - 4, 0); // next_blkaddr
    }

    /// Fill an inode-node block. `addrs` fills `i_addr` (with the
    /// extra-attr offset applied); `inline_data` writes the inline payload.
    #[allow(clippy::too_many_arguments)]
    fn inode_node(
        &mut self,
        blk: u64,
        nid: u32,
        mode: u16,
        size: u64,
        links: u32,
        flags: u32,
        inline: u8,
        name: &[u8],
        pino: u32,
        addrs: &[u32],
        i_nids: &[u32; 5],
        cp_ver: u64,
        extra_isize: u16,
    ) {
        let b = self.blk(blk);
        put_u16(b, 0, mode);
        b[3] = inline;
        put_u32(b, 4, 1000); // uid
        put_u32(b, 8, 1000); // gid
        put_u32(b, 12, links);
        put_u64(b, 16, size);
        put_u64(b, 24, size / BLK as u64 + 1);
        put_u64(b, 32, MTIME_SEC); // atime
        put_u64(b, 40, MTIME_SEC); // ctime
        put_u64(b, 48, MTIME_SEC); // mtime
        put_u32(b, 56, MTIME_NSEC);
        put_u32(b, 60, MTIME_NSEC);
        put_u32(b, 64, MTIME_NSEC);
        put_u32(b, 68, 7); // generation
        put_u32(b, 72, 1); // current_depth
        put_u32(b, 80, flags);
        put_u32(b, 84, pino);
        put_u32(b, 88, name.len() as u32);
        put(b, 92, name);
        if inline & 0x20 != 0 {
            // EXTRA_ATTR: i_extra_isize + inline_xattr_size + crtime…
            put_u16(b, 360, extra_isize);
            if extra_isize >= 24 {
                put_u64(b, 372, CRTIME_SEC); // i_crtime (extra +12)
                put_u32(b, 380, CRTIME_NSEC);
            }
        }
        let base = 360 + (extra_isize as usize / 4) * 4;
        for (i, &a) in addrs.iter().enumerate() {
            put_u32(b, base + i * 4, a);
        }
        for (i, &n) in i_nids.iter().enumerate() {
            put_u32(b, 4052 + i * 4, n);
        }
        Self::footer(b, nid, nid, cp_ver);
    }

    /// A dentry block: `entries` = (name, ino, file_type, live).
    /// Deleted residue = live:false (content present, bitmap clear).
    fn dentry_block(&mut self, blk: u64, entries: &[(&[u8], u32, u8, bool)]) {
        let b = self.blk(blk);
        write_dentries(b, 0, BLK, entries);
    }

    fn data(&mut self, blk: u64, content: &[u8]) {
        put(self.blk(blk), 0, content);
    }

    /// Populate the main area.
    fn main_area(&mut self) {
        // --- live tree (seg 0) ---
        self.inode_node(
            ROOT_INODE_BLK,
            ROOT_NID,
            0o040755,
            BLK as u64,
            3,
            0,
            0,
            b"/",
            ROOT_NID,
            &[ROOT_DENTRY_BLK as u32],
            &[0; 5],
            CKPT_VER,
            0,
        );
        self.dentry_block(
            ROOT_DENTRY_BLK,
            &[
                (b".", ROOT_NID, 2, true),
                (b"..", ROOT_NID, 2, true),
                (b"hello.txt", HELLO_NID, 1, true),
                (b"subdir", SUBDIR_NID, 2, true),
                (b"vault", VAULT_NID, 2, true),
                (b"secret.bin", SECRET_NID, 1, true),
                (b"inline.dat", INLINE_NID, 1, true),
                (b"link", LINK_NID, 7, true),
                // deleted residue: bitmap clear, dirent survives.
                (b"dead.txt", DEAD_NID, 1, false),
            ],
        );
        self.inode_node(
            HELLO_INODE_BLK,
            HELLO_NID,
            0o100644,
            HELLO_CONTENT.len() as u64,
            1,
            0,
            0,
            b"hello.txt",
            ROOT_NID,
            &[HELLO_DATA_BLK as u32],
            &[0; 5],
            CKPT_VER,
            0,
        );
        {
            // i_ext extent cache: fofs 0 → HELLO_DATA_BLK, len 1.
            let b = self.blk(HELLO_INODE_BLK);
            put_u32(b, 348, 0);
            put_u32(b, 352, HELLO_DATA_BLK as u32);
            put_u32(b, 356, 1);
        }
        self.data(HELLO_DATA_BLK, HELLO_CONTENT);
        self.inode_node(
            SUBDIR_INODE_BLK,
            SUBDIR_NID,
            0o040755,
            BLK as u64,
            2,
            0,
            0,
            b"subdir",
            ROOT_NID,
            &[SUBDIR_DENTRY_BLK as u32],
            &[0; 5],
            CKPT_VER,
            0,
        );
        self.dentry_block(
            SUBDIR_DENTRY_BLK,
            &[
                (b".", SUBDIR_NID, 2, true),
                (b"..", ROOT_NID, 2, true),
                (b"deep.txt", DEEP_NID, 1, true),
                (b"a_longer_name.txt", LONGER_NID, 1, true),
                // residue: nid reused by a live inode.
                (b"ghost.txt", GHOST_NID, 1, false),
            ],
        );
        self.inode_node(
            DEEP_INODE_BLK,
            DEEP_NID,
            0o100600,
            DEEP_CONTENT.len() as u64,
            1,
            0,
            0,
            b"deep.txt",
            SUBDIR_NID,
            &[DEEP_DATA_BLK as u32],
            &[0; 5],
            CKPT_VER,
            0,
        );
        self.data(DEEP_DATA_BLK, DEEP_CONTENT);
        // vault: encrypted dir using INLINE_DENTRY — its dentries live
        // inside the inode's i_addr region (offset 364 when extra_isize=0).
        self.inode_node(
            VAULT_INODE_BLK,
            VAULT_NID,
            0o040700,
            BLK as u64,
            2,
            0x800,
            0x04,
            b"vault",
            ROOT_NID,
            &[0],
            &[0; 5],
            CKPT_VER,
            0,
        );
        // vault's dentry names are fscrypt ciphertext — random-looking
        // bytes, still emitted sanitized. Inline dentry region = 364..4052.
        {
            let b = self.blk(VAULT_INODE_BLK);
            write_dentries(
                b,
                364,
                4052 - 364,
                &[
                    (b".", VAULT_NID, 2, true),
                    (b"..", ROOT_NID, 2, true),
                    (b"\x8f\x12\x9a\x44\x01\xb7\x3c\x9e\x55", HIDDEN_NID, 1, true),
                ],
            );
        }
        // ghost nid reused: a live inode sitting at nid 8.
        self.inode_node(
            GHOST_LIVE_INODE_BLK,
            GHOST_NID,
            0o100644,
            11,
            1,
            0,
            0,
            b"reused",
            ROOT_NID,
            &[0],
            &[0; 5],
            CKPT_VER,
            0,
        );
        // secret.bin: encrypted regular file with a crtime and an inline
        // fscrypt-context xattr ("c", index 9).
        self.inode_node(
            SECRET_INODE_BLK,
            SECRET_NID,
            0o100600,
            SECRET_CONTENT.len() as u64,
            1,
            0x800,
            0x20 | 0x01,
            b"secret.bin",
            ROOT_NID,
            &[SECRET_DATA_BLK as u32],
            &[0; 5],
            CKPT_VER,
            36,
        );
        {
            let b = self.blk(SECRET_INODE_BLK);
            put_u16(b, 362, 10); // i_inline_xattr_size = 10 u32s = 40 bytes
                                 // inline xattr region = tail of i_addr: 360 + (923-10)*4 = 4012
            let x = 4012usize;
            b[x] = 9; // name_index = ENCRYPTION
            b[x + 1] = 1; // name_len
            put_u16(b, x + 2, 28); // value_size = fscrypt ctx v2
            b[x + 4] = b'c';
            // entry_size = ALIGN(4+1) = 8 → context at x+8
            b[x + 8] = 2; // ctx version v2
            b[x + 9] = 4; // contents mode AES-256-XTS
            b[x + 10] = 2; // filenames mode AES-256-CTS
            for i in 0..20 {
                b[x + 11 + i] = 0xC0 + i as u8;
            }
        }
        self.data(SECRET_DATA_BLK, SECRET_CONTENT);
        // inline.dat: data inside the node block.
        {
            let extra: &[u32] = &[];
            self.inode_node(
                INLINE_INODE_BLK,
                INLINE_NID,
                0o100644,
                INLINE_CONTENT.len() as u64,
                1,
                0,
                0x02,
                b"inline.dat",
                ROOT_NID,
                extra,
                &[0; 5],
                CKPT_VER,
                0,
            );
            let b = self.blk(INLINE_INODE_BLK);
            // inline data region starts at i_addr[1] (offset 364).
            put(b, 364, INLINE_CONTENT);
        }
        // link → symlink with target in a data block.
        self.inode_node(
            LINK_INODE_BLK,
            LINK_NID,
            0o120777,
            LINK_TARGET.len() as u64,
            1,
            0,
            0,
            b"link",
            ROOT_NID,
            &[LINK_DATA_BLK as u32],
            &[0; 5],
            CKPT_VER,
            0,
        );
        self.data(LINK_DATA_BLK, LINK_TARGET.as_bytes());
        self.inode_node(
            LONGER_INODE_BLK,
            LONGER_NID,
            0o100644,
            LONGER_CONTENT.len() as u64,
            1,
            0,
            0,
            b"a_longer_name.txt",
            SUBDIR_NID,
            &[LONGER_DATA_BLK as u32],
            &[0; 5],
            CKPT_VER,
            0,
        );
        self.data(LONGER_DATA_BLK, LONGER_CONTENT);
        self.inode_node(
            HIDDEN_INODE_BLK,
            HIDDEN_NID,
            0o100600,
            13,
            1,
            0,
            0,
            b"hidden.dat",
            VAULT_NID,
            &[HIDDEN_DATA_BLK as u32],
            &[0; 5],
            CKPT_VER,
            0,
        );
        self.data(HIDDEN_DATA_BLK, b"hidden inside");

        // --- stale/deleted residue (seg 1, SIT-free) ---
        self.inode_node(
            DEAD_INODE_BLK,
            DEAD_NID,
            0o100644,
            DEAD_CONTENT.len() as u64,
            1,
            0,
            0,
            b"dead.txt",
            ROOT_NID,
            &[DEAD_DATA_BLK as u32],
            &[0; 5],
            OLD_CKPT_VER,
            0,
        );
        self.data(DEAD_DATA_BLK, DEAD_CONTENT);
        self.dentry_block(
            STALE_DENTRY_BLK,
            &[
                (b".", ROOT_NID, 2, true),
                (b"..", ROOT_NID, 2, true),
                (b"dead.txt", DEAD_NID, 1, true),
                (b"gone.txt", GONE_NAME_NID, 1, true),
            ],
        );
        // prior version of hello.txt inode (older cp_ver, old extent).
        self.inode_node(
            HELLO_OLD_INODE_BLK,
            HELLO_NID,
            0o100644,
            OLD_HELLO.len() as u64,
            1,
            0,
            0,
            b"hello.txt",
            ROOT_NID,
            &[HELLO_OLD_DATA_BLK as u32],
            &[0; 5],
            OLD_CKPT_VER,
            0,
        );
        self.data(HELLO_OLD_DATA_BLK, OLD_HELLO);
        // orphan inode (still in current NAT).
        self.inode_node(
            ORPHAN_INODE_BLK,
            ORPHAN_NID,
            0o100644,
            0,
            0,
            0,
            0,
            b"orphan-file",
            ROOT_NID,
            &[0],
            &[0; 5],
            CKPT_VER,
            0,
        );

        // --- partially overwritten (seg 2) ---
        // partial.bin: extent 0 reallocated (SIT live), extent 1 survives.
        self.inode_node(
            PARTIAL_INODE_BLK,
            PARTIAL_NID,
            0o100644,
            (2 * BLK) as u64,
            1,
            0,
            0,
            b"partial.bin",
            ROOT_NID,
            &[PARTIAL_LOST_BLK as u32, PARTIAL_SURV_BLK as u32],
            &[0; 5],
            OLD_CKPT_VER,
            0,
        );
        self.data(PARTIAL_SURV_BLK, b"surviving half of partial.bin");
        // gone.bin: sole extent reallocated → Unrecoverable.
        self.inode_node(
            GONE_INODE_BLK,
            GONE_NID,
            0o100644,
            BLK as u64,
            1,
            0,
            0,
            b"gone.bin",
            ROOT_NID,
            &[GONE_DATA_BLK as u32],
            &[0; 5],
            OLD_CKPT_VER,
            0,
        );
        // ghost's original inode (pre-reuse) at the stale-NAT target.
        self.inode_node(
            GHOST_OLD_INODE_BLK,
            GHOST_NID,
            0o100644,
            9,
            1,
            0,
            0,
            b"ghost.txt",
            SUBDIR_NID,
            &[0],
            &[0; 5],
            OLD_CKPT_VER,
            0,
        );
    }

    pub fn build(mut self) -> Arc<Vec<u8>> {
        self.superblocks();
        self.checkpoints();
        self.sit();
        self.nat();
        self.ssa();
        self.main_area();
        Arc::new(self.bytes)
    }
}

/// Write the dentry-block layout into `b[region_off..region_off+len]`
/// (a whole 4 KiB block, or an inode's inline-dentry region).
/// `entries` = (name, ino, file_type, live); `live:false` writes residue
/// (dirent + name bytes present, bitmap bit clear).
fn write_dentries(b: &mut [u8], region_off: usize, len: usize, entries: &[(&[u8], u32, u8, bool)]) {
    let nr = len * 8 / (19 * 8 + 1);
    let bitmap_len = nr.div_ceil(8);
    let dentry_off = region_off + bitmap_len + (len - (19 * nr + bitmap_len));
    let filename_off = dentry_off + 11 * nr;
    let mut slot = 0usize;
    for (name, ino, ft, live) in entries {
        let slots = name.len().div_ceil(8).max(1);
        let de = dentry_off + slot * 11;
        put_u32(b, de, 0xCAFE); // hash
        put_u32(b, de + 4, *ino);
        put_u16(b, de + 8, name.len() as u16);
        b[de + 10] = *ft;
        for (i, ch) in name.iter().enumerate() {
            b[filename_off + slot * 8 + i] = *ch;
        }
        if *live {
            for s in slot..slot + slots {
                b[region_off + s / 8] |= 1 << (s % 8);
            }
        }
        slot += slots;
    }
}

/// A complete synthetic image with all fixture content.
/// `Vec<u8>` implements `ByteSource` directly.
pub fn image() -> Arc<Vec<u8>> {
    Img::new().build()
}

/// A *minimal* valid image (~104 KiB) — small enough to seed a fuzz
/// corpus, complete enough to mount, walk and recover one deleted file.
///
/// Geometry: 4 KiB blocks, 2 blocks/segment (`log_blocks_per_seg = 1`):
///
/// ```text
/// blocks 0..2    superblocks
/// blk 2..6       checkpoint area (packs at 2 and 4, 2 blocks each)
/// blk 6..10      SIT  (copy A blk 6, copy B blk 8)
/// blk 10..14     NAT  (copy A blks 10-11, copy B blks 12-13)
/// blk 14..18     SSA
/// blk 18..26     main area (4 segments of 2 blocks)
/// ```
///
/// Contents: root dir (nid 3) with live `file.txt` (nid 4) and deleted
/// residue `old.txt` (nid 5); nid 5 is free in the current NAT but its
/// stale copy still maps the surviving inode+data in SIT-free segment 2.
pub fn minimal_image() -> Arc<Vec<u8>> {
    const BPS: u64 = 2; // blocks per segment
    // blk numbers
    const CP: u64 = 2;
    const SIT: u64 = 6;
    const NAT: u64 = 10;
    const SSA: u64 = 14;
    const MAIN: u64 = 18;
    const SEGS: u32 = 12; // 2 ckpt + 2 sit + 2 nat + 2 ssa + 4 main
    const NBLK: usize = 2 + SEGS as usize * BPS as usize; // 26

    fn block_mut(bytes: &mut [u8], n: u64) -> &mut [u8] {
        let s = n as usize * BLK;
        &mut bytes[s..s + BLK]
    }
    let mut bytes = vec![0u8; NBLK * BLK];

    // --- superblocks ---
    for base in [0x400usize, 0x1400] {
        let sb = &mut bytes[base..base + 0xC00];
        put_u32(sb, 0, 0xF2F5_2010);
        put_u16(sb, 4, 1);
        put_u16(sb, 6, 15);
        put_u32(sb, 8, 9); // log_sectorsize
        put_u32(sb, 12, 3); // log_sectors_per_block
        put_u32(sb, 16, 12); // log_blocksize
        put_u32(sb, 20, 1); // log_blocks_per_seg = 2 blocks
        put_u32(sb, 24, 1); // segs_per_sec
        put_u32(sb, 28, 1); // secs_per_zone
        put_u32(sb, 32, 3068); // checksum_offset
        put_u64(sb, 36, NBLK as u64); // block_count
        put_u32(sb, 44, SEGS); // section_count
        put_u32(sb, 48, SEGS); // segment_count
        put_u32(sb, 52, 2); // ckpt
        put_u32(sb, 56, 2); // sit
        put_u32(sb, 60, 2); // nat
        put_u32(sb, 64, 2); // ssa
        put_u32(sb, 68, 4); // main
        put_u32(sb, 72, 2); // segment0_blkaddr
        put_u32(sb, 76, CP as u32);
        put_u32(sb, 80, SIT as u32);
        put_u32(sb, 84, NAT as u32);
        put_u32(sb, 88, SSA as u32);
        put_u32(sb, 92, MAIN as u32);
        put_u32(sb, 96, 3); // root_ino
        put_u32(sb, 100, 1); // node_ino
        put_u32(sb, 104, 2); // meta_ino
        let crc = crc32(0xF2F5_2010, &sb[..3068]);
        put_u32(sb, 3068, crc);
    }

    // --- checkpoint packs (pack_total 2: [cp][cp copy]) ---
    for p in [CP, CP + BPS] {
        for n in [p, p + 1] {
            let b = block_mut(&mut bytes, n);
            put_u64(b, 0, CKPT_VER);
            put_u64(b, 8, 4 * BPS); // user_block_count
            put_u64(b, 16, 4); // valid_block_count
            put_u32(b, 32, 2); // free_segment_count
            put_u32(b, 132, 0x0001); // UMOUNT
            put_u32(b, 136, 2); // pack_total
            put_u32(b, 140, 1); // start_sum
            put_u32(b, 152, 6); // next_free_nid
            put_u32(b, 156, 4); // sit bitmap bytes
            put_u32(b, 160, 4); // nat bitmap bytes (all zero → copy A)
            put_u32(b, 164, 512); // checksum_offset
            let crc = {
                let c = crc32(0xF2F5_2010, &b[..512]);
                crc32(c, &b[516..])
            };
            put_u32(b, 512, crc);
        }
    }

    // --- SIT copy A (blk 6): segs 0,1 valid; 2,3 free ---
    {
        let b = block_mut(&mut bytes, SIT);
        for (i, live) in [(0usize, 2u16), (1, 2)] {
            let e = &mut b[i * 74..i * 74 + 74];
            put_u16(e, 0, live);
            e[2] |= 0b11; // blkoffs 0,1 valid
            put_u64(e, 66, 42);
        }
    }

    // --- NAT copies: A blk 10 (current), B blk 12 (stale) ---
    {
        let ent = |b: &mut [u8], nid: usize, blk: u32| {
            b[nid * 9] = 1;
            put_u32(b, nid * 9 + 1, nid as u32);
            put_u32(b, nid * 9 + 5, blk);
        };
        let a = block_mut(&mut bytes, NAT);
        ent(a, 3, MAIN as u32); // root inode
        ent(a, 4, (MAIN + 2) as u32); // file.txt inode
        let s = block_mut(&mut bytes, NAT + BPS);
        ent(s, 3, MAIN as u32);
        ent(s, 4, (MAIN + 2) as u32);
        ent(s, 5, (MAIN + 4) as u32); // deleted nid — stale copy only
    }

    // --- main area ---
    // inode helper: node block with footer nid==ino.
    let inode_at = |bytes: &mut Vec<u8>, blk: u64, nid: u32, mode: u16, size: u64,
                        name: &[u8], addrs: &[u32], cp_ver: u64| {
        let s = blk as usize * BLK;
        let b = &mut bytes[s..s + BLK];
        put_u16(b, 0, mode);
        put_u32(b, 4, 1000);
        put_u32(b, 8, 1000);
        put_u32(b, 12, 1);
        put_u64(b, 16, size);
        put_u64(b, 24, size / BLK as u64 + 1);
        put_u64(b, 32, MTIME_SEC);
        put_u64(b, 40, MTIME_SEC);
        put_u64(b, 48, MTIME_SEC);
        put_u32(b, 56, MTIME_NSEC);
        put_u32(b, 60, MTIME_NSEC);
        put_u32(b, 64, MTIME_NSEC);
        put_u32(b, 88, name.len() as u32);
        put(b, 92, name);
        for (i, &a) in addrs.iter().enumerate() {
            put_u32(b, 360 + i * 4, a);
        }
        put_u32(b, BLK - 24, nid);
        put_u32(b, BLK - 20, nid);
        put_u64(b, BLK - 12, cp_ver);
    };
    inode_at(&mut bytes, MAIN, 3, 0o040755, BLK as u64, b"/", &[(MAIN + 1) as u32], CKPT_VER);
    write_dentries(
        block_mut(&mut bytes, MAIN + 1),
        0,
        BLK,
        &[
            (b".", 3, 2, true),
            (b"..", 3, 2, true),
            (b"file.txt", 4, 1, true),
            (b"old.txt", 5, 1, false), // residue
        ],
    );
    inode_at(&mut bytes, MAIN + 2, 4, 0o100644, 10, b"file.txt", &[(MAIN + 3) as u32], CKPT_VER);
    put(block_mut(&mut bytes, MAIN + 3), 0, b"hello fuzz");
    // deleted nid 5: inode + data in SIT-free segment 2.
    inode_at(&mut bytes, MAIN + 4, 5, 0o100644, 18, b"old.txt", &[(MAIN + 5) as u32], OLD_CKPT_VER);
    put(block_mut(&mut bytes, MAIN + 5), 0, b"stale deleted data");

    let _ = SSA; // summaries left zeroed — no reallocated blocks here
    Arc::new(bytes)
}

/// `secret.bin` ciphertext bytes (never decrypted — flagged only).
pub const SECRET_CONTENT: &[u8] = b"\x99\xc7\x01 encrypted bytes \xde\xad";
