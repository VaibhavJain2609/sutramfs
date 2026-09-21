//! Synthetic XFS v5 image builder.
//!
//! Constructs byte-accurate filesystem images: big-endian fields, correct
//! CRC32C checksums (LE-stored, field zeroed), real btree/dir3/inode
//! structures — close enough to `mkfs.xfs` output that the parser must do
//! real work, not pattern matching.
//!
//! Geometry (defaults): 4 KiB blocks, 512 B sectors, 256 B inodes,
//! 16 inodes/block, one AG, dirblklog=0.

#![allow(dead_code)]

pub const BS: usize = 4096;
pub const SECT: usize = 512;
pub const ISZ: usize = 256;
pub const INOPB: u32 = 16; // inodes per block (4096/256)
pub const AGBLOCKS: u32 = 512;
pub const UUID: [u8; 16] = [0xA5; 16];
pub const ROOTINO: u64 = 64; // chunk at agbno 4 (64>>4)

pub const SB_MAGIC: u32 = 0x5846_5342; // 'XFSB'
pub const AGF_MAGIC: u32 = 0x5841_4746; // 'XAGF'
pub const AGI_MAGIC: u32 = 0x5841_4749; // 'XAGI'
pub const AGFL_MAGIC: u32 = 0x5841_464C; // 'XAFL'
pub const AB3B: u32 = 0x4142_3342;
pub const IAB3: u32 = 0x4941_4233;
pub const FIB3: u32 = 0x4649_4233;
pub const XDB3: u32 = 0x5844_4233;
pub const INO_MAGIC: u16 = 0x494E; // 'IN'
pub const NULLAGINO: u32 = u32::MAX;
pub const NULLAGBLOCK: u32 = u32::MAX;

// ---- CRC32C (Castagnoli) — table-free bitwise impl, fine for tests ----

pub fn crc32c(seed: u32, mut crc: u32, buf: &[u8]) -> u32 {
    const POLY: u32 = 0x82F6_3B78;
    crc ^= seed;
    for &b in buf {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (POLY & 0u32.wrapping_sub(crc & 1));
        }
    }
    crc
}

/// XFS checksum: ~crc32c(~0, buf with field zeroed), stored little-endian.
pub fn write_crc(buf: &mut [u8], crc_off: usize) {
    buf[crc_off..crc_off + 4].fill(0);
    let c = !crc32c(0xFFFF_FFFF, 0, buf);
    buf[crc_off..crc_off + 4].copy_from_slice(&c.to_le_bytes());
}

// ---- big-endian writers ----

pub fn w16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_be_bytes());
}
pub fn w32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_be_bytes());
}
pub fn w64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_be_bytes());
}

/// One inode-chunk record for inobt/finobt.
#[derive(Clone, Copy)]
pub struct ChunkRec {
    pub startino: u32,
    pub freecount: u32,
    pub free: u64,
}

/// A file extent (bmbt record inputs).
#[derive(Clone, Copy)]
pub struct ExtentSpec {
    pub fileoff: u64,
    pub fsb: u64,
    pub len: u32,
    pub unwritten: bool,
}

/// Encode a 16-byte extent record (big-endian, unwritten flag bit 63).
pub fn extent_rec(e: &ExtentSpec) -> [u8; 16] {
    let l0 = ((e.unwritten as u64) << 63) | (e.fileoff << 9) | (e.fsb >> 43);
    let l1 = (e.fsb << 21) | e.len as u64;
    let mut r = [0u8; 16];
    r[..8].copy_from_slice(&l0.to_be_bytes());
    r[8..].copy_from_slice(&l1.to_be_bytes());
    r
}

pub struct InodeSpec {
    pub mode: u16,
    pub format: u8, // 1=local 2=extents 3=btree 0=dev
    pub size: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub atime: u64, // packed {sec,nsec}
    pub mtime: u64,
    pub ctime: u64,
    pub nblocks: u64,
    pub extents: Vec<ExtentSpec>,
    pub inline_data: Vec<u8>,
    pub next_unlinked: u32,
    pub flags: u16,
}

impl Default for InodeSpec {
    fn default() -> Self {
        InodeSpec {
            mode: 0o100644,
            format: 2,
            size: 0,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            atime: (1_700_000_000 << 32) | 111,
            mtime: (1_700_000_100 << 32) | 222,
            ctime: (1_700_000_200 << 32) | 333,
            nblocks: 0,
            extents: Vec::new(),
            inline_data: Vec::new(),
            next_unlinked: NULLAGINO,
            flags: 0,
        }
    }
}

/// Build a shortform (LOCAL) directory fork payload.
pub fn sf_dir(parent_ino: u64, entries: &[(&str, u64, u8)]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(entries.len() as u8); // count
    v.push(0); // i8count=0 → 4-byte inos
    v.extend_from_slice(&(parent_ino as u32).to_be_bytes());
    for (name, ino, ftype) in entries {
        v.push(name.len() as u8);
        v.extend_from_slice(&(v.len() as u16).to_be_bytes()); // fake offset
        v.extend_from_slice(name.as_bytes());
        v.push(*ftype);
        v.extend_from_slice(&(*ino as u32).to_be_bytes());
    }
    v
}

/// The image under construction.
pub struct Img {
    pub b: Vec<u8>,
    pub agblocks: u32,
    /// bnobt free extents (sorted by startblock).
    pub free: Vec<(u32, u32)>,
    /// inobt chunk records.
    pub inobt: Vec<ChunkRec>,
    /// finobt chunk records.
    pub finobt: Vec<ChunkRec>,
    /// agi_unlinked buckets (agino or NULLAGINO).
    pub unlinked: [u32; 64],
    pub logstart: u64,
    pub logblocks: u32,
    pub icount: u64,
    pub ifree: u64,
    /// v5 features: ftype + finobt.
    pub incompat: u32,
    pub ro_compat: u32,
    /// When true, skip writing checksums (corrupt-image tests).
    pub write_crcs: bool,
}

impl Img {
    pub fn new() -> Self {
        Img {
            b: vec![0; AGBLOCKS as usize * BS],
            agblocks: AGBLOCKS,
            free: Vec::new(),
            inobt: Vec::new(),
            finobt: Vec::new(),
            unlinked: [NULLAGINO; 64],
            logstart: 16,
            logblocks: 8,
            icount: 0,
            ifree: 0,
            incompat: 0x1,  // FTYPE
            ro_compat: 0x1, // FINOBT
            write_crcs: true,
        }
    }

    pub fn blk_mut(&mut self, agbno: u32) -> &mut [u8] {
        let s = agbno as usize * BS;
        &mut self.b[s..s + BS]
    }

    /// Byte offset of inode `ino` (ag0 only).
    pub fn ino_pos(&self, ino: u64) -> usize {
        ((ino >> 4) as usize) * BS + ((ino % INOPB as u64) as usize) * ISZ
    }

    /// Write a v3 inode (with valid CRC) at `ino`.
    pub fn write_inode(&mut self, ino: u64, spec: &InodeSpec) {
        let pos = self.ino_pos(ino);
        let ib = &mut self.b[pos..pos + ISZ];
        w16(ib, 0, INO_MAGIC);
        w16(ib, 2, spec.mode);
        ib[4] = 3; // version
        ib[5] = spec.format;
        w16(ib, 6, spec.nlink.min(0xFFFF) as u16); // onlink
        w32(ib, 8, spec.uid);
        w32(ib, 12, spec.gid);
        w32(ib, 16, spec.nlink);
        w64(ib, 32, spec.atime);
        w64(ib, 40, spec.mtime);
        w64(ib, 48, spec.ctime);
        w64(ib, 56, spec.size);
        w64(ib, 64, spec.nblocks);
        w32(ib, 76, spec.extents.len() as u32);
        w16(ib, 80, 0); // anextents
        ib[82] = 0; // forkoff
        ib[83] = 0; // aformat
        w16(ib, 90, spec.flags);
        w32(ib, 92, 7); // generation
        w32(ib, 96, spec.next_unlinked);
        // v3 extras
        w64(ib, 104, 1); // change_count
        w64(ib, 112, 0x1122); // lsn
        w64(ib, 120, 0); // flags2
        w64(ib, 144, (1_699_999_000u64 << 32) | 99); // crtime
        w64(ib, 152, ino); // di_ino
        ib[160..176].copy_from_slice(&UUID);
        // fork data at 176
        if spec.format == 1 {
            let n = spec.inline_data.len().min(ISZ - 176);
            ib[176..176 + n].copy_from_slice(&spec.inline_data[..n]);
        } else {
            for (i, e) in spec.extents.iter().enumerate() {
                let p = 176 + i * 16;
                if p + 16 > ISZ {
                    break;
                }
                ib[p..p + 16].copy_from_slice(&extent_rec(e));
            }
        }
        // CRC last (field at 100, LE, covers ISZ bytes).
        if self.write_crcs {
            write_crc(ib, 100);
        }
    }

    /// Write a block-format directory (XDB3) at `agbno`.
    ///
    /// `entries` = live `{ino, name, ftype}` triples (excluding "."/".."
    /// which the caller includes explicitly). `deleted` writes the entry
    /// then stamps a free run over its head (residue recovery target).
    pub fn write_block_dir(
        &mut self,
        agbno: u32,
        owner_ino: u64,
        entries: &[(&str, u64, u8)],
        deleted: &[(&str, u64, u8)],
    ) {
        let blk = &mut self.b[agbno as usize * BS..agbno as usize * BS + BS];
        // dir3 blk hdr
        w32(blk, 0, XDB3);
        w64(blk, 8, agbno as u64); // blkno (daddr ok)
        w64(blk, 16, 0x2222); // lsn
        blk[24..40].copy_from_slice(&UUID);
        w64(blk, 40, owner_ino);
        // best_free[3] at 48 (each {u16 off, u16 len}); pad at 60;
        // entries from sizeof(xfs_dir3_data_hdr) = 64.
        let mut off = 64usize;
        // Live entries first, then deleted (which get freed).
        for (name, ino, ftype) in entries.iter().chain(deleted.iter()) {
            let namelen = name.len();
            let esize = ((9 + namelen + 1 + 2) + 7) & !7;
            w64(blk, off, *ino);
            blk[off + 8] = namelen as u8;
            blk[off + 9..off + 9 + namelen].copy_from_slice(name.as_bytes());
            blk[off + 9 + namelen] = *ftype;
            w16(blk, off + esize - 2, off as u16); // tag
            off += esize;
        }
        // Convert deleted entries' space into a free run.
        if !deleted.is_empty() {
            let dstart = 64 + entries
                .iter()
                .map(|(n, _, _)| ((9 + n.len() + 1 + 2) + 7) & !7)
                .sum::<usize>();
            let dlen = off - dstart;
            w16(blk, dstart, 0xFFFF); // freetag
            w16(blk, dstart + 2, dlen as u16); // length
            w16(blk, dstart + dlen - 2, dstart as u16); // tail tag
            // best_free[0] = {u16 off, u16 len} points at the run.
            w16(blk, 48, dstart as u16);
            w16(blk, 50, dlen as u16);
        }
        // Tail: leaf count + stale count at blksize-8.
        w32(blk, BS - 8, 0); // leaf count = 0 (no leaf entries needed)
        w32(blk, BS - 4, 0); // stale
        // Pad the gap between last entry and tail with a free run so the
        // entry chain terminates cleanly.
        let tail = BS - 8;
        if off < tail {
            w16(blk, off, 0xFFFF);
            w16(blk, off + 2, (tail - off) as u16);
            w16(blk, tail - 2, off as u16);
        }
        if self.write_crcs {
            write_crc(blk, 4);
        }
    }

    /// Write raw file data at fsblock `fsb` (ag0).
    pub fn write_data(&mut self, fsb: u64, data: &[u8]) {
        let s = fsb as usize * BS;
        let n = data.len().min(BS);
        self.b[s..s + n].copy_from_slice(&data[..n]);
    }

    /// Write the XLOG record magic at the log start (journal flagging).
    pub fn write_log_magic(&mut self) {
        let s = self.logstart as usize * BS;
        w32(&mut self.b, s, 0xFEED_BABE);
        w32(&mut self.b, s + 4, 2); // cycle
    }

    /// Write a v5 sblock btree leaf at `agbno` with raw record bytes.
    fn sblock_leaf(&mut self, agbno: u32, magic: u32, owner: u64, recs: &[&[u8]]) {
        let blk = &mut self.b[agbno as usize * BS..agbno as usize * BS + BS];
        w32(blk, 0, magic);
        w16(blk, 4, 0); // level 0 = leaf
        w16(blk, 6, recs.len() as u16);
        w32(blk, 8, NULLAGBLOCK);
        w32(blk, 12, NULLAGBLOCK);
        w64(blk, 16, agbno as u64); // blkno
        w64(blk, 24, 0x4444); // lsn
        blk[32..48].copy_from_slice(&UUID);
        w64(blk, 48, owner);
        let mut p = 56usize;
        for r in recs {
            blk[p..p + r.len()].copy_from_slice(r);
            p += r.len();
        }
        if self.write_crcs {
            write_crc(blk, 52);
        }
    }

    /// Emit AG headers, btrees and the superblock; returns image bytes.
    pub fn finish(mut self) -> Vec<u8> {
        // bnobt leaf at agbno 1.
        let bno_recs: Vec<Vec<u8>> = self
            .free
            .iter()
            .map(|&(s, l)| {
                let mut r = Vec::with_capacity(8);
                r.extend_from_slice(&s.to_be_bytes());
                r.extend_from_slice(&l.to_be_bytes());
                r
            })
            .collect();
        let rb: Vec<&[u8]> = bno_recs.iter().map(|r| r.as_slice()).collect();
        self.sblock_leaf(1, AB3B, 0, &rb);
        // inobt leaf at agbno 2.
        let it_recs: Vec<Vec<u8>> = self
            .inobt
            .iter()
            .map(|c| {
                let mut r = Vec::with_capacity(16);
                r.extend_from_slice(&c.startino.to_be_bytes());
                r.extend_from_slice(&c.freecount.to_be_bytes());
                r.extend_from_slice(&c.free.to_be_bytes());
                r
            })
            .collect();
        let ri: Vec<&[u8]> = it_recs.iter().map(|r| r.as_slice()).collect();
        self.sblock_leaf(2, IAB3, 0, &ri);
        // finobt leaf at agbno 3.
        let ft_recs: Vec<Vec<u8>> = self
            .finobt
            .iter()
            .map(|c| {
                let mut r = Vec::with_capacity(16);
                r.extend_from_slice(&c.startino.to_be_bytes());
                r.extend_from_slice(&c.freecount.to_be_bytes());
                r.extend_from_slice(&c.free.to_be_bytes());
                r
            })
            .collect();
        let rf: Vec<&[u8]> = ft_recs.iter().map(|r| r.as_slice()).collect();
        self.sblock_leaf(3, FIB3, 0, &rf);

        // AGF at sector 1.
        {
            let b = &mut self.b[SECT..2 * SECT];
            w32(b, 0, AGF_MAGIC);
            w32(b, 4, 1); // version
            w32(b, 8, 0); // seqno
            w32(b, 12, self.agblocks);
            w32(b, 16, 1); // bnobt root
            w32(b, 20, 1); // cntbt root (shares bnobt blk for tests? no — set valid)
            w32(b, 24, 0); // rmapbt root (absent)
            w32(b, 28, 1); // bnobt level
            w32(b, 32, 1); // cntbt level
            w32(b, 36, 0); // rmapbt level
            w32(b, 40, 0); // flfirst
            w32(b, 44, 0); // fllast
            w32(b, 48, 0); // flcount
            let freeblks: u32 = self.free.iter().map(|&(_, l)| l).sum();
            w32(b, 52, freeblks);
            w32(b, 56, freeblks); // longest (approx)
            w32(b, 60, 3); // btreeblks
            b[64..80].copy_from_slice(&UUID);
            w64(b, 208, 0x99); // lsn
            if self.write_crcs {
                write_crc(b, 216);
            }
        }
        // AGI at sector 2.
        {
            let b = &mut self.b[2 * SECT..3 * SECT];
            w32(b, 0, AGI_MAGIC);
            w32(b, 4, 1); // version
            w32(b, 8, 0); // seqno
            w32(b, 12, self.agblocks);
            let count: u32 = self
                .inobt
                .iter()
                .map(|c| 64 - c.freecount)
                .sum();
            w32(b, 16, count);
            w32(b, 20, 2); // inobt root
            w32(b, 24, 1); // level
            let freec: u32 = self.inobt.iter().map(|c| c.freecount).sum();
            w32(b, 28, freec);
            w32(b, 32, 64); // newino
            for i in 0..64 {
                w32(b, 40 + i * 4, self.unlinked[i]);
            }
            b[296..312].copy_from_slice(&UUID);
            w64(b, 320, 0x77); // lsn
            w32(b, 328, 3); // free_root (finobt)
            w32(b, 332, 1); // free_level
            if self.write_crcs {
                write_crc(b, 312);
            }
        }
        // AGFL at sector 3 — magic only (v5).
        {
            let b = &mut self.b[3 * SECT..4 * SECT];
            w32(b, 0, AGFL_MAGIC);
            w64(b, 8, 3); // blkno-ish
            b[24..40].copy_from_slice(&UUID);
            if self.write_crcs {
                write_crc(b, 4);
            }
        }
        // Superblock at sector 0.
        {
            let b = &mut self.b[..SECT];
            w32(b, 0, SB_MAGIC);
            w32(b, 4, BS as u32);
            w64(b, 8, self.agblocks as u64); // dblocks (1 AG)
            w64(b, 16, 0); // rblocks
            b[32..48].copy_from_slice(&UUID);
            w64(b, 48, self.logstart);
            w64(b, 56, ROOTINO);
            w32(b, 80, 1); // rextsize
            w32(b, 84, self.agblocks);
            w32(b, 88, 1); // agcount
            w32(b, 96, self.logblocks);
            w16(b, 100, 0xB4B5); // v5 + feature bits
            w16(b, 102, SECT as u16);
            w16(b, 104, ISZ as u16);
            w16(b, 106, INOPB as u16);
            b[108..120].copy_from_slice(b"TESTXFS\0\0\0\0\0");
            b[120] = 12; // blocklog
            b[121] = 9; // sectlog
            b[122] = 8; // inodelog
            b[123] = 4; // inopblog
            b[124] = 9; // agblklog (ceil log2 512)
            b[125] = 0; // rextslog
            b[126] = 0; // inprogress
            w64(b, 128, self.icount);
            w64(b, 136, self.ifree);
            let fdblocks: u64 = self.free.iter().map(|&(_, l)| l as u64).sum();
            w64(b, 144, fdblocks);
            b[192] = 0; // dirblklog
            w32(b, 200, 0x2808); // features2 = ATTR2|PROJID32BIT|LAZYSB…
            w32(b, 208, 0); // compat
            w32(b, 212, self.ro_compat);
            w32(b, 216, self.incompat);
            w32(b, 220, 0); // log_incompat
            w64(b, 240, 0x5555); // lsn
            b[248..264].copy_from_slice(&UUID);
            if self.write_crcs {
                write_crc(b, 224);
            }
        }
        self.write_log_magic();
        self.b
    }
}
