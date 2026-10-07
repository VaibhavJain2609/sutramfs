//! Synthetic NTFS image construction for tests.
//!
//! Builds a byte-exact NTFS volume in a `Vec<u8>`: boot sector, $MFT with
//! fixup-carrying FILE records (resident + non-resident + ADS + deleted +
//! partial + fragmented + compressed + attribute-list cases), $BITMAP, and
//! an INDX index block with slack residue. No fixture files, no network.
//!
//! Geometry: 512 B/sector, 8 sectors/cluster (4 KiB clusters), 1024 B FILE
//! records, 4096 B INDX records, $MFT at LCN 4, 2048 clusters (8 MiB).
//!
//! Cluster map:
//!
//! | clusters | contents                                            |
//! |----------|-----------------------------------------------------|
//! | 0        | boot sector                                          |
//! | 4–23     | $MFT (4–19 used records, 20–23 slack w/ fragment @70)  |
//! | 30       | $Bitmap data                                         |
//! | 31–34    | $LogFile (RSTR/RCRD/CHKD pages)                                             |
//! | 35       | $UsnJrnl:$J (USN records)                                          |
//! | 40–43    | BIG.BIN                                              |
//! | 44–45,46–47 | SPARSE.BIN (hole between)                       |
//! | 50–51    | DELETED1.TXT (freed, intact)                          |
//! | 52–53    | NEWFILE.TXT (live — overwrote PARTIAL's first extent)  |
//! | 54–55    | PARTIAL.BIN surviving tail                            |
//! | 60,61    | EVIL.DOC (MZ), RESUME.DOCX (PK)                       |
//! | 62       | BITDEL.TXT (deleted, still marked in $BITMAP)           |
//! | 63       | DELDIR $INDEX_ALLOCATION (deleted dir)                  |
//! | 64       | COMPRESS.BIN LZNT1 unit                               |
//! | 70–71,72–73 | ATTRLIST.BIN split extents                       |
//! | 80       | root dir INDX block (live + slack + dangling entries)  |
//! | 84,85    | DECOY.DAT (live), stale ext-record data                |
//! | 86–87,88–89 | DELSPRSE.BIN surviving runs (sparse hole between) |
//! | 96–111   | RAWCMP.BIN unit 0 stored raw (unit 1 is fully sparse)   |
//! | 120–123  | GAPDATA.BIN extent (VCN gap before it)                  |

pub const BPS: usize = 512;
pub const SPC: usize = 8;
pub const CSZ: usize = BPS * SPC; // 4096
pub const REC_SIZE: usize = 1024;
pub const INDX_SIZE: usize = 4096;
pub const TOTAL_SECTORS: u32 = 16384;
pub const TOTAL_CLUSTERS: u32 = TOTAL_SECTORS / SPC as u32; // 2048
pub const MFT_LCN: u32 = 4;
pub const MFT_OFF: usize = MFT_LCN as usize * CSZ;
/// $MFT occupies clusters 4..24 (20 clusters = 80 records); used size
/// covers records 0..63 (16 clusters) — records 64+ are MFT slack.
pub const MFT_CLUSTERS: u32 = 20;
pub const MFT_USED_CLUSTERS: u32 = 16;

pub const FLG_INUSE: u16 = 0x01;
pub const FLG_DIR: u16 = 0x02;

pub const T_SI: u32 = 0x10;
pub const T_ALIST: u32 = 0x20;
pub const T_FN: u32 = 0x30;
pub const T_OBJID: u32 = 0x40;
pub const T_VNAME: u32 = 0x60;
pub const T_VINFO: u32 = 0x70;
pub const T_DATA: u32 = 0x80;
pub const T_IROOT: u32 = 0x90;
pub const T_IALLOC: u32 = 0xA0;
pub const T_BITMAP: u32 = 0xB0;
pub const T_REPARSE: u32 = 0xC0;
pub const T_EAINFO: u32 = 0xD0;
pub const T_EA: u32 = 0xE0;

pub const AFLAG_COMPRESSED: u16 = 0x0001;
pub const AFLAG_SPARSE: u16 = 0x8000;

/// FILETIME for unix seconds.
pub fn ft(sec: i64) -> u64 {
    (116_444_736_000_000_000i64 + sec * 10_000_000) as u64
}

// ---- little-endian writers ----------------------------------------------
pub fn w16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
pub fn w32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
pub fn w64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Absolute byte offset of cluster `c`.
pub fn clus_off(c: u32) -> usize {
    c as usize * CSZ
}

/// Absolute byte offset of MFT record `n`.
pub fn rec_off(n: u32) -> usize {
    MFT_OFF + n as usize * REC_SIZE
}

/// Write data at a cluster.
pub fn put(img: &mut [u8], cluster: u32, data: &[u8]) {
    img[clus_off(cluster)..clus_off(cluster) + data.len()].copy_from_slice(data);
}

/// Mark cluster `c` allocated/free in the volume bitmap at cluster 30.
pub fn bitmap_set(img: &mut [u8], c: u32, allocated: bool) {
    let off = clus_off(30) + (c / 8) as usize;
    if allocated {
        img[off] |= 1 << (c % 8);
    } else {
        img[off] &= !(1 << (c % 8));
    }
}

// ---- runlist encoding -----------------------------------------------------

/// Encode `(len_clusters, Option<lcn>)` runs into NTFS runlist bytes.
/// LCNs are absolute; deltas are computed internally.
pub fn runlist(runs: &[(u64, Option<u64>)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut prev_lcn: i64 = 0;
    for &(len, lcn) in runs {
        // minimal unsigned field size for the length
        let mut len_sz = 1usize;
        while len_sz < 8 && (len >> (len_sz * 8)) != 0 {
            len_sz += 1;
        }
        match lcn {
            Some(l) => {
                let delta = l as i64 - prev_lcn;
                prev_lcn = l as i64;
                // minimal *signed* field size for the delta
                let mut off_sz = 1usize;
                while off_sz < 8 {
                    let shift = off_sz * 8;
                    let min = -(1i64 << (shift - 1));
                    let max = (1i64 << (shift - 1)) - 1;
                    if delta >= min && delta <= max {
                        break;
                    }
                    off_sz += 1;
                }
                out.push(((off_sz as u8) << 4) | len_sz as u8);
                for i in 0..len_sz {
                    out.push((len >> (i * 8)) as u8);
                }
                for i in 0..off_sz {
                    out.push((delta >> (i * 8)) as u8);
                }
            }
            None => {
                out.push(len_sz as u8);
                for i in 0..len_sz {
                    out.push((len >> (i * 8)) as u8);
                }
            }
        }
    }
    out.push(0);
    out
}

// ---- attribute builders ---------------------------------------------------

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect()
}

/// Resident attribute: `(type, name, content)` → encoded bytes (8-aligned).
pub fn attr_resident(type_code: u32, name: &str, content: &[u8], id: u16) -> Vec<u8> {
    let nb = utf16(name);
    let name_off = 0x18usize;
    let content_off = name_off + nb.len();
    let len = (content_off + content.len() + 7) & !7;
    let mut a = vec![0u8; len];
    w32(&mut a, 0, type_code);
    w32(&mut a, 4, len as u32);
    a[8] = 0; // resident
    a[9] = (nb.len() / 2) as u8;
    w16(&mut a, 10, name_off as u16);
    w16(&mut a, 14, id);
    w32(&mut a, 16, content.len() as u32);
    w16(&mut a, 20, content_off as u16);
    a[name_off..name_off + nb.len()].copy_from_slice(&nb);
    a[content_off..content_off + content.len()].copy_from_slice(content);
    a
}

/// Non-resident attribute. `runs` = `[(len, Option<lcn>)]`.
#[allow(clippy::too_many_arguments)]
pub fn attr_nonresident(
    type_code: u32,
    name: &str,
    runs: &[(u64, Option<u64>)],
    first_vcn: u64,
    alloc_size: u64,
    real_size: u64,
    init_size: u64,
    flags: u16,
    comp_shift: u8,
    id: u16,
) -> Vec<u8> {
    let nb = utf16(name);
    let rl = runlist(runs);
    let name_off = 0x40usize;
    let runs_off = name_off + nb.len();
    let len = (runs_off + rl.len() + 7) & !7;
    let mut a = vec![0u8; len];
    w32(&mut a, 0, type_code);
    w32(&mut a, 4, len as u32);
    a[8] = 1; // non-resident
    a[9] = (nb.len() / 2) as u8;
    w16(&mut a, 10, name_off as u16);
    w16(&mut a, 12, flags);
    w16(&mut a, 14, id);
    w64(&mut a, 16, first_vcn);
    let last_vcn = first_vcn + runs.iter().map(|r| r.0).sum::<u64>() - 1;
    w64(&mut a, 24, last_vcn);
    w16(&mut a, 32, runs_off as u16);
    a[34] = comp_shift;
    w64(&mut a, 40, alloc_size);
    w64(&mut a, 48, real_size);
    w64(&mut a, 56, init_size);
    a[name_off..name_off + nb.len()].copy_from_slice(&nb);
    a[runs_off..runs_off + rl.len()].copy_from_slice(&rl);
    a
}

// ---- journal payloads ($LogFile LFS pages, $UsnJrnl USN records) -----------

/// Build a 4 KiB LFS page (`RSTR`/`RCRD`/`CHKD`/`BAAD`): multisig header,
/// USA at offset 8, `data` = `(offset, bytes)` patches applied pre-fixup.
pub fn lfs_page(sig: &[u8; 4], data: &[(usize, Vec<u8>)]) -> Vec<u8> {
    const SEQ: u16 = 0xA5A5;
    let mut page = vec![0u8; CSZ];
    page[0..4].copy_from_slice(sig);
    let sectors = CSZ / BPS;
    let usa_off = 8usize;
    w16(&mut page, 4, usa_off as u16);
    w16(&mut page, 6, (sectors + 1) as u16);
    for (off, bytes) in data {
        page[*off..*off + bytes.len()].copy_from_slice(bytes);
    }
    w16(&mut page, usa_off, SEQ);
    for i in 0..sectors {
        let trailer = (i + 1) * BPS - 2;
        let orig = u16::from_le_bytes([page[trailer], page[trailer + 1]]);
        w16(&mut page, usa_off + 2 + i * 2, orig);
        w16(&mut page, trailer, SEQ);
    }
    page
}

/// RESTART_AREA body (written at offset 0x30 of an RSTR page).
pub fn restart_area() -> Vec<u8> {
    let mut a = vec![0u8; 0x36];
    w64(&mut a, 0x00, 0x4A00); // current_lsn
    w16(&mut a, 0x08, 1); // log_clients
    w32(&mut a, 0x1A, 34); // seq_nr_bits
    w16(&mut a, 0x1E, 0x36); // restart_area_len
    w64(&mut a, 0x24, 0x4000); // file_size
    w32(&mut a, 0x2C, 0x48); // last_lsn_data_len
    w16(&mut a, 0x30, 0x1000); // record_page_len
    a
}

/// LOG_RECORD header + client data (extent = 0x48 + data, 8-aligned).
#[allow(dead_code)]
pub fn log_record(lsn: u64, rtype: u32, tid: u32, client_data: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; 0x48 + client_data.len()];
    w64(&mut r, 0x00, lsn); // this_lsn
    w64(&mut r, 0x08, lsn.saturating_sub(0x40)); // client_prev_lsn
    w16(&mut r, 0x18, client_data.len() as u16); // client_data_len
    w32(&mut r, 0x1C, rtype); // record_type
    w32(&mut r, 0x20, tid); // transaction_id
    w16(&mut r, 0x28, 0x01); // redo_op
    w16(&mut r, 0x2A, 0x02); // undo_op
    w16(&mut r, 0x2E, client_data.len() as u16); // redo_len
    w16(&mut r, 0x32, 0x10); // undo_len
    r[0x48..].copy_from_slice(client_data);
    r
}

/// LOG_RECORD with explicit operation codes and payloads: the redo
/// buffer sits at client-data offset 0, the undo buffer follows it
/// 8-aligned. `mft_cluster` is the `mft_cluster_index` anchor (VCN of
/// the $MFT extent holding the target file-record segment).
#[allow(clippy::too_many_arguments)]
pub fn log_record_ex(
    lsn: u64,
    rtype: u32,
    tid: u32,
    redo_op: u16,
    undo_op: u16,
    target_attr: u16,
    mft_cluster: u64,
    redo: &[u8],
    undo: &[u8],
) -> Vec<u8> {
    let undo_off = (redo.len() + 7) & !7;
    let client_len = undo_off + undo.len();
    let mut r = vec![0u8; 0x48 + client_len];
    w64(&mut r, 0x00, lsn); // this_lsn
    w64(&mut r, 0x08, lsn.saturating_sub(0x40)); // client_prev_lsn
    w16(&mut r, 0x18, client_len as u16); // client_data_len
    w32(&mut r, 0x1C, rtype); // record_type
    w32(&mut r, 0x20, tid); // transaction_id
    w16(&mut r, 0x28, redo_op);
    w16(&mut r, 0x2A, undo_op);
    w16(&mut r, 0x2C, 0); // redo_offset
    w16(&mut r, 0x2E, redo.len() as u16); // redo_len
    w16(&mut r, 0x30, undo_off as u16); // undo_offset
    w16(&mut r, 0x32, undo.len() as u16); // undo_len
    w16(&mut r, 0x34, target_attr); // target_attribute
    w64(&mut r, 0x40, mft_cluster); // mft_cluster_index
    r[0x48..0x48 + redo.len()].copy_from_slice(redo);
    r[0x48 + undo_off..0x48 + undo_off + undo.len()].copy_from_slice(undo);
    r
}

/// A USN_RECORD_V2 body (8-aligned, fixed header + UTF-16 filename).
#[allow(clippy::too_many_arguments)]
pub fn usn_record(
    file_ref: u64,
    parent_ref: u64,
    usn: i64,
    ts: u64,
    reason: u32,
    attrs: u32,
    name: &str,
) -> Vec<u8> {
    let nb = utf16(name);
    let len = (0x3C + nb.len() + 7) & !7;
    let mut r = vec![0u8; len];
    w32(&mut r, 0, len as u32);
    w16(&mut r, 4, 2); // major_version
    w64(&mut r, 8, file_ref);
    w64(&mut r, 0x10, parent_ref);
    w64(&mut r, 0x18, usn as u64);
    w64(&mut r, 0x20, ts);
    w32(&mut r, 0x28, reason);
    w32(&mut r, 0x34, attrs);
    w16(&mut r, 0x38, nb.len() as u16);
    w16(&mut r, 0x3A, 0x3C);
    r[0x3C..0x3C + nb.len()].copy_from_slice(&nb);
    r
}

/// $STANDARD_INFORMATION content.
pub fn si_body(created: u64, modified: u64, mft_changed: u64, accessed: u64, attrs: u32) -> Vec<u8> {
    let mut b = vec![0u8; 0x48];
    w64(&mut b, 0, created);
    w64(&mut b, 8, modified);
    w64(&mut b, 16, mft_changed);
    w64(&mut b, 24, accessed);
    w32(&mut b, 32, attrs);
    b
}

/// $FILE_NAME content.
#[allow(clippy::too_many_arguments)]
pub fn fn_body(
    parent_ref: u64,
    name: &str,
    namespace: u8,
    flags: u32,
    real_size: u64,
    times: [u64; 4], // created, modified, mft_changed, accessed
) -> Vec<u8> {
    let nb = utf16(name);
    let mut b = vec![0u8; 0x42 + nb.len()];
    w64(&mut b, 0, parent_ref);
    w64(&mut b, 8, times[0]);
    w64(&mut b, 16, times[1]);
    w64(&mut b, 24, times[2]);
    w64(&mut b, 32, times[3]);
    w64(&mut b, 40, real_size.div_ceil(CSZ as u64) * CSZ as u64);
    w64(&mut b, 48, real_size);
    w32(&mut b, 56, flags);
    b[0x40] = (nb.len() / 2) as u8;
    b[0x41] = namespace;
    b[0x42..0x42 + nb.len()].copy_from_slice(&nb);
    b
}

/// $ATTRIBUTE_LIST content: entries `(type, name, first_vcn, record_ref, id)`.
pub fn alist_body(entries: &[(u32, &str, u64, u64, u16)]) -> Vec<u8> {
    let mut b = Vec::new();
    for &(ty, name, vcn, rref, id) in entries {
        let nb = utf16(name);
        let elen = (0x1A + nb.len() + 7) & !7;
        let mut e = vec![0u8; elen];
        w32(&mut e, 0, ty);
        w16(&mut e, 4, elen as u16);
        e[6] = (nb.len() / 2) as u8;
        e[7] = 0x1A;
        w64(&mut e, 8, vcn);
        w64(&mut e, 16, rref);
        w16(&mut e, 24, id);
        e[0x1A..0x1A + nb.len()].copy_from_slice(&nb);
        b.extend_from_slice(&e);
    }
    b
}

/// $EA content: list of `(name, value)`.
pub fn ea_body(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = Vec::new();
    for (i, (name, val)) in entries.iter().enumerate() {
        let size = (8 + name.len() + 1 + val.len() + 3) & !3;
        let mut e = vec![0u8; size];
        let next = if i + 1 == entries.len() { 0 } else { size as u32 };
        w32(&mut e, 0, next);
        e[5] = name.len() as u8;
        w16(&mut e, 6, val.len() as u16);
        e[8..8 + name.len()].copy_from_slice(name.as_bytes());
        e[8 + name.len() + 1..8 + name.len() + 1 + val.len()].copy_from_slice(val);
        b.extend_from_slice(&e);
    }
    b
}

/// $REPARSE_POINT content for a symlink: substitute + print names.
pub fn reparse_symlink_body(substitute: &str, print: &str) -> Vec<u8> {
    let sub = utf16(substitute);
    let prn = utf16(print);
    let total = 0x14 + sub.len() + prn.len();
    let mut b = vec![0u8; total];
    w32(&mut b, 0, 0xA000_000C); // IO_REPARSE_TAG_SYMLINK
    w16(&mut b, 4, (total - 8) as u16); // data length (excl. header)
    w16(&mut b, 8, 0); // SubstituteNameOffset
    w16(&mut b, 0x0A, sub.len() as u16);
    w16(&mut b, 0x0C, sub.len() as u16); // PrintNameOffset (after substitute)
    w16(&mut b, 0x0E, prn.len() as u16);
    w32(&mut b, 0x10, 1); // SYMLINK_FLAG_RELATIVE
    b[0x14..0x14 + sub.len()].copy_from_slice(&sub);
    b[0x14 + sub.len()..0x14 + sub.len() + prn.len()].copy_from_slice(&prn);
    b
}

// ---- FILE record builder --------------------------------------------------

/// Build a FILE record in place at `rec_off(n)`. `attrs` are pre-encoded
/// attribute blobs; fixup is applied (USA at 0x30, sequence 0x5A5A+n).
/// `sig` is normally `b"FILE"`; pass `b"BAAD"` for the corrupt-marked case.
#[allow(clippy::too_many_arguments)]
pub fn file_record(
    img: &mut [u8],
    rec_no: u32,
    sig: &[u8; 4],
    seq: u16,
    flags: u16,
    links: u16,
    base_ref: u64,
    attrs: &[Vec<u8>],
) {
    let mut rec = vec![0u8; REC_SIZE];
    rec[0..4].copy_from_slice(sig);
    w16(&mut rec, 4, 0x30); // USA offset
    w16(&mut rec, 6, 3); // USA count (1 + 2 sectors)
    w64(&mut rec, 8, 0x1111_2222_3333_4444); // LSN
    w16(&mut rec, 16, seq);
    w16(&mut rec, 18, links);
    w16(&mut rec, 20, 0x38); // first attr offset
    w16(&mut rec, 22, flags);
    w64(&mut rec, 32, base_ref);
    w32(&mut rec, 40, 4); // next attr id
    w32(&mut rec, 44, rec_no); // record number (Vista+)
    let mut off = 0x38usize;
    for a in attrs {
        rec[off..off + a.len()].copy_from_slice(a);
        off += a.len();
    }
    // end-of-attributes marker
    w32(&mut rec, off, 0xFFFF_FFFF);
    off += 8;
    w32(&mut rec, 24, off as u32); // used size
    w32(&mut rec, 28, REC_SIZE as u32); // allocated size
    // Fixup: USA = [seq_no, tail0, tail1]; write the displaced bytes into
    // the USA and stamp the sequence into each sector trailer.
    let usa_seq = 0x5A00u16.wrapping_add(rec_no as u16);
    let tail0 = u16::from_le_bytes([rec[510], rec[511]]);
    let tail1 = u16::from_le_bytes([rec[1022], rec[1023]]);
    w16(&mut rec, 0x30, usa_seq);
    w16(&mut rec, 0x32, tail0);
    w16(&mut rec, 0x34, tail1);
    w16(&mut rec, 510, usa_seq);
    w16(&mut rec, 1022, usa_seq);
    img[rec_off(rec_no)..rec_off(rec_no) + REC_SIZE].copy_from_slice(&rec);
}

// ---- INDX builders --------------------------------------------------------

/// One `$I30` index entry: file ref + $FILE_NAME stream.
pub fn indx_entry(file_ref: u64, name: &str, parent: u64, real_size: u64, times: [u64; 4]) -> Vec<u8> {
    let body = fn_body(parent, name, 1, 0x20, real_size, times);
    let size = (0x10 + body.len() + 7) & !7;
    let mut e = vec![0u8; size];
    w64(&mut e, 0, file_ref);
    w16(&mut e, 8, size as u16);
    w16(&mut e, 0x0A, body.len() as u16);
    w16(&mut e, 0x0C, 0); // flags
    e[0x10..0x10 + body.len()].copy_from_slice(&body);
    e
}

/// Terminator index entry.
pub fn indx_end() -> Vec<u8> {
    let mut e = vec![0u8; 0x10];
    w16(&mut e, 8, 0x10);
    w16(&mut e, 0x0C, 2); // last entry
    e
}

/// $INDEX_ROOT resident content wrapping `entries` (+ optional slack bytes).
pub fn index_root_body(entries: &[Vec<u8>], slack: &[Vec<u8>]) -> Vec<u8> {
    let mut body = vec![0u8; 0x10];
    w32(&mut body, 0, 0x30); // indexes $FILE_NAME
    w32(&mut body, 4, 1); // collation: filename
    w32(&mut body, 8, INDX_SIZE as u32);
    body[0x0C] = 1; // clusters per index record
    // index header at 0x10
    let mut ih = vec![0u8; 0x10];
    let used = 0x10 + entries.iter().map(|e| e.len()).sum::<usize>();
    let alloc = used + slack.iter().map(|e| e.len()).sum::<usize>() + 0x40;
    w32(&mut ih, 0, 0x10); // entries offset (rel to index header)
    w32(&mut ih, 4, used as u32);
    w32(&mut ih, 8, alloc as u32);
    ih[0x0C] = if slack.is_empty() { 0 } else { 1 };
    body.extend_from_slice(&ih);
    for e in entries {
        body.extend_from_slice(e);
    }
    for e in slack {
        body.extend_from_slice(e);
    }
    body.resize(alloc + 0x10, 0); // pad to allocated
    w32(&mut body, 0x10 + 8, alloc as u32);
    body
}

/// Write an INDX record (4096 B) at a cluster: `used` entries in the live
/// region, `slack` entries beyond it.
pub fn indx_record(
    img: &mut [u8],
    cluster: u32,
    vcn: u64,
    used_entries: &[Vec<u8>],
    slack_entries: &[Vec<u8>],
) {
    let mut rec = vec![0u8; INDX_SIZE];
    rec[0..4].copy_from_slice(b"INDX");
    w16(&mut rec, 4, 0x28); // USA offset
    w16(&mut rec, 6, 9); // USA count (1 + 8 sectors)
    w64(&mut rec, 8, 0xDEAD_BEEF);
    w64(&mut rec, 0x10, vcn);
    // index header at 0x18; entries start at 0x18 + 0x28 = 0x40
    let used = 0x28 + used_entries.iter().map(|e| e.len()).sum::<usize>();
    let slack_len: usize = slack_entries.iter().map(|e| e.len()).sum();
    w32(&mut rec, 0x18, 0x28); // entries offset rel to index header
    w32(&mut rec, 0x1C, used as u32); // used
    w32(&mut rec, 0x20, (used + slack_len) as u32); // allocated
    rec[0x24] = 0; // no children flag (leaf node for the test)
    let mut off = 0x40usize;
    for e in used_entries.iter().chain(slack_entries) {
        rec[off..off + e.len()].copy_from_slice(e);
        off += e.len();
    }
    // fixup: USA at 0x28, 8 sector trailers
    let usa_seq = 0x5A5Au16;
    w16(&mut rec, 0x28, usa_seq);
    for i in 0..8 {
        let tail = (i + 1) * BPS - 2;
        let t = u16::from_le_bytes([rec[tail], rec[tail + 1]]);
        w16(&mut rec, 0x2A + i * 2, t);
        w16(&mut rec, tail, usa_seq);
    }
    img[clus_off(cluster)..clus_off(cluster) + INDX_SIZE].copy_from_slice(&rec);
}

// ---- the corpus -----------------------------------------------------------

/// Build the synthetic NTFS image (8 MiB).
pub fn build_ntfs() -> Vec<u8> {
    let mut img = vec![0u8; TOTAL_SECTORS as usize * BPS];

    // ---- boot sector ---------------------------------------------------
    img[0] = 0xEB;
    img[1] = 0x52;
    img[2] = 0x90;
    img[3..11].copy_from_slice(b"NTFS    ");
    w16(&mut img, 11, BPS as u16);
    img[13] = SPC as u8;
    img[21] = 0xF8;
    w64(&mut img, 40, TOTAL_SECTORS as u64);
    w64(&mut img, 48, MFT_LCN as u64);
    w64(&mut img, 56, 8); // $MFTMirr LCN
    img[64] = 0xF6; // clusters per FILE record = -10 → 1024 B
    img[68] = 0xF4; // clusters per INDX record = -12 → 4096 B
    w64(&mut img, 72, 0xA1B2_C3D4_E5F6_0718); // serial
    img[510] = 0x55;
    img[511] = 0xAA;

    let t = ft(1_705_314_620); // 2024-01-15T10:30:20Z
    let t_old = ft(1_000_000_000); // 2001-09-09 (timestomp "created")

    // ---- record 0: $MFT ------------------------------------------------
    let mft_data = attr_nonresident(
        T_DATA,
        "",
        &[(MFT_CLUSTERS as u64, Some(MFT_LCN as u64))],
        0,
        MFT_CLUSTERS as u64 * CSZ as u64,
        MFT_USED_CLUSTERS as u64 * CSZ as u64,
        MFT_USED_CLUSTERS as u64 * CSZ as u64,
        0,
        0,
        0,
    );
    // $MFT's own record bitmap: bits 0..34 used, bit 20 also set though the
    // record is deleted (deallocation not yet committed → anomaly flag).
    let mut mft_bm = vec![0u8; 16];
    for i in 0..35u32 {
        mft_bm[(i / 8) as usize] |= 1 << (i % 8);
    }
    mft_bm[2] |= 1 << 4; // record 20 (deleted) still marked in-use
    let mft_bitmap_attr = attr_resident(T_BITMAP, "", &mft_bm, 1);
    file_record(
        &mut img,
        0,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x06), 0),
            attr_resident(T_FN, "", &fn_body(5, "$MFT", 1, 0x06, 0, [t; 4]), 1),
            mft_data,
            mft_bitmap_attr,
        ],
    );

    // ---- record 1: $MFTMirr ---------------------------------------------
    file_record(
        &mut img,
        1,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x06), 0),
            attr_resident(T_FN, "", &fn_body(5, "$MFTMirr", 1, 0x06, 0, [t; 4]), 1),
            attr_resident(T_DATA, "", b"MIRR", 2),
        ],
    );

    // ---- record 2: $LogFile ---------------------------------------------
    file_record(
        &mut img,
        2,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x06), 0),
            attr_resident(T_FN, "", &fn_body(5, "$LogFile", 1, 0x06, 8192, [t; 4]), 1),
            attr_nonresident(T_DATA, "", &[(4, Some(31))], 0, 16384, 16384, 16384, 0, 0, 2),
        ],
    );
    // $LogFile stream, clusters 31-34 = four LFS pages: two restart areas,
    // one record page (two LOG_RECORDs), one checkpoint.
    put(&mut img, 31, &lfs_page(b"RSTR", &[(0x30, restart_area())]));
    put(&mut img, 32, &lfs_page(b"RSTR", &[(0x30, restart_area())]));
    // rec1: $I30 index add of BIG.BIN into the root — the redo payload
    // is the INDEX_ENTRY; the cluster anchor points at the directory's
    // record cluster (floor = rec 4, bound-flagged).
    let idx = indx_entry(17 | (1u64 << 48), "BIG.BIN", 5, 6000, [t; 4]);
    let rec1 = log_record_ex(0x4A80, 1, 7, 0x0E, 0x0F, 0, 1, &idx, b"");
    // rec2: deallocate the file-record segment whose MFT cluster covers
    // rec 20 — correlates with DELETED1.TXT's file_delete USN.
    let rec2 = log_record_ex(0x4AE0, 1, 7, 0x03, 0x02, 0, 5, b"", b"");
    put(
        &mut img,
        33,
        &lfs_page(
            b"RCRD",
            &[(0x40, rec1.clone()), (0x40 + rec1.len(), rec2)],
        ),
    );
    put(
        &mut img,
        34,
        &lfs_page(b"CHKD", &[(0x30, 0x4A00u64.to_le_bytes().to_vec())]),
    );

    // ---- record 3: $Volume ----------------------------------------------
    file_record(
        &mut img,
        3,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x06), 0),
            attr_resident(T_FN, "", &fn_body(5, "$Volume", 1, 0x06, 0, [t; 4]), 1),
            attr_resident(T_VNAME, "", &utf16("TESTVOL"), 2),
            attr_resident(
                T_VINFO,
                "",
                &[0, 0, 0, 0, 0, 0, 0, 0, 3, 1, 0x08, 0],
                3,
            ),
        ],
    );

    // ---- record 4: $AttrDef ----------------------------------------------
    file_record(
        &mut img,
        4,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x06), 0),
            attr_resident(T_FN, "", &fn_body(5, "$AttrDef", 1, 0x06, 0, [t; 4]), 1),
            attr_resident(T_DATA, "", b"ATTRDEF", 2),
        ],
    );

    // ---- record 5: root directory "." ------------------------------------
    // INDEX_ROOT holds one live entry; the heavy listing lives in the
    // INDEX_ALLOCATION INDX block at cluster 80.
    let root_ir = index_root_body(
        &[indx_entry(16 | (1u64 << 48), "HELLO.TXT", 5, 16, [t; 4]), indx_end()],
        &[],
    );
    file_record(
        &mut img,
        5,
        b"FILE",
        1,
        FLG_INUSE | FLG_DIR,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x1000_0006), 0),
            attr_resident(T_FN, "", &fn_body(5, ".", 1, 0x1000_0006, 0, [t; 4]), 1),
            attr_resident(T_IROOT, "$I30", &root_ir, 2),
            attr_nonresident(
                T_IALLOC,
                "$I30",
                &[(1, Some(80))],
                0,
                INDX_SIZE as u64,
                INDX_SIZE as u64,
                INDX_SIZE as u64,
                0,
                0,
                3,
            ),
        ],
    );

    // ---- record 6: $Bitmap ------------------------------------------------
    file_record(
        &mut img,
        6,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x06), 0),
            attr_resident(T_FN, "", &fn_body(5, "$Bitmap", 1, 0x06, 0, [t; 4]), 1),
            attr_nonresident(T_DATA, "", &[(1, Some(30))], 0, CSZ as u64, 256, 256, 0, 0, 2),
        ],
    );

    // ---- record 7: $Boot ---------------------------------------------------
    file_record(
        &mut img,
        7,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x06), 0),
            attr_resident(T_FN, "", &fn_body(5, "$Boot", 1, 0x06, 0, [t; 4]), 1),
            attr_resident(T_DATA, "", b"BOOT", 2),
        ],
    );

    // ---- record 11: $Extend directory --------------------------------------
    file_record(
        &mut img,
        11,
        b"FILE",
        1,
        FLG_INUSE | FLG_DIR,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x1000_0006), 0),
            attr_resident(T_FN, "", &fn_body(5, "$Extend", 1, 0x1000_0006, 0, [t; 4]), 1),
        ],
    );

    // ---- record 12: $UsnJrnl (with $J and $Max streams) ---------------------
    file_record(
        &mut img,
        12,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x06), 0),
            attr_resident(T_FN, "", &fn_body(11, "$UsnJrnl", 1, 0x06, 0, [t; 4]), 1),
            attr_resident(T_DATA, "$Max", &32u64.to_le_bytes(), 2),
            attr_nonresident(T_DATA, "$J", &[(1, Some(35))], 0, CSZ as u64, 256, 256, AFLAG_SPARSE, 0, 3),
        ],
    );
    // $UsnJrnl:$J at cluster 35 — two USN_RECORD_V2 change records:
    // BIG.BIN written (rec 17), DELETED1.TXT deleted (rec 20).
    let usn1 = usn_record(
        17 | (1u64 << 48),
        5 | (1u64 << 48),
        0x1000,
        ft(1_705_300_000),
        0x8000_0101, // data_overwrite|file_create|close
        0x20,
        "BIG.BIN",
    );
    let usn2 = usn_record(
        20 | (3u64 << 48),
        5 | (1u64 << 48),
        0x1080,
        ft(1_705_300_100),
        0x8000_0200, // file_delete|close
        0x20,
        "DELETED1.TXT",
    );
    let mut jdata = usn1;
    jdata.extend_from_slice(&usn2);
    put(&mut img, 35, &jdata);

    // ---- record 16: HELLO.TXT (resident data) -------------------------------
    file_record(
        &mut img,
        16,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "HELLO.TXT", 1, 0x20, 16, [t; 4]), 1),
            attr_resident(T_DATA, "", b"hello ntfs world", 2),
        ],
    );

    // ---- record 17: BIG.BIN (non-resident, slack) ----------------------------
    file_record(
        &mut img,
        17,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "BIG.BIN", 1, 0x20, 6000, [t; 4]), 1),
            attr_nonresident(T_DATA, "", &[(4, Some(40))], 0, 4 * CSZ as u64, 6000, 6000, 0, 0, 2),
        ],
    );
    put(&mut img, 40, b"BIG-BIN-HEAD-");
    put(&mut img, 41, b"BIG-BIN-DATA-1");
    put(&mut img, 42, b"BIG-BIN-DATA-2");
    put(&mut img, 43, b"BIG-BIN-TAIL-");

    // ---- record 18: SPARSE.BIN ----------------------------------------------
    file_record(
        &mut img,
        18,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "SPARSE.BIN", 1, 0x20, 6 * CSZ as u64, [t; 4]), 1),
            attr_nonresident(
                T_DATA,
                "",
                &[(2, Some(44)), (2, None), (2, Some(46))],
                0,
                6 * CSZ as u64,
                6 * CSZ as u64,
                6 * CSZ as u64,
                AFLAG_SPARSE,
                0,
                2,
            ),
        ],
    );
    put(&mut img, 44, b"SPARSE-HEAD____");
    put(&mut img, 46, b"SPARSE-TAIL____");

    // ---- record 19: ADS.TXT (named stream) ------------------------------------
    file_record(
        &mut img,
        19,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "ADS.TXT", 1, 0x20, 4, [t; 4]), 1),
            attr_resident(T_DATA, "", b"main", 2),
            attr_resident(T_DATA, "secret", b"hidden-stream-data", 3),
        ],
    );

    // ---- record 20: DELETED1.TXT (deleted, intact extents) --------------------
    file_record(
        &mut img,
        20,
        b"FILE",
        3,
        0, // in-use flag clear
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "DELETED1.TXT", 1, 0x20, 5000, [t; 4]), 1),
            attr_nonresident(T_DATA, "", &[(2, Some(50))], 0, 2 * CSZ as u64, 5000, 5000, 0, 0, 2),
        ],
    );
    put(&mut img, 50, b"DELETED-ONE-HEAD");
    put(&mut img, 51, b"DELETED-ONE-TAIL");

    // ---- record 21: PARTIAL.BIN (deleted; first extent reallocated) ------------
    file_record(
        &mut img,
        21,
        b"FILE",
        2,
        0,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "PARTIAL.BIN", 1, 0x20, 14000, [t; 4]), 1),
            attr_nonresident(
                T_DATA,
                "",
                &[(2, Some(52)), (2, Some(54))],
                0,
                4 * CSZ as u64,
                14000,
                14000,
                0,
                0,
                2,
            ),
        ],
    );
    put(&mut img, 54, b"PARTIAL-TAIL-SURVIVES-1");
    put(&mut img, 55, b"PARTIAL-TAIL-SURVIVES-2");

    // ---- record 22: NEWFILE.TXT (live, claims the stolen clusters) --------------
    file_record(
        &mut img,
        22,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "NEWFILE.TXT", 1, 0x20, 100, [t; 4]), 1),
            attr_nonresident(T_DATA, "", &[(2, Some(52))], 0, 2 * CSZ as u64, 100, 100, 0, 0, 2),
        ],
    );
    put(&mut img, 52, b"new file owns these clusters!!");

    // ---- record 23: GONE.TXT (deleted, metadata only) ----------------------------
    file_record(
        &mut img,
        23,
        b"FILE",
        1,
        0,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "GONE.TXT", 1, 0x20, 700, [t; 4]), 1),
        ],
    );

    // ---- record 24: SUBDIR -------------------------------------------------------
    // Index-root slack: ROOTSLACK.TXT is deleted-name residue between the
    // used and allocated lengths of the resident index node.
    let sub_ir = index_root_body(
        &[indx_entry(25, "INNER.TXT", 24, 5, [t; 4]), indx_end()],
        &[indx_entry(91, "ROOTSLACK.TXT", 24, 5, [t; 4])],
    );
    file_record(
        &mut img,
        24,
        b"FILE",
        1,
        FLG_INUSE | FLG_DIR,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x1000_0020), 0),
            attr_resident(T_FN, "", &fn_body(5, "SUBDIR", 1, 0x1000_0020, 0, [t; 4]), 1),
            attr_resident(T_IROOT, "$I30", &sub_ir, 2),
        ],
    );

    // ---- record 25: SUBDIR/INNER.TXT ------------------------------------------------
    file_record(
        &mut img,
        25,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(24, "INNER.TXT", 1, 0x20, 5, [t; 4]), 1),
            attr_resident(T_DATA, "", b"inner", 2),
        ],
    );

    // ---- record 26: EVIL.DOC (masquerade: MZ content) ---------------------------------
    file_record(
        &mut img,
        26,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "EVIL.DOC", 1, 0x20, 60, [t; 4]), 1),
            attr_nonresident(T_DATA, "", &[(1, Some(60))], 0, CSZ as u64, 60, 60, 0, 0, 2),
        ],
    );
    let mut mz = b"MZ\x90\0\x03\0\0\0".to_vec();
    mz.resize(60, 0);
    put(&mut img, 60, &mz);

    // ---- record 27: RESUME.DOCX (container-consistent PK) ------------------------------
    file_record(
        &mut img,
        27,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "RESUME.DOCX", 1, 0x20, 20, [t; 4]), 1),
            attr_nonresident(T_DATA, "", &[(1, Some(61))], 0, CSZ as u64, 20, 20, 0, 0, 2),
        ],
    );
    let mut pk = b"PK\x03\x04\x14\0\0\0".to_vec();
    pk.resize(20, 0);
    put(&mut img, 61, &pk);

    // ---- record 28: hardlink — two WIN32 FNs in different dirs -------------------------
    file_record(
        &mut img,
        28,
        b"FILE",
        1,
        FLG_INUSE,
        2, // link count
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "LINK1.TXT", 1, 0x20, 9, [t; 4]), 1),
            attr_resident(T_FN, "", &fn_body(24, "LINK2.TXT", 1, 0x20, 9, [t; 4]), 2),
            attr_resident(T_DATA, "", b"link-body", 3),
        ],
    );

    // ---- record 29: TIMESTOMP.TXT — SI predates FN (suspect) -----------------------------
    file_record(
        &mut img,
        29,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t_old, t_old, t_old, t_old, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "TIMESTOMP.TXT", 1, 0x20, 3, [t; 4]), 1),
            attr_resident(T_DATA, "", b"ts!", 2),
        ],
    );

    // ---- record 30: COMPRESS.BIN — LZNT1-compressed unit -----------------------------------
    // One compression unit (16 clusters) stored as a single LZNT1 chunk at
    // cluster 64: flag byte 0x00 + 8 literals "COMPRESS" — decompresses to
    // 8 bytes; real_size 8.
    {
        let payload = [0x00u8, b'C', b'O', b'M', b'P', b'R', b'E', b'S', b'S'];
        let hdr = 0x8000u16 | 0x3000 | ((payload.len() as u16) - 1);
        let mut unit = Vec::new();
        unit.extend_from_slice(&hdr.to_le_bytes());
        unit.extend_from_slice(&payload);
        unit.resize(CSZ, 0);
        put(&mut img, 64, &unit);
    }
    file_record(
        &mut img,
        30,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "COMPRESS.BIN", 1, 0x20, 8, [t; 4]), 1),
            attr_nonresident(
                T_DATA,
                "",
                &[(1, Some(64))], // stored < 16-cluster unit → compressed
                0,
                CSZ as u64,
                8,
                8,
                AFLAG_COMPRESSED,
                4, // 2^4 = 16-cluster compression unit
                2,
            ),
        ],
    );

    // ---- records 31+32: ATTRLIST.BIN — split across two records -------------------------
    file_record(
        &mut img,
        31,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "ATTRLIST.BIN", 1, 0x20, 14000, [t; 4]), 1),
            attr_resident(
                T_ALIST,
                "",
                &alist_body(&[
                    (T_SI, "", 0, 31, 0),
                    (T_FN, "", 0, 31, 1),
                    (T_DATA, "", 0, 31, 3),
                    (T_DATA, "", 2, 32, 1), // second extent lives in rec 32
                ]),
                2,
            ),
            attr_nonresident(T_DATA, "", &[(2, Some(70))], 0, 2 * CSZ as u64, 14000, 2 * CSZ as u64, 0, 0, 3),
        ],
    );
    file_record(
        &mut img,
        32,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        31, // base record ref
        &[attr_nonresident(T_DATA, "", &[(2, Some(72))], 2, 2 * CSZ as u64, 14000, 2 * CSZ as u64, 0, 0, 1)],
    );
    put(&mut img, 70, b"ATTRLIST-PART-ONE-");
    put(&mut img, 72, b"ATTRLIST-PART-TWO-");

    // ---- record 33: EA.TXT — extended attributes -----------------------------------------
    file_record(
        &mut img,
        33,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "EA.TXT", 1, 0x20, 3, [t; 4]), 1),
            attr_resident(T_EAINFO, "", &[0x20, 0, 0, 0, 1, 0, 0, 0], 2),
            attr_resident(T_EA, "", &ea_body(&[("MYEA", b"value")]), 3),
            attr_resident(T_DATA, "", b"ea!", 4),
        ],
    );

    // ---- record 34: ORPHAN.TXT — parent record 60 does not exist --------------------------
    file_record(
        &mut img,
        34,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(60, "ORPHAN.TXT", 1, 0x20, 6, [t; 4]), 1),
            attr_resident(T_DATA, "", b"orphan", 2),
        ],
    );

    // ---- record 35: DOSFLAGS.TXT — DOS 8.3 alias + DOS attribute bits ------------------------
    file_record(
        &mut img,
        35,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x07), 0), // RO+hidden+system
            attr_resident(T_FN, "", &fn_body(5, "DOSFLAGS.TXT", 1, 0x20, 5, [t; 4]), 1),
            attr_resident(T_FN, "", &fn_body(5, "DOSFLA~1.TXT", 2, 0x20, 5, [t; 4]), 2),
            attr_resident(T_DATA, "", b"flags", 3),
        ],
    );

    // ---- record 36: SYMLINK.LNK — $REPARSE_POINT symlink ---------------------------------------
    file_record(
        &mut img,
        36,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "SYMLINK.LNK", 1, 0x20, 0, [t; 4]), 1),
            attr_resident(
                T_REPARSE,
                "",
                &reparse_symlink_body("\\??\\C:\\target\\real.txt", "target\\real.txt"),
                2,
            ),
        ],
    );

    // ---- record 37: OBJID.BIN — $OBJECT_ID, and no $SI (FN-only timestamps) ---------------------
    file_record(
        &mut img,
        37,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_FN, "", &fn_body(5, "OBJID.BIN", 1, 0x20, 4, [t; 4]), 1),
            attr_resident(
                T_OBJID,
                "",
                &[
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                    0x0D, 0x0E, 0x0F, 0x10,
                ],
                2,
            ),
            attr_resident(T_DATA, "", b"oid!", 3),
        ],
    );

    // ---- record 38: RAWCMP.BIN — compressed stream, unit 0 stored raw, unit 1 sparse -------------
    // A 16-cluster unit that did not compress is stored verbatim; a fully
    // sparse unit decodes to zeros.
    file_record(
        &mut img,
        38,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "RAWCMP.BIN", 1, 0x20, 32 * CSZ as u64, [t; 4]), 1),
            attr_nonresident(
                T_DATA,
                "",
                &[(16, Some(96)), (16, None)],
                0,
                32 * CSZ as u64,
                32 * CSZ as u64,
                32 * CSZ as u64,
                AFLAG_COMPRESSED | AFLAG_SPARSE,
                4,
                2,
            ),
        ],
    );
    put(&mut img, 96, b"RAWCMP-UNIT0-STORED-RAW");

    // ---- record 39: GAPDATA.BIN — sparse stream with a leading VCN gap ---------------------------
    // first_vcn=4: logical offsets 0..16KiB are an unmapped gap (reads as
    // zeros) before the real extent at vcn 4.
    file_record(
        &mut img,
        39,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "GAPDATA.BIN", 1, 0x20, 8 * CSZ as u64, [t; 4]), 1),
            attr_nonresident(
                T_DATA,
                "",
                &[(4, Some(120))],
                4, // first VCN — bytes before this are a hole
                8 * CSZ as u64,
                8 * CSZ as u64,
                8 * CSZ as u64,
                AFLAG_SPARSE,
                0,
                2,
            ),
        ],
    );
    put(&mut img, 120, b"GAPDATA-REAL-EXTENT-");

    // ---- record 40: BITDEL.TXT — deleted; extent still marked in $BITMAP --------------------------
    // Cluster 62 stays marked allocated in the volume bitmap although no
    // live record claims it — the "still marked allocated" anomaly note.
    file_record(
        &mut img,
        40,
        b"FILE",
        2,
        0, // deleted
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "BITDEL.TXT", 1, 0x20, 8000, [t; 4]), 1),
            attr_nonresident(T_DATA, "", &[(1, Some(62))], 0, CSZ as u64, 8000, CSZ as u64, 0, 0, 2),
        ],
    );
    put(&mut img, 62, b"BITDEL-SURVIVING-CLUSTER");

    // ---- record 41: DELDIR — deleted directory with $INDEX_ALLOCATION ----------------------------
    file_record(
        &mut img,
        41,
        b"FILE",
        1,
        FLG_DIR, // deleted directory
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x1000_0006), 0),
            attr_resident(T_FN, "", &fn_body(5, "DELDIR", 1, 0x1000_0006, 0, [t; 4]), 1),
            attr_nonresident(
                T_IALLOC,
                "$I30",
                &[(1, Some(63))],
                0,
                INDX_SIZE as u64,
                INDX_SIZE as u64,
                INDX_SIZE as u64,
                0,
                0,
                2,
            ),
        ],
    );

    // ---- record 42: orphaned extension record (base record 45 absent) ----------------------------
    file_record(
        &mut img,
        42,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        45, // base record ref — record 45 is an empty slot
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(45, "EXTORPHAN.DAT", 1, 0x20, 0, [t; 4]), 1),
        ],
    );

    // ---- record 43: BADATTR.BIN — live record with a corrupt attribute header --------------------
    {
        let mut bad = attr_resident(T_DATA, "", b"x", 4);
        w32(&mut bad, 4, 0x00FF_FFFF); // attribute length runs off the record
        file_record(
            &mut img,
            43,
            b"FILE",
            1,
            FLG_INUSE,
            1,
            0,
            &[
                attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
                attr_resident(T_FN, "", &fn_body(5, "BADATTR.BIN", 1, 0x20, 1, [t; 4]), 1),
                bad,
            ],
        );
    }

    // ---- record 44: DELADS.TXT — deleted file with a named stream ---------------------------------
    file_record(
        &mut img,
        44,
        b"FILE",
        1,
        0, // deleted
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "DELADS.TXT", 1, 0x20, 8, [t; 4]), 1),
            attr_resident(T_DATA, "hidden", b"dead-ads", 2),
        ],
    );

    // ---- records 49–51: BADLIST.BIN — a corrupt $ATTRIBUTE_LIST ---------------------------------
    // The list references record 50 (a *base* record — not an extension of
    // 49) and record 51 (an extension whose reference sequence is stale).
    // Neither may be merged into record 49's attribute set.
    file_record(
        &mut img,
        49,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "BADLIST.BIN", 1, 0x20, 12, [t; 4]), 1),
            attr_resident(
                T_ALIST,
                "",
                &alist_body(&[
                    (T_DATA, "", 0, 49, 3),                 // base record's own $DATA
                    (T_DATA, "", 2, 50, 1),                 // record 50: a base record, not ours
                    (T_DATA, "", 4, 51 | (9u64 << 48), 2),  // stale sequence reference
                ]),
                2,
            ),
            attr_resident(T_DATA, "", b"badlist-data", 3),
        ],
    );
    file_record(
        &mut img,
        50,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0, // base record — must NOT merge into record 49
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "DECOY.DAT", 1, 0x20, 11, [t; 4]), 1),
            attr_nonresident(T_DATA, "", &[(1, Some(84))], 0, CSZ as u64, 11, 11, 0, 0, 2),
        ],
    );
    put(&mut img, 84, b"decoy-bytes");
    file_record(
        &mut img,
        51,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        49, // base record ref — but the attr-list reference claims seq 9
        &[attr_nonresident(T_DATA, "", &[(1, Some(85))], 4, CSZ as u64, 12, 12, 0, 0, 1)],
    );
    put(&mut img, 85, b"stale-bytes!");

    // ---- record 48: DELSPRSE.BIN — deleted sparse file ------------------------------------------
    // Real clusters 86-87 and 88-89 survive (free in $BITMAP); the 3-cluster
    // hole between them is recoverable as zeros → fully Intact.
    file_record(
        &mut img,
        48,
        b"FILE",
        1,
        0, // deleted
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "DELSPRSE.BIN", 1, 0x20, 7 * CSZ as u64, [t; 4]), 1),
            attr_nonresident(
                T_DATA,
                "",
                &[(2, Some(86)), (3, None), (2, Some(88))],
                0,
                7 * CSZ as u64,
                7 * CSZ as u64,
                7 * CSZ as u64,
                AFLAG_SPARSE,
                0,
                2,
            ),
        ],
    );
    put(&mut img, 86, b"DELSP-HEAD_____");
    put(&mut img, 88, b"DELSP-TAIL_____");

    // ---- record 70: FILE fragment in MFT slack ----------------------------------------------
    // (MFT allocated = 20 clusters → records 0..79; used = 16 clusters → 0..63)
    file_record(
        &mut img,
        70,
        b"FILE",
        5,
        0,
        1,
        0,
        &[
            attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0),
            attr_resident(T_FN, "", &fn_body(5, "GHOSTF.DAT", 1, 0x20, 11, [t; 4]), 1),
            attr_resident(T_DATA, "", b"ghost-bytes", 2),
        ],
    );

    // ---- record 71: BAAD record (chkdsk-flagged) ---------------------------------------------
    file_record(
        &mut img,
        71,
        b"BAAD",
        2,
        FLG_INUSE,
        1,
        0,
        &[attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0)],
    );

    // ---- record 72: FILE sig but deliberately broken fixup -------------------------------------
    file_record(
        &mut img,
        72,
        b"FILE",
        1,
        FLG_INUSE,
        1,
        0,
        &[attr_resident(T_SI, "", &si_body(t, t, t, t, 0x20), 0)],
    );
    img[rec_off(72) + 510] ^= 0xFF; // tear the sector-0 trailer

    // ---- root dir INDX block at cluster 80 ------------------------------------------------------
    // live entries: BIG.BIN (17), SUBDIR (24); dangling: DELETED1.TXT →
    // record 20 (free); slack: SLACKED.TXT → record 90 (never existed).
    indx_record(
        &mut img,
        80,
        0,
        &[
            indx_entry(17 | (1u64 << 48), "BIG.BIN", 5, 6000, [t; 4]),
            indx_entry(20 | (3u64 << 48), "DELETED1.TXT", 5, 5000, [t; 4]), // rec 20 free, seq 3
            indx_entry(24 | (1u64 << 48), "SUBDIR", 5, 0, [t; 4]),
            indx_end(),
        ],
        &[indx_entry(90, "SLACKED.TXT", 5, 777, [t; 4])],
    );

    // ---- volume cluster bitmap at cluster 30 -----------------------------------------------------
    // mark allocated: 0-3 (boot/rsvd), 4-23 (MFT), 30-35, 40-47, 52-53,
    // 60-61, 64, 70-73, 80, plus the live extents of the extra records.
    // 62 is marked although only the *deleted* BITDEL.TXT points at it —
    // the "deallocation never committed" anomaly the parser reports.
    for c in 0..TOTAL_CLUSTERS {
        let used = matches!(
            c,
            0..=3 | 4..=23 | 30..=35 | 40..=47 | 52..=53 | 60..=64 | 70..=73 | 80
                | 84..=85 | 96..=111 | 120..=123
        );
        bitmap_set(&mut img, c, used);
    }
    // deleted files' clusters (50-51, 54-55) stay free — they "survive".

    img
}
