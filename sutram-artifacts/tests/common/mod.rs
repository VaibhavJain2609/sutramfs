//! Synthetic artifact-file builders for integration tests.
//!
//! Each builder constructs the documented on-disk layout byte-by-byte —
//! no fixture files, no network. Corruption cases are produced by writing
//! deliberately bad bytes on top of a valid skeleton.

#![allow(dead_code)] // not every test file uses every builder

// ---------- shared writers ----------

pub fn w16(b: &mut Vec<u8>, v: u16) {
    b.extend_from_slice(&v.to_le_bytes());
}
pub fn w32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
pub fn w64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_le_bytes());
}
/// Patch a u32 in place.
pub fn p32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
/// Patch a u64 in place.
pub fn p64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
/// Append a UTF-16LE string (no NUL).
pub fn wstr16(b: &mut Vec<u8>, s: &str) {
    for u in s.encode_utf16() {
        w16(b, u);
    }
}

// ---------- LNK ----------

/// `{00021401-0000-0000-C000-000000000046}` on-disk.
pub const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
pub const LNK_HEADER_SIZE: usize = 0x4C;

/// Minimal valid header with the given LinkFlags (zeroed timestamps).
pub fn lnk_header(flags: u32) -> Vec<u8> {
    let mut b = Vec::new();
    w32(&mut b, LNK_HEADER_SIZE as u32);
    b.extend_from_slice(&LINK_CLSID);
    w32(&mut b, flags);
    w32(&mut b, 0x20); // attributes
    w64(&mut b, 132_000_000_000_000_000);
    w64(&mut b, 132_000_001_000_000_000);
    w64(&mut b, 132_000_002_000_000_000);
    w32(&mut b, 4096); // size
    w32(&mut b, 0); // icon idx
    w32(&mut b, 1); // show
    w16(&mut b, 0); // hotkey
    b.extend_from_slice(&[0; 10]);
    debug_assert_eq!(b.len(), LNK_HEADER_SIZE);
    b
}

/// A counted StringData string.
pub fn counted_str(s: &str, unicode: bool) -> Vec<u8> {
    let mut b = Vec::new();
    if unicode {
        w16(&mut b, s.chars().count() as u16);
        wstr16(&mut b, s);
    } else {
        w16(&mut b, s.len() as u16);
        b.extend_from_slice(s.as_bytes());
    }
    b
}

/// An ExtraData block: `size:u32`, `signature:u32`, `body`.
pub fn extra_block(sig: u32, body: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    w32(&mut b, 8 + body.len() as u32);
    w32(&mut b, sig);
    b.extend_from_slice(body);
    b
}

/// A valid 0x60-byte TrackerDataBlock body (after size+signature).
pub fn tracker_body(machine: &str, v1_guid: &[u8; 16]) -> Vec<u8> {
    let mut b = Vec::new();
    w32(&mut b, 0x58); // length
    w32(&mut b, 0); // version
    let mut m = [0u8; 16];
    let mb = machine.as_bytes();
    m[..mb.len().min(16)].copy_from_slice(&mb[..mb.len().min(16)]);
    b.extend_from_slice(&m);
    b.extend_from_slice(&[0x11; 16]); // droid volume
    b.extend_from_slice(v1_guid); // droid file
    b.extend_from_slice(&[0x22; 16]); // birth volume
    b.extend_from_slice(v1_guid); // birth file
    debug_assert_eq!(b.len(), 0x58);
    b
}

/// A version-1 droid GUID embedding `mac`.
pub fn droid_guid_v1(mac: [u8; 6]) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[0..4].copy_from_slice(&0x12345678u32.to_le_bytes());
    g[4..6].copy_from_slice(&0x9abcu16.to_le_bytes());
    g[6..8].copy_from_slice(&0x1defu16.to_le_bytes()); // version 1
    g[8] = 0x80;
    g[10..16].copy_from_slice(&mac);
    g
}

/// A complete minimal LNK: header + terminal block.
pub fn lnk_min() -> Vec<u8> {
    let mut b = lnk_header(0);
    w32(&mut b, 0);
    b
}

// ---------- registry hive ----------

pub const BASE_BLOCK: usize = 0x1000;
pub const HBIN_HEADER: usize = 0x20;
pub const NIL: u32 = 0xFFFF_FFFF;

/// Synthetic hive builder: one `hbin` sized to fit, cells 8-aligned.
pub struct HiveBuilder {
    cells: Vec<(u32, Vec<u8>)>,
    next_rel: u32,
}

impl HiveBuilder {
    pub fn new() -> Self {
        HiveBuilder {
            cells: Vec::new(),
            next_rel: HBIN_HEADER as u32,
        }
    }
    /// Add a raw cell body; returns the cell-relative offset.
    pub fn cell(&mut self, body: &[u8], allocated: bool) -> u32 {
        let rel = self.next_rel;
        let size = (body.len() + 4 + 7) & !7;
        let mut c = Vec::with_capacity(size);
        let sz: i32 = if allocated {
            -(size as i32)
        } else {
            size as i32
        };
        c.extend_from_slice(&sz.to_le_bytes());
        c.extend_from_slice(body);
        c.resize(size, 0);
        self.cells.push((rel, c));
        self.next_rel += size as u32;
        rel
    }
    /// An `nk` key cell (ASCII name).
    pub fn nk(
        &mut self,
        name: &str,
        sub_list: u32,
        sub_count: u32,
        val_list: u32,
        val_count: u32,
        ts: u64,
    ) -> u32 {
        let mut b = vec![0u8; 0x4C];
        b[0] = b'n';
        b[1] = b'k';
        b[2..4].copy_from_slice(&0x20u16.to_le_bytes());
        b[4..12].copy_from_slice(&ts.to_le_bytes());
        b[0x10..0x14].copy_from_slice(&NIL.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&sub_count.to_le_bytes());
        b[0x1C..0x20].copy_from_slice(&sub_list.to_le_bytes());
        b[0x20..0x24].copy_from_slice(&NIL.to_le_bytes());
        b[0x24..0x28].copy_from_slice(&val_count.to_le_bytes());
        b[0x28..0x2C].copy_from_slice(&val_list.to_le_bytes());
        b[0x2C..0x30].copy_from_slice(&NIL.to_le_bytes());
        b[0x30..0x34].copy_from_slice(&NIL.to_le_bytes());
        b[0x48..0x4A].copy_from_slice(&(name.len() as u16).to_le_bytes());
        b.extend_from_slice(name.as_bytes());
        self.cell(&b, true)
    }
    /// A `vk` value cell (ASCII name flag set).
    pub fn vk(&mut self, name: &str, ty: u32, data_rel: u32, size: u32) -> u32 {
        let mut b = vec![0u8; 0x14];
        b[0] = b'v';
        b[1] = b'k';
        b[2..4].copy_from_slice(&(name.len() as u16).to_le_bytes());
        b[4..8].copy_from_slice(&size.to_le_bytes());
        b[8..12].copy_from_slice(&data_rel.to_le_bytes());
        b[12..16].copy_from_slice(&ty.to_le_bytes());
        b[16..18].copy_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(name.as_bytes());
        self.cell(&b, true)
    }
    /// A subkey list cell (`lf`/`lh`: 8-byte entries; `li`/`ri`: 4-byte).
    pub fn subkey_list(&mut self, sig: &[u8; 2], kids: &[u32]) -> u32 {
        let mut b = vec![0u8; 4];
        b[0] = sig[0];
        b[1] = sig[1];
        b[2..4].copy_from_slice(&(kids.len() as u16).to_le_bytes());
        for &k in kids {
            b.extend_from_slice(&k.to_le_bytes());
            if sig == b"lf" || sig == b"lh" {
                b.extend_from_slice(&0u32.to_le_bytes()); // hash
            }
        }
        self.cell(&b, true)
    }
    /// A `db` big-data indirection cell: `count` segments listed in
    /// `list_rel`.
    pub fn db(&mut self, seg_list_rel: u32, seg_count: u16) -> u32 {
        let mut b = vec![0u8; 8];
        b[0] = b'd';
        b[1] = b'b';
        b[2..4].copy_from_slice(&seg_count.to_le_bytes());
        b[4..8].copy_from_slice(&seg_list_rel.to_le_bytes());
        self.cell(&b, true)
    }
    /// A value-offsets list cell (raw u32 array, no signature).
    pub fn val_list(&mut self, vs: &[u32]) -> u32 {
        let mut b = Vec::new();
        for &v in vs {
            b.extend_from_slice(&v.to_le_bytes());
        }
        self.cell(&b, true)
    }
    pub fn data(&mut self, bytes: &[u8]) -> u32 {
        self.cell(bytes, true)
    }
    /// A *free* cell holding residue bytes (deleted-record carving).
    pub fn free_cell(&mut self, body: &[u8]) -> u32 {
        self.cell(body, false)
    }
    /// A free `nk` residue cell for `deleted_keys()`.
    pub fn free_nk(&mut self, name: &str, ts: u64) -> u32 {
        let mut b = vec![0u8; 0x4C];
        b[0] = b'n';
        b[1] = b'k';
        b[2..4].copy_from_slice(&0x20u16.to_le_bytes());
        b[4..12].copy_from_slice(&ts.to_le_bytes());
        b[0x48..0x4A].copy_from_slice(&(name.len() as u16).to_le_bytes());
        b.extend_from_slice(name.as_bytes());
        self.cell(&b, false)
    }
    /// A free `vk` residue cell for `deleted_keys()`.
    pub fn free_vk(&mut self, name: &str, ty: u32, inline_data: u32) -> u32 {
        let mut b = vec![0u8; 0x14];
        b[0] = b'v';
        b[1] = b'k';
        b[2..4].copy_from_slice(&(name.len() as u16).to_le_bytes());
        b[4..8].copy_from_slice(&(0x8000_0000u32 | 4).to_le_bytes());
        b[8..12].copy_from_slice(&inline_data.to_le_bytes());
        b[12..16].copy_from_slice(&ty.to_le_bytes());
        b[16..18].copy_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(name.as_bytes());
        self.cell(&b, false)
    }
    /// Render: base block + one hbin sized to hold every cell.
    pub fn build(self, root: u32) -> Vec<u8> {
        let hbin_size = (self.next_rel as usize + 0xFFF) & !0xFFF;
        let mut img = vec![0u8; BASE_BLOCK + hbin_size];
        img[0..4].copy_from_slice(b"regf");
        img[4..8].copy_from_slice(&1u32.to_le_bytes());
        img[8..12].copy_from_slice(&1u32.to_le_bytes());
        img[0x0C..0x14].copy_from_slice(&133_000_000_000_000_000u64.to_le_bytes());
        img[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        img[0x18..0x1C].copy_from_slice(&3u32.to_le_bytes());
        img[0x24..0x28].copy_from_slice(&root.to_le_bytes());
        img[0x28..0x2C].copy_from_slice(&(hbin_size as u32).to_le_bytes());
        let nm: Vec<u16> = "SYSTEM".encode_utf16().collect();
        for (i, u) in nm.iter().enumerate() {
            img[0x30 + 2 * i..0x32 + 2 * i].copy_from_slice(&u.to_le_bytes());
        }
        img[BASE_BLOCK..BASE_BLOCK + 4].copy_from_slice(b"hbin");
        img[BASE_BLOCK + 8..BASE_BLOCK + 12]
            .copy_from_slice(&(hbin_size as u32).to_le_bytes());
        for (rel, c) in self.cells {
            let off = BASE_BLOCK + rel as usize;
            img[off..off + c.len()].copy_from_slice(&c);
        }
        img
    }
}

/// The canonical sample hive: ROOT → Child(3 values) + free `nk` residue.
pub fn hive() -> Vec<u8> {
    let mut h = HiveBuilder::new();
    let d1 = h.data(&42u32.to_le_bytes());
    let v1 = h.vk("Count", 4, d1, 4);
    let mut utf = Vec::new();
    wstr16(&mut utf, "hello");
    utf.extend_from_slice(&[0, 0]);
    let d2 = h.data(&utf);
    let v2 = h.vk("", 1, d2, utf.len() as u32);
    let vl = h.val_list(&[v1, v2]);
    let child = h.nk("Child", NIL, 0, vl, 2, 0x1122);
    let lf = h.subkey_list(b"lf", &[child]);
    let root = h.nk("ROOT", lf, 1, NIL, 0, 0x3344);
    h.free_nk("Deleted", 0xAA55);
    h.build(root)
}

// ---------- $I recycle-bin ----------

/// Version-1 (Vista/7) record: fixed 544 bytes, ANSI path at +24.
pub fn irec_v1(path: &str) -> Vec<u8> {
    let mut b = Vec::new();
    w64(&mut b, 1);
    w64(&mut b, 4096);
    w64(&mut b, 133_000_000_000_000_000);
    let mut p = path.as_bytes().to_vec();
    p.push(0);
    p.resize(520, 0);
    b.extend_from_slice(&p);
    b
}

/// Version-2 (Win10+) record: `name_len` u32 incl. NUL, UTF-16LE path.
pub fn irec_v2(path: &str) -> Vec<u8> {
    let mut b = Vec::new();
    w64(&mut b, 2);
    w64(&mut b, 0xBADC0DE);
    w64(&mut b, 133_000_000_000_000_000);
    w32(&mut b, (path.chars().count() + 1) as u32);
    wstr16(&mut b, path);
    w16(&mut b, 0);
    b
}

// ---------- bplist00 ----------

/// Build a bplist from object blobs; object 0 is root. 1-byte offsets
/// and refs (test data is small).
pub fn bplist(objects: &[&[u8]]) -> Vec<u8> {
    let mut b = b"bplist00".to_vec();
    let mut offsets = Vec::new();
    for o in objects {
        offsets.push(b.len() as u64);
        b.extend_from_slice(o);
    }
    let ot_off = b.len() as u64;
    for o in &offsets {
        b.push(*o as u8);
    }
    b.extend_from_slice(&[0; 6]);
    b.push(1); // offset int size
    b.push(1); // ref size
    b.extend_from_slice(&(objects.len() as u64).to_be_bytes());
    b.extend_from_slice(&0u64.to_be_bytes()); // top object
    b.extend_from_slice(&ot_off.to_be_bytes());
    b
}

/// Build a bplist with explicit trailer fields (edge-case testing).
pub fn bplist_custom(
    objects: &[&[u8]],
    offsets: &[u64],
    offset_int_size: u8,
    object_ref_size: u8,
    top_object: u64,
    offset_table_offset: u64,
) -> Vec<u8> {
    let mut b = b"bplist00".to_vec();
    for o in objects {
        b.extend_from_slice(o);
    }
    for &o in offsets {
        for i in (0..offset_int_size).rev() {
            b.push((o >> (8 * i)) as u8);
        }
    }
    b.extend_from_slice(&[0; 6]);
    b.push(offset_int_size);
    b.push(object_ref_size);
    b.extend_from_slice(&(offsets.len() as u64).to_be_bytes());
    b.extend_from_slice(&top_object.to_be_bytes());
    b.extend_from_slice(&offset_table_offset.to_be_bytes());
    b
}

// ---------- prefetch ----------

pub const PF_HEADER_LEN: usize = 0x54;
pub const PF_NAME_OFF: usize = 0x10;

/// Minimal `SCCA` prefetch file of `version`, `size` bytes, name EVIL.EXE.
pub fn prefetch(version: u32, size: usize) -> Vec<u8> {
    let mut b = vec![0u8; size];
    p32(&mut b, 0, version);
    b[4..8].copy_from_slice(b"SCCA");
    p32(&mut b, 0x0C, size as u32);
    for (i, u) in "EVIL.EXE".encode_utf16().enumerate() {
        b[PF_NAME_OFF + 2 * i] = u as u8;
        b[PF_NAME_OFF + 2 * i + 1] = (u >> 8) as u8;
    }
    p32(&mut b, 0x4C, 0xCAFEBABE);
    b
}
