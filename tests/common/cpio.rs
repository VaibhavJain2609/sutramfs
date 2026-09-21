//! Byte-exact CPIO image builder — newc, odc and binary dialects.

pub const MODE_FILE: u64 = 0o100644;
pub const MODE_DIR: u64 = 0o040755;
pub const MODE_SYMLINK: u64 = 0o120777;
pub const MTIME: u64 = 1_700_000_000;

pub struct CpioBuilder {
    pub buf: Vec<u8>,
    ino: u64,
    /// Header offsets in member order.
    pub member_offsets: Vec<u64>,
}

impl CpioBuilder {
    pub fn new() -> Self {
        CpioBuilder {
            buf: Vec::new(),
            ino: 100,
            member_offsets: Vec::new(),
        }
    }

    fn next_ino(&mut self) -> u64 {
        self.ino += 1;
        self.ino
    }

    fn pad(&mut self, align: usize) {
        let rem = self.buf.len() % align;
        if rem != 0 {
            self.buf.resize(self.buf.len() + (align - rem), 0);
        }
    }

    // -- newc (070701) --------------------------------------------------

    /// newc member. `namesize` counts the trailing NUL.
    #[allow(clippy::too_many_arguments)]
    pub fn add_newc(
        &mut self,
        name: &str,
        data: &[u8],
        mode: u64,
        mtime: u64,
        nlink: u64,
        ino: Option<u64>,
        check: u64,
    ) -> u64 {
        let off = self.buf.len() as u64;
        let ino = ino.unwrap_or_else(|| self.next_ino());
        let namesize = name.len() as u64 + 1;
        let h = format!(
            "070701{ino:08x}{mode:08x}{uid:08x}{gid:08x}{nlink:08x}{mtime:08x}{fs:08x}{dmaj:08x}{dmin:08x}{rmaj:08x}{rmin:08x}{namesize:08x}{check:08x}",
            ino = ino,
            mode = mode,
            uid = 1000,
            gid = 1000,
            nlink = nlink,
            mtime = mtime,
            fs = data.len() as u64,
            dmaj = 3,
            dmin = 1,
            rmaj = 0,
            rmin = 0,
            namesize = namesize,
            check = check,
        );
        assert_eq!(h.len(), 110);
        self.buf.extend_from_slice(h.as_bytes());
        self.buf.extend_from_slice(name.as_bytes());
        self.buf.push(0);
        self.pad(4);
        self.buf.extend_from_slice(data);
        self.pad(4);
        self.member_offsets.push(off);
        off
    }

    /// The TRAILER!!! record that ends a newc archive.
    pub fn trailer_newc(&mut self) {
        self.add_newc("TRAILER!!!", b"", 0, 0, 1, Some(0), 0);
        self.member_offsets.pop(); // not a member
    }

    // -- odc (070707) ---------------------------------------------------

    pub fn add_odc(&mut self, name: &str, data: &[u8], mode: u64, mtime: u64) -> u64 {
        let off = self.buf.len() as u64;
        let namesize = name.len() as u64 + 1;
        let h = format!(
            "070707{dev:06o}{ino:06o}{mode:06o}{uid:06o}{gid:06o}{nlink:06o}{rdev:06o}{mtime:011o}{namesize:06o}{fs:011o}",
            dev = 0,
            ino = self.next_ino() & 0o777777,
            mode = mode & 0o777777,
            uid = 0,
            gid = 0,
            nlink = 1,
            rdev = 0,
            mtime = mtime,
            namesize = namesize,
            fs = data.len() as u64,
        );
        assert_eq!(h.len(), 76);
        self.buf.extend_from_slice(h.as_bytes());
        self.buf.extend_from_slice(name.as_bytes());
        self.buf.push(0);
        self.buf.extend_from_slice(data);
        self.member_offsets.push(off);
        off
    }

    pub fn trailer_odc(&mut self) {
        self.add_odc("TRAILER!!!", b"", 0, 0);
        self.member_offsets.pop();
    }

    // -- binary (0x71C7) ------------------------------------------------

    /// Binary member; `le` selects field byte order.
    pub fn add_bin(&mut self, name: &str, data: &[u8], mode: u64, mtime: u64, le: bool) -> u64 {
        let off = self.buf.len() as u64;
        let ino = self.next_ino();
        let w16 = |v: u16| -> [u8; 2] {
            if le { v.to_le_bytes() } else { v.to_be_bytes() }
        };
        // 32-bit fields: most-significant 16-bit word first, each word in
        // the archive byte order (PDP-endian).
        let w32 = |v: u32| -> [u8; 4] {
            let (hi, lo) = (v >> 16, v as u16);
            let (a, b) = (w16(hi as u16), w16(lo));
            [a[0], a[1], b[0], b[1]]
        };
        let mut fields: Vec<u8> = Vec::with_capacity(26);
        for f in [
            w16(0o070707),
            w16(0),                     // dev
            w16((ino & 0xFFFF) as u16), // ino
            w16((mode & 0xFFFF) as u16),
            w16(1000),
            w16(1000),
            w16(1),                     // nlink
            w16(0),                     // rdev
        ] {
            fields.extend_from_slice(&f);
        }
        fields.extend_from_slice(&w32(mtime as u32));
        fields.extend_from_slice(&w16(name.len() as u16 + 1)); // namesize
        fields.extend_from_slice(&w32(data.len() as u32)); // filesize
        assert_eq!(fields.len(), 26);
        self.buf.extend_from_slice(&fields);
        self.buf.extend_from_slice(name.as_bytes());
        self.buf.push(0);
        self.pad(2);
        self.buf.extend_from_slice(data);
        self.pad(2);
        self.member_offsets.push(off);
        off
    }

    pub fn trailer_bin(&mut self, le: bool) {
        self.add_bin("TRAILER!!!", b"", 0, 0, le);
        self.member_offsets.pop();
    }

    // -- finishes --------------------------------------------------------

    pub fn finish_bare(self) -> Vec<u8> {
        self.buf
    }

    /// Bare bytes + trailing slack after the trailer.
    pub fn with_slack(mut self, slack: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(slack);
        self.buf
    }
}
