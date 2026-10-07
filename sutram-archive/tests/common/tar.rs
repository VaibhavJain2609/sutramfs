//! Byte-exact TAR image builder (ustar / v7 / pax / GNU variants).

/// A fixed mtime for assertions: 1700000000 = 2023-11-14T22:13:20Z.
pub const MTIME: u64 = 1_700_000_000;

fn octal(f: &mut [u8], v: u64) {
    let width = f.len() - 1;
    let s = format!("{:0width$o}", v, width = width);
    f[..width].copy_from_slice(s.as_bytes());
    f[width] = 0;
}

fn text(f: &mut [u8], s: &str) {
    let n = s.len().min(f.len());
    f[..n].copy_from_slice(&s.as_bytes()[..n]);
}

/// pax `len key=value\n` record bytes for one record.
pub fn pax_record(key: &str, value: &str) -> Vec<u8> {
    let body = format!("{key}={value}\n");
    // Record length includes the decimal digits themselves.
    let mut len = body.len() + 2;
    while format!("{len}").len() + 1 + body.len() != len {
        len = format!("{len}").len() + 1 + body.len();
    }
    format!("{len} {body}").into_bytes()
}

pub fn pax_block(records: &[(&str, &str)]) -> Vec<u8> {
    let mut v = Vec::new();
    for (k, val) in records {
        v.extend_from_slice(&pax_record(k, val));
    }
    v
}

pub struct TarBuilder {
    pub buf: Vec<u8>,
    /// Header offsets, in member order.
    pub member_offsets: Vec<u64>,
}

impl TarBuilder {
    pub fn new() -> Self {
        TarBuilder {
            buf: Vec::new(),
            member_offsets: Vec::new(),
        }
    }

    /// Write one 512-byte header; returns its offset.
    #[allow(clippy::too_many_arguments)]
    pub fn header(
        &mut self,
        name: &str,
        mode: u64,
        uid: u64,
        gid: u64,
        size: u64,
        mtime: u64,
        typeflag: u8,
        linkname: &str,
        magic: &[u8; 6],
        prefix: &str,
    ) -> u64 {
        let off = self.buf.len() as u64;
        let mut h = [0u8; 512];
        text(&mut h[0..100], name);
        octal(&mut h[100..108], mode);
        octal(&mut h[108..116], uid);
        octal(&mut h[116..124], gid);
        octal(&mut h[124..136], size);
        octal(&mut h[136..148], mtime);
        h[156] = typeflag;
        text(&mut h[157..257], linkname);
        h[257..263].copy_from_slice(magic);
        if magic == b"ustar\0" {
            h[263..265].copy_from_slice(b"00");
            text(&mut h[265..297], "user");
            text(&mut h[297..329], "group");
            text(&mut h[345..500], prefix);
        }
        // checksum: field is spaces during summation, then "%06o\0 ".
        let sum: u64 = h
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                if (148..156).contains(&i) {
                    b' ' as u64
                } else {
                    b as u64
                }
            })
            .sum();
        let s = format!("{:06o}\0 ", sum);
        h[148..156].copy_from_slice(s.as_bytes());
        self.buf.extend_from_slice(&h);
        self.member_offsets.push(off);
        off
    }

    fn pad_block(&mut self) {
        let rem = self.buf.len() % 512;
        if rem != 0 {
            self.buf.resize(self.buf.len() + (512 - rem), 0);
        }
    }

    /// Regular file ('0').
    pub fn add_file(&mut self, name: &str, data: &[u8]) -> u64 {
        self.add_typed(name, data, b'0', b"ustar\0")
    }

    pub fn add_typed(&mut self, name: &str, data: &[u8], tf: u8, magic: &[u8; 6]) -> u64 {
        let off = self.header(
            name,
            0o644,
            1000,
            1000,
            data.len() as u64,
            MTIME,
            tf,
            "",
            magic,
            "",
        );
        self.buf.extend_from_slice(data);
        self.pad_block();
        off
    }

    /// ustar prefix+name split (long paths).
    pub fn add_prefixed(&mut self, prefix: &str, name: &str, data: &[u8]) -> u64 {
        let off = self.header(
            name,
            0o644,
            1000,
            1000,
            data.len() as u64,
            MTIME,
            b'0',
            "",
            b"ustar\0",
            prefix,
        );
        self.buf.extend_from_slice(data);
        self.pad_block();
        off
    }

    /// v7 member — no ustar magic.
    pub fn add_v7(&mut self, name: &str, data: &[u8]) -> u64 {
        let off = self.header(
            name,
            0o644,
            0,
            0,
            data.len() as u64,
            MTIME,
            b'0',
            "",
            b"\0\0\0\0\0\0",
            "",
        );
        self.buf.extend_from_slice(data);
        self.pad_block();
        off
    }

    pub fn add_dir(&mut self, name: &str) -> u64 {
        self.header(name, 0o755, 1000, 1000, 0, MTIME, b'5', "", b"ustar\0", "")
    }

    pub fn add_symlink(&mut self, name: &str, target: &str) -> u64 {
        self.header(
            name, 0o777, 1000, 1000, 0, MTIME, b'2', target, b"ustar\0", "",
        )
    }

    pub fn add_hardlink(&mut self, name: &str, target: &str) -> u64 {
        self.header(
            name, 0o644, 1000, 1000, 0, MTIME, b'1', target, b"ustar\0", "",
        )
    }

    /// GNU longname ('L') + member written with the truncated name.
    pub fn add_longname(&mut self, real_name: &str, data: &[u8]) -> u64 {
        let mut nb = real_name.as_bytes().to_vec();
        nb.push(0);
        self.header(
            "././@LongLink",
            0o644,
            0,
            0,
            nb.len() as u64,
            MTIME,
            b'L',
            "",
            b"ustar ",
            "",
        );
        self.buf.extend_from_slice(&nb);
        self.pad_block();
        let short: String = real_name.chars().take(99).collect();
        self.add_typed(&short, data, b'0', b"ustar ")
    }

    /// pax extended header ('x') then the member it applies to.
    pub fn add_pax(&mut self, name: &str, data: &[u8], records: &[(&str, &str)]) -> u64 {
        let pb = pax_block(records);
        self.header(
            "pax_header",
            0o644,
            0,
            0,
            pb.len() as u64,
            MTIME,
            b'x',
            "",
            b"ustar\0",
            "",
        );
        self.buf.extend_from_slice(&pb);
        self.pad_block();
        self.add_file(name, data)
    }

    /// pax sparse member: `map` = [(file_offset, len), …], stored bytes
    /// are the concatenated non-hole regions.
    pub fn add_pax_sparse(
        &mut self,
        name: &str,
        map: &[(u64, u64)],
        stored: &[u8],
        realsize: u64,
    ) -> u64 {
        let map_s = map
            .iter()
            .map(|(o, l)| format!("{o},{l}"))
            .collect::<Vec<_>>()
            .join(",");
        let pb = pax_block(&[
            ("GNU.sparse.map", map_s.as_str()),
            ("GNU.sparse.size", &realsize.to_string()),
            ("GNU.sparse.major", "1"),
            ("GNU.sparse.minor", "0"),
        ]);
        self.header(
            "pax_sparse",
            0o644,
            0,
            0,
            pb.len() as u64,
            MTIME,
            b'x',
            "",
            b"ustar\0",
            "",
        );
        self.buf.extend_from_slice(&pb);
        self.pad_block();
        let off = self.header(
            name,
            0o644,
            0,
            0,
            stored.len() as u64,
            MTIME,
            b'0',
            "",
            b"ustar\0",
            "",
        );
        self.buf.extend_from_slice(stored);
        self.pad_block();
        off
    }

    /// Old-GNU sparse member ('S'): sparse map inside the header,
    /// realsize at 483, magic "ustar ".
    pub fn add_gnu_sparse(
        &mut self,
        name: &str,
        map: &[(u64, u64)],
        stored: &[u8],
        realsize: u64,
    ) -> u64 {
        let off = self.header(
            name,
            0o644,
            0,
            0,
            stored.len() as u64,
            MTIME,
            b'S',
            "",
            b"ustar ",
            "",
        );
        // Patch the header we just wrote with the sparse area.
        let base = off as usize;
        for (i, &(foff, flen)) in map.iter().enumerate().take(4) {
            octal(
                &mut self.buf[base + 386 + i * 24..base + 398 + i * 24],
                foff,
            );
            octal(
                &mut self.buf[base + 398 + i * 24..base + 410 + i * 24],
                flen,
            );
        }
        octal(&mut self.buf[base + 483..base + 495], realsize);
        // Recompute checksum after patching.
        let mut sum: u64 = 0;
        for i in 0..512 {
            let b = self.buf[base + i];
            sum += if (148..156).contains(&i) {
                b' ' as u64
            } else {
                b as u64
            };
        }
        let s = format!("{:06o}\0 ", sum);
        self.buf[base + 148..base + 156].copy_from_slice(s.as_bytes());
        self.buf.extend_from_slice(stored);
        self.pad_block();
        off
    }

    /// Two zero end-blocks + optional trailing padding.
    pub fn finish(self) -> Vec<u8> {
        let mut out = self.buf;
        out.resize(out.len() + 1024, 0);
        out
    }

    /// End blocks then junk — archive slack.
    pub fn finish_with_slack(self, slack: &[u8]) -> Vec<u8> {
        let mut out = self.finish();
        out.extend_from_slice(slack);
        out
    }

    /// No end-of-archive marker — image just stops.
    pub fn finish_bare(self) -> Vec<u8> {
        self.buf
    }
}
