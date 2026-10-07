//! Synthetic AFF4-L container construction for tests.
//!
//! Builds a byte-level valid ZIP of **stored** members — the AFF4-L
//! container profile — with `information.turtle`, `container.description`
//! and `version.txt`. Digests embedded in the manifest are real SHA-256
//! values (via `sutram_aff4::sha256_hex`, the crate's hidden test helper).
//! Corruption cases are produced by patching bytes after the fact.

/// Little-endian writers over a `Vec<u8>`.
pub fn w16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
pub fn w32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// CRC-32 (IEEE, polynomial 0xEDB88320) — zip members need real CRCs.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

/// One stored member (name + bytes).
#[derive(Clone)]
pub struct Member {
    pub name: String,
    pub data: Vec<u8>,
    /// Offset of this member's local file header in the built image.
    pub lfh_off: u64,
}

/// A built container plus enough bookkeeping to assert provenance.
pub struct Built {
    pub image: Vec<u8>,
    /// `(name, lfh_off)` in member order.
    pub members: Vec<(String, u64)>,
    /// Absolute offset of the central directory.
    pub cd_off: u64,
}

/// Minimal stored-member ZIP builder: LFH + data per member, then CD,
/// then EOCD. Method 0 (store), no extras, DOS timestamp 2020-01-01.
pub fn build_zip(members: &[(&str, &[u8])]) -> Built {
    let mut img = Vec::new();
    let mut recs: Vec<(String, u64, u32, u32)> = Vec::new(); // name, lfh_off, crc, len
    for (name, data) in members {
        let lfh = img.len() as u64;
        let crc = crc32(data);
        w32(&mut img, 0x0403_4b50); // LFH sig
        w16(&mut img, 20); // version needed
        w16(&mut img, 0x0800); // flags: UTF-8 names
        w16(&mut img, 0); // method: store
        w16(&mut img, 0); // mod time
        w16(&mut img, (33 << 9) | (1 << 5) | 1); // date: 2020-01-01
        w32(&mut img, crc);
        w32(&mut img, data.len() as u32);
        w32(&mut img, data.len() as u32);
        w16(&mut img, name.len() as u16);
        w16(&mut img, 0); // extra len
        img.extend_from_slice(name.as_bytes());
        img.extend_from_slice(data);
        recs.push((name.to_string(), lfh, crc, data.len() as u32));
    }
    let cd_off = img.len() as u64;
    for (name, lfh, crc, len) in &recs {
        w32(&mut img, 0x0201_4b50); // CD sig
        w16(&mut img, 0x033f); // made by unix, spec 6.3
        w16(&mut img, 20);
        w16(&mut img, 0x0800);
        w16(&mut img, 0);
        w16(&mut img, 0);
        w16(&mut img, (33 << 9) | (1 << 5) | 1);
        w32(&mut img, *crc);
        w32(&mut img, *len);
        w32(&mut img, *len);
        w16(&mut img, name.len() as u16);
        w16(&mut img, 0); // extra
        w16(&mut img, 0); // comment
        w16(&mut img, 0); // disk
        w16(&mut img, 0); // int attrs
        w32(&mut img, 0); // ext attrs
        w32(&mut img, *lfh as u32);
        img.extend_from_slice(name.as_bytes());
    }
    let cd_size = img.len() as u64 - cd_off;
    w32(&mut img, 0x0605_4b50); // EOCD
    w16(&mut img, 0);
    w16(&mut img, 0);
    w16(&mut img, recs.len() as u16);
    w16(&mut img, recs.len() as u16);
    w32(&mut img, cd_size as u32);
    w32(&mut img, cd_off as u32);
    w16(&mut img, 0); // comment len
    Built {
        image: img,
        members: recs.into_iter().map(|(n, o, _, _)| (n, o)).collect(),
        cd_off,
    }
}

pub const CONTAINER_ARN: &str = "aff4://c0ffee00-c0ff-ee00-c0ff-ee00c0ffee00";

/// A canonical `information.turtle` line-set for `members`: each member
/// gets `<ARN/name> a aff4:file_image ; aff4:hash <aff4:sha256=…> .`
/// `extra` raw lines are appended verbatim (unmatched subjects, junk).
pub fn turtle_for(members: &[(&str, &[u8])], extra: &str) -> Vec<u8> {
    let mut t = String::from(
        "@prefix aff4: <http://aff4.org/Schema#> .\n\
         @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n",
    );
    t.push_str(&format!(
        "<{CONTAINER_ARN}> a aff4:zip_volume ;\n    aff4:stored \"container\" .\n\n"
    ));
    for (name, data) in members {
        let hex = sutram_aff4::sha256_hex(data);
        t.push_str(&format!(
            "<{CONTAINER_ARN}/{name}> a aff4:file_image ;\n    aff4:hash <aff4:sha256={hex}> ;\n    aff4:originalSize \"{}\" .\n\n",
            data.len()
        ));
    }
    t.push_str(extra);
    t.into_bytes()
}

/// Full AFF4-L container: `version.txt`, `container.description`,
/// `information.turtle` (hashing `evidence` members), then the evidence
/// members themselves.
pub fn build_aff4(evidence: &[(&str, &[u8])], manifest_extra: &str) -> Built {
    let turtle = turtle_for(evidence, manifest_extra);
    let mut members: Vec<(&str, &[u8])> = vec![
        ("version.txt", b"1.0\n"),
        ("container.description", CONTAINER_ARN.as_bytes()),
        ("information.turtle", &turtle),
    ];
    members.extend_from_slice(evidence);
    build_zip(&members)
}

/// Standard corpus: two evidence files (`evidence/note.txt`,
/// `evidence/photo.raw`), one hash-verified each.
pub fn standard_container() -> Built {
    build_aff4(
        &[
            ("evidence/note.txt", b"the quick brown fox\n".as_ref()),
            ("evidence/photo.raw", &[0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3, 4]),
        ],
        "",
    )
}
