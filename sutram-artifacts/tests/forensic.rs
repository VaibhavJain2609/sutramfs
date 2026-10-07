//! Integration tests: synthetic artifact corpora, provenance assertions,
//! and hostile-input regression (truncation / bit-flip / garbage loops
//! must never panic).

mod common;

use common::*;
use std::time::Duration;
use sutram_artifacts::common::{
    ansi_str, filetime, guid_string, guid_v1_mac_time, mac_absolute_time, read_to_end_bounded,
    slice_at, unix_nanos, unix_secs, utf16_str, Cursor, Error,
};
use sutram_artifacts::{lnk, plist, prefetch, recycle, reg};

// ============================ common.rs ============================

#[test]
fn error_display_and_source() {
    let cases: Vec<(Error, &str)> = vec![
        (
            Error::Corrupt {
                offset: 0x10,
                msg: "bad".into(),
            },
            "corrupt at 0x10: bad",
        ),
        (
            Error::Truncated {
                offset: 4,
                needed: 8,
                available: 2,
            },
            "truncated at 0x4: need 8 bytes, have 2",
        ),
        (
            Error::Unsupported { msg: "v9".into() },
            "unsupported: v9",
        ),
        (
            Error::InvalidInput { msg: "cap".into() },
            "invalid input: cap",
        ),
    ];
    for (e, want) in cases {
        assert_eq!(e.to_string(), want);
        assert!(std::error::Error::source(&e).is_none());
    }
    let io = Error::from(std::io::Error::new(std::io::ErrorKind::Other, "boom"));
    assert!(io.to_string().contains("boom"));
    assert!(std::error::Error::source(&io).is_some());
}

#[test]
fn read_to_end_bounded_limits() {
    let v = read_to_end_bounded(&b"abc"[..], 16).expect("read");
    assert_eq!(v, b"abc");
    // Over the cap → InvalidInput.
    let big = vec![0u8; 70 * 1024];
    assert!(matches!(
        read_to_end_bounded(&big[..], 1024),
        Err(Error::InvalidInput { .. })
    ));
    // Underlying read failure propagates as Io.
    struct Fail;
    impl std::io::Read for Fail {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "x"))
        }
    }
    assert!(matches!(
        read_to_end_bounded(Fail, 16),
        Err(Error::Io(_))
    ));
}

#[test]
fn timestamp_decoders() {
    // FILETIME 0 → unset.
    assert_eq!(filetime(0).value, None);
    let t = filetime(133_000_000_000_000_000);
    assert!(t.value.is_some());
    assert_eq!(t.raw_encoding, "ntfs-filetime");
    // Saturating values → None rather than wrap.
    assert_eq!(filetime(u64::MAX).value, None);

    let u = unix_secs(1_700_000_000, "unix32");
    assert_eq!(u.value, Some(1_700_000_000_000_000_000));
    assert_eq!(u.granularity, Duration::from_secs(1));

    let m = mac_absolute_time(0.0);
    assert_eq!(m.value, Some(978_307_200_000_000_000));
    assert_eq!(mac_absolute_time(f64::NAN).value, None);
    assert_eq!(mac_absolute_time(f64::MAX).value, None);
}

#[test]
fn unix_nanos_validates() {
    assert_eq!(
        unix_nanos(1970, 1, 1, 0, 0, 0, 0),
        Some(0)
    );
    // Known date: 2001-01-01 UTC = 978307200 s.
    assert_eq!(
        unix_nanos(2001, 1, 1, 0, 0, 0, 0),
        Some(978_307_200_000_000_000)
    );
    // Leap day valid in 2000 (div by 400), invalid in 1900.
    assert!(unix_nanos(2000, 2, 29, 0, 0, 0, 0).is_some());
    assert!(unix_nanos(1900, 2, 29, 0, 0, 0, 0).is_none());
    for args in [
        (2024, 0, 1, 0, 0, 0, 0),   // bad month
        (2024, 13, 1, 0, 0, 0, 0),
        (2024, 1, 0, 0, 0, 0, 0),   // bad day
        (2024, 4, 31, 0, 0, 0, 0),  // Apr 31
        (2024, 1, 1, 24, 0, 0, 0),  // bad hour
        (2024, 1, 1, 0, 60, 0, 0),  // bad minute
        (2024, 1, 1, 0, 0, 60, 0),  // bad second
        (2024, 1, 1, 0, 0, 0, -1),
        (2024, 1, 1, 0, 0, 0, 1_000_000_000),
    ] {
        assert_eq!(
            unix_nanos(args.0, args.1, args.2, args.3, args.4, args.5, args.6),
            None
        );
    }
}

#[test]
fn cursor_reads_and_errors() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut c = Cursor::new(&buf);
    assert_eq!(c.u8().unwrap(), 1);
    assert_eq!(c.u16().unwrap(), 0x0403);
    assert_eq!(c.u8().unwrap(), 5);
    let mut c = Cursor::at(&buf, 4);
    assert_eq!(c.u32().unwrap(), 0x08070605);
    let mut c = Cursor::new(&buf);
    assert_eq!(c.be_u32().unwrap(), 0x01020304);
    assert_eq!(c.be_u64().unwrap(), 0x0102030405060708);
    // Truncation errors.
    let mut c = Cursor::at(&buf, 8);
    assert!(matches!(c.u8(), Err(Error::Truncated { .. })));
    let mut c = Cursor::at(&buf, 7);
    assert!(matches!(c.u16(), Err(Error::Truncated { .. })));
    let mut c = Cursor::at(&buf, 5);
    assert!(matches!(c.be_u32(), Err(Error::Truncated { .. })));
    let mut c = Cursor::at(&buf, 1);
    assert!(matches!(c.be_u64(), Err(Error::Truncated { .. })));
    let mut c = Cursor::at(&buf, 6);
    assert!(matches!(c.u64(), Err(Error::Truncated { .. })));
    let mut c = Cursor::at(&buf, 2);
    assert_eq!(c.i32().unwrap(), 0x06050403);
    let mut c = Cursor::new(&buf);
    assert_eq!(c.bytes(3).unwrap(), &[1, 2, 3]);
    assert!(matches!(c.bytes(99), Err(Error::Truncated { .. })));
    c.pos = 4;
    c.skip(4).unwrap();
    assert!(matches!(c.skip(1), Err(Error::Truncated { .. })));
}

#[test]
fn slice_and_string_helpers() {
    let buf = [1u8, 2, 3, 4];
    assert_eq!(slice_at(&buf, 1, 2).unwrap(), &[2, 3]);
    assert!(matches!(
        slice_at(&buf, 3, 4),
        Err(Error::Truncated { .. })
    ));
    assert!(matches!(
        slice_at(&buf, usize::MAX, 4),
        Err(Error::Corrupt { .. })
    ));
    // utf16_str: strips NULs, tolerates odd tail byte.
    assert_eq!(utf16_str(&[b'h', 0, b'i', 0, 0, 0]), "hi");
    assert_eq!(utf16_str(&[b'a', 0, 0xFF]), "a");
    assert_eq!(ansi_str(b"ab\0cd"), "ab");
    assert_eq!(ansi_str(b"nul-free"), "nul-free");
    // guid helpers.
    assert_eq!(guid_string(&[0; 3]), "");
    let g = droid_guid_v1([0x00, 0x0c, 0x29, 0x11, 0x22, 0x33]);
    assert_eq!(
        guid_string(&g),
        "12345678-9abc-1def-8000-000c29112233"
    );
    let (mac, _ts) = guid_v1_mac_time(&g).expect("v1");
    assert_eq!(mac, "00:0c:29:11:22:33");
    assert!(guid_v1_mac_time(&[0; 8]).is_none());
    assert!(guid_v1_mac_time(&[0x11; 16]).is_none()); // not v1
}

// ============================ lnk.rs ============================

#[test]
fn lnk_from_reader_and_flags() {
    let mut b = lnk_header(lnk::flags::RUN_AS_USER | lnk::flags::HAS_ARGUMENTS);
    b.extend_from_slice(&counted_str("/q", false));
    w32(&mut b, 0);
    let f = lnk::LnkFile::from_reader(&b[..]).expect("from_reader");
    assert!(f.run_as_user());
    assert!(!f.unicode_strings);
    assert_eq!(f.arguments.as_deref(), Some("/q"));
}

/// LINKINFO with the extended (0x24) header: unicode paths, unicode
/// volume label, and a CommonNetworkRelativeLink block.
#[test]
fn lnk_linkinfo_extended_header() {
    let mut b = lnk_header(lnk::flags::HAS_LINK_INFO);
    let mut li = Vec::new();
    w32(&mut li, 0); // size patch
    w32(&mut li, 0x24); // extended header
    w32(&mut li, 3); // flags: volumeID + net-rel
    w32(&mut li, 0x24); // volumeID off (right after header)
    // volumeID: 0x14-byte header + unicode "SHARE" label (12 bytes).
    let vol_size = 0x14 + 12;
    let vol_end = 0x24 + vol_size;
    let base = b"C:\\u\\f.exe\0";
    let base_off = vol_end;
    let suffix = b"f.exe\0";
    let suffix_off = base_off + base.len();
    let uni_base: Vec<u16> = "C:\\u\\f.exe".encode_utf16().collect();
    let uni_base_off = suffix_off + suffix.len();
    let uni_suffix: Vec<u16> = "f.exe".encode_utf16().collect();
    let uni_suffix_off = uni_base_off + (uni_base.len() + 1) * 2;
    let net_rel_off = uni_suffix_off + (uni_suffix.len() + 1) * 2;
    w32(&mut li, base_off as u32); // local base path
    w32(&mut li, net_rel_off as u32); // common network rel link
    w32(&mut li, suffix_off as u32); // common suffix
    w32(&mut li, uni_base_off as u32); // local base unicode
    w32(&mut li, uni_suffix_off as u32); // suffix unicode
    assert_eq!(li.len(), 0x24);
    // volumeID header: label_off == 0x14 selects the unicode-label path;
    // the u32 at +0x10 is the volumeID-relative offset of the label.
    w32(&mut li, vol_size as u32); // vsize
    w32(&mut li, 4); // DRIVE_REMOTE
    w32(&mut li, 0x12345678); // serial
    w32(&mut li, 0x14); // label_off == 0x14 → unicode label
    w32(&mut li, 0x14); // label unicode offset (within volumeID)
    wstr16(&mut li, "SHARE");
    w16(&mut li, 0);
    assert_eq!(li.len(), vol_end);
    li.extend_from_slice(base);
    li.extend_from_slice(suffix);
    for u in &uni_base {
        w16(&mut li, *u);
    }
    w16(&mut li, 0);
    for u in &uni_suffix {
        w16(&mut li, *u);
    }
    w16(&mut li, 0);
    // CommonNetworkRelativeLink block (4 filler bytes for provenance).
    w32(&mut li, 0);
    let li_len = li.len() as u32;
    li[0..4].copy_from_slice(&li_len.to_le_bytes());
    b.extend_from_slice(&li);
    w32(&mut b, 0); // terminal
    let f = lnk::LnkFile::parse(&b).expect("parse");
    let li = f.link_info.expect("linkinfo");
    assert_eq!(li.flags, 3);
    let v = li.volume_id.expect("vol");
    assert_eq!(v.drive_type, 4);
    assert!(v.label_is_unicode);
    assert_eq!(v.label, "SHARE");
    assert_eq!(li.local_base_path.as_deref(), Some("C:\\u\\f.exe"));
    assert_eq!(li.local_base_path_unicode.as_deref(), Some("C:\\u\\f.exe"));
    assert_eq!(li.common_path_suffix_unicode.as_deref(), Some("f.exe"));
    assert!(li.common_network_rel_link_offset.is_some());
}

#[test]
fn lnk_all_extra_block_names() {
    use lnk::block_sig as sig;
    let mut b = lnk_header(0);
    for (i, s) in [
        sig::ENVIRONMENT_VARIABLE,
        sig::CONSOLE,
        sig::CONSOLE_FE,
        sig::SPECIAL_FOLDER,
        sig::DARWIN,
        sig::ICON_ENVIRONMENT,
        sig::SHIM,
        sig::PROPERTY_STORE,
        sig::KNOWN_FOLDER,
        sig::VISTA_ID_LIST,
        0xA000_1234, // genuinely unknown
    ]
    .iter()
    .enumerate()
    {
        b.extend_from_slice(&extra_block(*s, &[i as u8; 8]));
    }
    w32(&mut b, 0);
    let f = lnk::LnkFile::parse(&b).expect("parse");
    let names: Vec<&str> = f.extra_blocks.iter().map(|e| e.name).collect();
    assert_eq!(
        names,
        [
            "EnvironmentVariableDataBlock",
            "ConsoleDataBlock",
            "ConsoleFEDataBlock",
            "SpecialFolderDataBlock",
            "DarwinDataBlock",
            "IconEnvironmentDataBlock",
            "ShimDataBlock",
            "PropertyStoreDataBlock",
            "KnownFolderDataBlock",
            "VistaAndAboveIDListDataBlock",
            "Unknown",
        ]
    );
}

#[test]
fn lnk_lenient_failures() {
    // Corrupt IDList → warning and early return.
    let mut b = lnk_header(lnk::flags::HAS_LINK_TARGET_ID_LIST);
    w16(&mut b, 0xFF00); // absurd IDListSize
    b.extend_from_slice(&[0; 8]);
    let f = lnk::LnkFile::parse(&b).expect("parse");
    assert!(f.id_list.is_none());
    assert!(!f.warnings.is_empty());
    assert_eq!(f.end_offset, LNK_HEADER_SIZE);

    // LINKINFO size < 0x1C → warning.
    let mut b = lnk_header(lnk::flags::HAS_LINK_INFO);
    w32(&mut b, 0x10);
    b.extend_from_slice(&[0; 0x10]);
    let f = lnk::LnkFile::parse(&b).expect("parse");
    assert!(f.link_info.is_none());
    assert!(f.warnings[0].contains("link info"));

    // Extra block with size < 8 → warning.
    let mut b = lnk_header(0);
    w32(&mut b, 4);
    w32(&mut b, 0);
    let f = lnk::LnkFile::parse(&b).expect("parse");
    assert!(f.warnings.iter().any(|w| w.contains("< 8")));

    // Truncated extra-block signature → warning.
    let mut b = lnk_header(0);
    w32(&mut b, 0x20); // size but no signature bytes
    let f = lnk::LnkFile::parse(&b).expect("parse");
    assert!(f.warnings.iter().any(|w| w.contains("truncated")));

    // Short tracker block → warning, still enumerated.
    let mut b = lnk_header(0);
    b.extend_from_slice(&extra_block(lnk::block_sig::TRACKER, &[0; 4]));
    w32(&mut b, 0);
    let f = lnk::LnkFile::parse(&b).expect("parse");
    assert!(f.tracker.is_none());
    assert!(f.warnings.iter().any(|w| w.contains("tracker")));
    assert_eq!(f.extra_blocks.len(), 1);
}

#[test]
fn lnk_idlist_multi_item() {
    let mut b = lnk_header(lnk::flags::HAS_LINK_TARGET_ID_LIST);
    // Two items + terminal.
    let idl = [6u8, 0, 1, 2, 3, 4, 5, 0, 9, 8, 7, 0, 0];
    w16(&mut b, idl.len() as u16);
    b.extend_from_slice(&idl);
    w32(&mut b, 0);
    let f = lnk::LnkFile::parse(&b).expect("parse");
    let idl = f.id_list.expect("idl");
    assert_eq!(idl.item_count, 2);
}

// ============================ reg.rs ============================

#[test]
fn hive_from_reader_and_meta() {
    let img = hive();
    let h = reg::Hive::from_reader(&img[..]).expect("from_reader");
    assert_eq!(h.name, "SYSTEM");
    assert_eq!(h.sequence, (1, 1));
    assert_eq!(h.version, (1, 3));
    assert!(h.timestamp.value.is_some());
    assert!(h.bins_size >= 0x1000);
    assert!(reg::detect(&img));
    assert!(!reg::detect(b"nope"));
}

#[test]
fn hive_value_types() {
    assert_eq!(reg::value_type_name(0), "REG_NONE");
    assert_eq!(reg::value_type_name(1), "REG_SZ");
    assert_eq!(reg::value_type_name(2), "REG_EXPAND_SZ");
    assert_eq!(reg::value_type_name(3), "REG_BINARY");
    assert_eq!(reg::value_type_name(4), "REG_DWORD");
    assert_eq!(reg::value_type_name(5), "REG_DWORD_BIG_ENDIAN");
    assert_eq!(reg::value_type_name(6), "REG_LINK");
    assert_eq!(reg::value_type_name(7), "REG_MULTI_SZ");
    assert_eq!(reg::value_type_name(8), "REG_RESOURCE_LIST");
    assert_eq!(reg::value_type_name(9), "REG_FULL_RESOURCE_DESCRIPTOR");
    assert_eq!(reg::value_type_name(10), "REG_RESOURCE_REQUIREMENTS_LIST");
    assert_eq!(reg::value_type_name(11), "REG_QWORD");
    assert_eq!(reg::value_type_name(99), "REG_UNKNOWN");

    // BE dword, multi-sz, and non-string as_string.
    let mut h = HiveBuilder::new();
    let be = h.data(&0x01020304u32.to_be_bytes());
    let v_be = h.vk("BE", 5, be, 4);
    let mut multi = Vec::new();
    wstr16(&mut multi, "one");
    multi.extend_from_slice(&[0, 0]);
    wstr16(&mut multi, "two");
    multi.extend_from_slice(&[0, 0, 0, 0]);
    let dm = h.data(&multi);
    let v_m = h.vk("M", 7, dm, multi.len() as u32);
    let bin = h.data(&[1, 2, 3]);
    let v_b = h.vk("B", 3, bin, 3);
    let vl = h.val_list(&[v_be, v_m, v_b]);
    let root = h.nk("R", NIL, 0, vl, 3, 1);
    let img = h.build(root);
    let keys = reg::Hive::parse(&img).expect("parse").all_keys();
    let vals = &keys[0].values;
    let be = vals.iter().find(|v| v.name == "BE").unwrap();
    assert_eq!(be.as_u32(), Some(0x01020304));
    assert_eq!(be.as_string(), None); // wrong type
    let m = vals.iter().find(|v| v.name == "M").unwrap();
    assert_eq!(
        m.as_multi_string().unwrap(),
        vec!["one".to_string(), "two".to_string()]
    );
    let bb = vals.iter().find(|v| v.name == "B").unwrap();
    assert_eq!(bb.as_multi_string(), None);
    assert_eq!(bb.as_u32(), None); // only 3 bytes
}

#[test]
fn hive_subkey_list_variants() {
    // lh list + li list + ri → li indirection.
    let mut h = HiveBuilder::new();
    let c1 = h.nk("L1", NIL, 0, NIL, 0, 1);
    let c2 = h.nk("L2", NIL, 0, NIL, 0, 1);
    let lh = h.subkey_list(b"lh", &[c1]);
    let li = h.subkey_list(b"li", &[c2]);
    let ri = h.subkey_list(b"ri", &[li]);
    let parent_lh = h.nk("P1", lh, 1, NIL, 0, 1);
    let parent_ri = h.nk("P2", ri, 1, NIL, 0, 1);
    let top = h.subkey_list(b"lf", &[parent_lh, parent_ri]);
    let root = h.nk("R", top, 2, NIL, 0, 1);
    let img = h.build(root);
    let keys = reg::Hive::parse(&img).expect("parse").all_keys();
    let names: Vec<&str> = keys.iter().map(|k| k.name.as_str()).collect();
    assert_eq!(keys.len(), 4);
    for n in ["R", "P1", "P2", "L2"] {
        assert!(names.contains(&n), "missing {n}");
    }
    // L1 reachable via lh under P1.
    let l1 = keys.iter().find(|k| k.name == "L1");
    assert!(l1.is_some());
}

#[test]
fn hive_big_data_db() {
    let mut h = HiveBuilder::new();
    // Two segments of ~0x3000 each → 0x5000 > BIG_DATA_THRESHOLD.
    let s1 = h.data(&vec![0xAA; 0x3000]);
    let s2 = h.data(&vec![0xBB; 0x2008]);
    let list = h.val_list(&[s1, s2]);
    let db = h.db(list, 2);
    let v = h.vk("Big", 3, db, 0x5008);
    let vl = h.val_list(&[v]);
    let root = h.nk("R", NIL, 0, vl, 1, 1);
    let img = h.build(root);
    let keys = reg::Hive::parse(&img).expect("parse").all_keys();
    let v = &keys[0].values[0];
    assert!(v.big_data);
    assert_eq!(v.data.len(), 0x5008);
    assert_eq!(v.data[0], 0xAA);
    assert_eq!(v.data[0x3000], 0xBB);
    assert!(v.data_offset.is_some());
}

#[test]
fn hive_db_bad_list() {
    let mut h = HiveBuilder::new();
    let db = h.db(NIL, 2); // segment list → nil cell
    let v = h.vk("Big", 3, db, 0x5000);
    let vl = h.val_list(&[v]);
    let root = h.nk("R", NIL, 0, vl, 1, 1);
    let img = h.build(root);
    let keys = reg::Hive::parse(&img).expect("parse").all_keys();
    // Data undecodable — metadata survives, data empty.
    let v = &keys[0].values[0];
    assert!(!v.big_data);
    assert!(v.data.is_empty());
}

#[test]
fn hive_deleted_vk_and_dangling() {
    let mut h = HiveBuilder::new();
    let root = h.nk("R", NIL, 0, NIL, 0, 1);
    h.free_vk("OldVal", 4, 0xFEEDFACE);
    let img = h.build(root);
    let hive = reg::Hive::parse(&img).expect("parse");
    let del = hive.deleted_keys();
    assert_eq!(del.len(), 1);
    assert_eq!(del[0].kind, "vk");
    assert_eq!(del[0].name, "OldVal");
    let (ty, data) = del[0].value.as_ref().unwrap();
    assert_eq!(*ty, 4);
    assert_eq!(data, &0xFEEDFACEu32.to_le_bytes());
}

#[test]
fn hive_mount_failures() {
    // Root cell is a vk, not nk.
    let mut h = HiveBuilder::new();
    let d = h.data(&1u32.to_le_bytes());
    let vk = h.vk("V", 4, d, 4);
    let img = h.build(vk);
    assert!(matches!(
        reg::Hive::parse(&img),
        Err(Error::Corrupt { .. })
    ));
    // Root cell unallocated.
    let mut h = HiveBuilder::new();
    let root = h.nk("R", NIL, 0, NIL, 0, 1);
    let free = h.free_nk("F", 1);
    let mut img = h.build(root);
    p32(&mut img, 0x24, free);
    assert!(matches!(
        reg::Hive::parse(&img),
        Err(Error::Corrupt { .. })
    ));
    // Root cell out of range.
    let mut img = hive();
    p32(&mut img, 0x24, 0x0FFF_FFF0);
    assert!(reg::Hive::parse(&img).is_err());
}

#[test]
fn hive_base_block_warnings() {
    // Torn sequence + unusual version + second hbin missing.
    let mut img = hive();
    p32(&mut img, 8, 7); // secondary seq
    p32(&mut img, 0x14, 2); // major = 2
    let h = reg::Hive::parse(&img).expect("parse");
    assert!(h.warnings.iter().any(|w| w.contains("torn")));
    assert!(h.warnings.iter().any(|w| w.contains("version")));

    // Second hbin with bad sig → warning, still mounts.
    let mut h = HiveBuilder::new();
    let root = h.nk("R", NIL, 0, NIL, 0, 1);
    let mut img = h.build(root);
    img.resize(BASE_BLOCK + img.len() - BASE_BLOCK + 0x1000, 0); // extra junk
    let h = reg::Hive::parse(&img).expect("parse");
    assert!(h.warnings.iter().any(|w| w.contains("no hbin")));
}

#[test]
fn hive_walk_errors_are_items() {
    // subkey list in a free cell → Err item; root still yields.
    let mut h = HiveBuilder::new();
    let list = h.subkey_list(b"lf", &[]);
    let root = h.nk("R", list, 1, NIL, 0, 1);
    let mut img = h.build(root);
    // Flip the lf cell to free: rel = list; file off = BASE_BLOCK+list.
    let fo = BASE_BLOCK + list as usize;
    let sz = i32::from_le_bytes(img[fo..fo + 4].try_into().unwrap());
    img[fo..fo + 4].copy_from_slice(&(-sz).to_le_bytes());
    let hive = reg::Hive::parse(&img).expect("parse");
    let res: Vec<_> = hive.walk().collect();
    assert!(res.iter().any(|r| r.is_ok()));
    assert!(res.iter().any(|r| r.is_err()));

    // Unknown list signature → Err item.
    let mut h = HiveBuilder::new();
    let bogus = h.subkey_list(b"zz", &[0]);
    let root = h.nk("R", bogus, 1, NIL, 0, 1);
    let img = h.build(root);
    let res: Vec<_> = reg::Hive::parse(&img)
        .expect("parse")
        .walk()
        .collect();
    assert!(res.iter().any(|r| r.is_err()));

    // List count overruns cell → Err item.
    let mut h = HiveBuilder::new();
    let lf = h.subkey_list(b"lf", &[0x30]); // declares 1 entry
    let root = h.nk("R", lf, 9, NIL, 0, 1); // count mismatch is fine
    let mut img = h.build(root);
    let fo = BASE_BLOCK + lf as usize;
    img[fo + 4 + 2] = 0xFF; // claimed count = 0xFF → overrun
    let res: Vec<_> = reg::Hive::parse(&img)
        .expect("parse")
        .walk()
        .collect();
    assert!(res.iter().any(|r| r.is_err()));
}

#[test]
fn hive_value_list_corruption() {
    // Value list cell freed → warning Err item, key still yields.
    let mut h = HiveBuilder::new();
    let d = h.data(&1u32.to_le_bytes());
    let v = h.vk("V", 4, d, 4);
    let vl = h.val_list(&[v]);
    let root = h.nk("R", NIL, 0, vl, 1, 1);
    let mut img = h.build(root);
    let fo = BASE_BLOCK + vl as usize;
    let sz = i32::from_le_bytes(img[fo..fo + 4].try_into().unwrap());
    img[fo..fo + 4].copy_from_slice(&(-sz).to_le_bytes());
    let res: Vec<_> = reg::Hive::parse(&img)
        .expect("parse")
        .walk()
        .collect();
    assert!(res.iter().any(|r| r.is_err()));

    // Value list reference outside any hbin → warning.
    let mut h = HiveBuilder::new();
    let root = h.nk("R", NIL, 0, 0x0FFF_FF00, 1, 1);
    let img = h.build(root);
    let res: Vec<_> = reg::Hive::parse(&img)
        .expect("parse")
        .walk()
        .collect();
    assert!(res.iter().any(|r| r.is_err()));

    // Value ref points at non-vk cell → warning.
    let mut h = HiveBuilder::new();
    let not_vk = h.data(&[0u8; 0x18]);
    let vl = h.val_list(&[not_vk]);
    let root = h.nk("R", NIL, 0, vl, 1, 1);
    let img = h.build(root);
    let res: Vec<_> = reg::Hive::parse(&img)
        .expect("parse")
        .walk()
        .collect();
    assert!(res.iter().any(|r| r.is_err()));

    // Dangling vk data pointer → key parses, value data empty.
    let mut h = HiveBuilder::new();
    let v = h.vk("Dangling", 3, NIL, 16);
    let vl = h.val_list(&[v]);
    let root = h.nk("R", NIL, 0, vl, 1, 1);
    let img = h.build(root);
    let keys = reg::Hive::parse(&img).expect("parse").all_keys();
    assert!(keys[0].values[0].data.is_empty());
}

#[test]
fn hive_class_name_and_security() {
    let mut h = HiveBuilder::new();
    let mut cls = Vec::new();
    wstr16(&mut cls, "SystemClass");
    let cls_cell = h.data(&cls);
    let sk = h.data(&[0u8; 0x14]); // fake sk cell (allocated)
    let mut nkb = vec![0u8; 0x4C];
    nkb[0] = b'n';
    nkb[1] = b'k';
    nkb[2..4].copy_from_slice(&0x20u16.to_le_bytes());
    nkb[0x2C..0x30].copy_from_slice(&sk.to_le_bytes());
    nkb[0x30..0x34].copy_from_slice(&cls_cell.to_le_bytes());
    nkb[0x48..0x4A].copy_from_slice(&4u16.to_le_bytes());
    nkb[0x4A..0x4C].copy_from_slice(&(cls.len() as u16).to_le_bytes());
    nkb.extend_from_slice(b"ROOT");
    let root = h.cell(&nkb, true);
    let img = h.build(root);
    let keys = reg::Hive::parse(&img).expect("parse").all_keys();
    assert_eq!(keys[0].security_cell, Some(sk));
    assert_eq!(keys[0].class_name.as_deref(), Some("SystemClass"));
}

#[test]
fn hive_depth_cap() {
    // Chain of 600 nested keys exceeds MAX_DEPTH=512.
    let mut h = HiveBuilder::new();
    let mut child = h.nk("leaf", NIL, 0, NIL, 0, 1);
    for _ in 0..600 {
        let lf = h.subkey_list(b"lf", &[child]);
        child = h.nk("k", lf, 1, NIL, 0, 1);
    }
    let img = h.build(child);
    let res: Vec<_> = reg::Hive::parse(&img).expect("parse").walk().collect();
    assert!(res.iter().any(|r| r.is_ok()));
    assert!(res.iter().any(|r| r.is_err())); // depth-cap error item
}

// ============================ recycle.rs ============================

#[test]
fn irec_from_reader_and_trailing() {
    let f = recycle::RecycledItem::from_reader(&irec_v2("C:\\a.txt")[..])
        .expect("from_reader");
    assert_eq!(f.original_path, "C:\\a.txt");

    // v1 with trailing bytes → warning.
    let mut v1 = irec_v1("C:\\x.bin");
    v1.extend_from_slice(&[0xEE; 8]);
    let f = recycle::RecycledItem::parse(&v1).expect("v1");
    assert!(f.warnings.iter().any(|w| w.contains("trailing")));

    // v2 with trailing bytes → warning.
    let mut v2 = irec_v2("C:\\y.bin");
    v2.extend_from_slice(&[0xEE; 8]);
    let f = recycle::RecycledItem::parse(&v2).expect("v2");
    assert!(f.warnings.iter().any(|w| w.contains("trailing")));
}

#[test]
fn irec_edge_cases() {
    // Exactly 24 bytes of a v1 record → Truncated.
    let v1 = irec_v1("C:\\x");
    assert!(matches!(
        recycle::RecycledItem::parse(&v1[..24]),
        Err(Error::Truncated { .. })
    ));
    // v2 header without name_len → Truncated.
    assert!(matches!(
        recycle::RecycledItem::parse(&v1[..27]),
        Err(Error::Truncated { .. })
    ));
    // detect: short, wrong version, v2 too short.
    assert!(!recycle::detect(&v1[..10]));
    let mut bad = v1.clone();
    p64(&mut bad, 0, 7);
    assert!(!recycle::detect(&bad));
    let mut v2short = irec_v2("C:\\x");
    v2short.truncate(26);
    assert!(!recycle::detect(&v2short));
    // v2 name_len = 0 → empty path.
    let mut v2 = irec_v2("");
    p32(&mut v2, 24, 0);
    let f = recycle::RecycledItem::parse(&v2).expect("parse");
    assert_eq!(f.original_path, "");
}

// ============================ plist.rs ============================

#[test]
fn plist_from_reader_and_more_scalars() {
    let objs: Vec<&[u8]> = vec![
        &[0x00],                                     // null
        &[0x0F],                                     // fill → Null
        &[0x14, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // int128
        &[0x23, 0x3F, 0xF0, 0, 0, 0, 0, 0, 0],       // real f64 = 1.0
        &[0x21, 0x12, 0x34],                         // real 2-byte → NaN warn
        &[0x10, 0x80],                               // int8 sign-extended → -128
        &[0x71, 0xE9],                               // utf-8 string
        &[0x81, 0x12, 0x34],                         // uid 0x1234
        &[0xC1, 1],                                  // set {obj1}
    ];
    // obj0 = array referencing all the scalars (indices 1..=8 incl null)
    let arr: &[u8] = &[0xA9, 0, 1, 2, 3, 4, 5, 6, 7, 8];
    let mut all: Vec<&[u8]> = vec![arr];
    all.extend_from_slice(&objs);
    let img = bplist(&all);
    let bp = plist::Bplist::from_reader(&img[..]).expect("from_reader");
    let root = match &bp.root {
        plist::Plist::Array(v) => v,
        _ => panic!("not array"),
    };
    assert!(matches!(root[0], plist::Plist::Null));
    assert!(matches!(root[1], plist::Plist::Null));
    assert_eq!(
        root[2],
        plist::Plist::Int(i128::from_be_bytes([
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF
        ]))
    );
    assert_eq!(root[3], plist::Plist::Real(1.0));
    if let plist::Plist::Real(f) = root[4] {
        assert!(f.is_nan());
    } else {
        panic!("not real");
    }
    assert_eq!(root[5], plist::Plist::Int(-128));
    assert_eq!(root[6], plist::Plist::String("é".into()));
    assert_eq!(root[7], plist::Plist::Uid(0x1234));
    assert!(matches!(root[8], plist::Plist::Array(_)));
    assert!(!bp.warnings.is_empty()); // 2-byte real warned
    assert_eq!(bp.trailer.num_objects, 10);
    assert_eq!(bp.object_offsets.len(), 10);
}

#[test]
fn plist_json_rendering() {
    // Escapes, null, NaN real, uid, non-string dict key.
    let objs: Vec<&[u8]> = vec![
        &[0xD3, 1, 3, 5, 2, 4, 6],
        &[0x51, b'"'],             // key with quote
        &[0x55, b'a', b'\\', b'\n', 0x01, b'z'], // escapable chars
        &[0x11, 0x00, 0x07],       // non-string key (int 7)
        &[0x80, 0x2A],             // uid 42
        &[0x00],                   // null value
        &[0x09],                   // true
    ];
    let bp = plist::Bplist::parse(&bplist(&objs)).expect("parse");
    let json = bp.root.to_json();
    assert!(json.contains("\\\""), "{json}");
    assert!(json.contains("a\\\\\\n\\u0001z"), "{json}");
    assert!(json.contains("\"7\":{\"$uid\":42}"), "{json}");
    // Standalone null + non-finite real render "null".
    let n = plist::Plist::parse(&bplist(&[&[0x00]])).unwrap();
    assert_eq!(n.to_json(), "null");
    let r = plist::Plist::parse(&bplist(&[
        &[0x23, 0x7F, 0xF8, 0, 0, 0, 0, 0, 0],
    ]))
    .unwrap();
    assert_eq!(r.to_json(), "null");
    // A date with no representable value → null.
    let d = plist::Plist::Date(mac_absolute_time(f64::NAN));
    assert_eq!(d.to_json(), "null");
}

#[test]
fn plist_trailer_edge_cases() {
    let good_obj: &[u8] = &[0x09];
    // num_objects → offset-table length overflow.
    let mut b = bplist(&[good_obj]);
    let n = b.len();
    b[n - 24..n - 16].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(matches!(
        plist::Bplist::parse(&b),
        Err(Error::Corrupt { .. })
    ));
    // offset table offset pointing into the trailer.
    let mut b = bplist(&[good_obj]);
    let n = b.len();
    b[n - 8..].copy_from_slice(&(n as u64 - 8).to_be_bytes());
    assert!(matches!(
        plist::Bplist::parse(&b),
        Err(Error::Corrupt { .. })
    ));
    // object_ref_size = 0 → Corrupt.
    let mut b = bplist(&[good_obj]);
    let n = b.len();
    b[n - 25] = 0;
    assert!(matches!(
        plist::Bplist::parse(&b),
        Err(Error::Corrupt { .. })
    ));
    // offset entry out of bounds (< 8).
    let b = bplist_custom(&[good_obj], &[4], 1, 1, 0, 0x09);
    assert!(matches!(
        plist::Bplist::parse(&b),
        Err(Error::Corrupt { .. })
    ));
}

#[test]
fn plist_extended_count_errors() {
    // Extended count marker not an int → Corrupt.
    let b = bplist(&[&[0x5F, 0x50, b'a']]);
    assert!(matches!(
        plist::Bplist::parse(&b),
        Err(Error::Corrupt { .. })
    ));
    // Extended count int wider than 8 bytes → Corrupt.
    let b = bplist(&[&[0x5F, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]]);
    assert!(matches!(
        plist::Bplist::parse(&b),
        Err(Error::Corrupt { .. })
    ));
    // Huge count → Truncated when payload runs out.
    let b = bplist(&[&[0x5F, 0x13, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]]);
    assert!(matches!(
        plist::Bplist::parse(&b),
        Err(Error::Truncated { .. })
    ));
    // Object ref out of range → Corrupt.
    let b = bplist(&[&[0xA1, 0x7F], &[0x09]]);
    assert!(matches!(
        plist::Bplist::parse(&b),
        Err(Error::Corrupt { .. })
    ));
}

#[test]
fn plist_budget_exhaustion() {
    // Root array with 2000 refs to a single int object → node budget
    // (2*8+64 = 80) exhausts, decode degrades to Null + warning.
    let mut arr = vec![0xAF, 0x11, 0x07, 0xD0]; // count 2000
    arr.extend(std::iter::repeat(1u8).take(2000));
    let objs: Vec<&[u8]> = vec![&arr, &[0x10, 0x2A]];
    let bp = plist::Bplist::parse(&bplist(&objs)).expect("parse");
    assert!(bp
        .warnings
        .iter()
        .any(|w| w.contains("budget")));
}

// ============================ prefetch.rs ============================

#[test]
fn prefetch_from_reader_and_detect() {
    let b = prefetch(23, 0x100);
    let p = prefetch::Prefetch::from_reader(&b[..]).expect("from_reader");
    assert_eq!(p.version, Some(23));
    assert!(p.body().is_ok());
    assert!(!prefetch::detect(b"nope"));
    assert!(!prefetch::detect(&[0u8; 4]));
    let mut bad = prefetch(42, 0x100);
    assert!(!prefetch::detect(&bad));
    bad[4..8].copy_from_slice(b"XXXX");
    assert!(!prefetch::detect(&bad));
}

#[test]
fn prefetch_v26_and_v31() {
    let mut b = prefetch(26, 0x200);
    for i in 0..8 {
        p64(&mut b, 0x80 + i * 8, 133_000_000_000_000_000 + i as u64);
    }
    p32(&mut b, 0xD0, 12);
    let p = prefetch::Prefetch::parse(&b).expect("v26");
    assert_eq!(p.run_count, Some(12));
    assert_eq!(p.last_run_times.len(), 8);

    let mut b = prefetch(31, 0x200);
    p32(&mut b, prefetch::HEADER_LEN, 0x130);
    p32(&mut b, 0xD0, 3);
    let p = prefetch::Prefetch::parse(&b).expect("v31");
    assert_eq!(p.version, Some(31));
    assert_eq!(p.run_count, Some(3));
}

#[test]
fn prefetch_warnings_and_mam_edge() {
    // Claimed size mismatch → warning.
    let mut b = prefetch(17, 0xA0);
    p32(&mut b, 0x0C, 0xDEAD);
    let p = prefetch::Prefetch::parse(&b).expect("parse");
    assert!(p.warnings.iter().any(|w| w.contains("!=")));

    // File too short for run-time slot / run count → warnings.
    let b = prefetch(23, 0x90);
    let p = prefetch::Prefetch::parse(&b).expect("parse");
    assert!(p.warnings.iter().any(|w| w.contains("run count")));

    // v30 metrics unknown → default 0xD0, no variant warning.
    let mut b = prefetch(30, 0x200);
    p32(&mut b, prefetch::HEADER_LEN, 0x999);
    p32(&mut b, 0xD0, 8);
    let p = prefetch::Prefetch::parse(&b).expect("parse");
    assert_eq!(p.run_count, Some(8));
    assert!(!p.warnings.iter().any(|w| w.contains("variant")));

    // MAM header truncated before size field → uncompressed_size None.
    let p = prefetch::Prefetch::parse(b"MAM\x04").expect("parse");
    assert!(p.compressed);
    assert_eq!(p.uncompressed_size, None);
}

// ============================ cross-format fuzz ============================

/// Truncations, bit flips and garbage must never panic — for *every*
/// parser. Results may be `Ok` or `Err`; a panic is a hard failure.
#[test]
fn hostile_input_never_panics() {
    let corpora: Vec<Vec<u8>> = vec![
        lnk_min(),
        hive(),
        irec_v1("C:\\a"),
        irec_v2("C:\\b"),
        bplist(&[&[0xD1, 1, 2], &[0x53, b'x', b'y', b'z'], &[0x11, 5]]),
        prefetch(30, 0x200),
        b"MAM\x04\x10\x00\x00\x00garbage".to_vec(),
        vec![0xFF; 256],
        vec![],
    ];
    let parse_all = |d: &[u8]| {
        let _ = lnk::LnkFile::parse(d);
        let _ = recycle::RecycledItem::parse(d);
        let _ = prefetch::Prefetch::parse(d);
        let _ = plist::Bplist::parse(d);
        if let Ok(h) = reg::Hive::parse(d) {
            let _ = h.all_keys();
            let _ = h.deleted_keys();
        }
    };
    for base in &corpora {
        for cut in 0..base.len() {
            parse_all(&base[..cut]);
        }
        // Sparse bit flips (full sweep on small inputs).
        let step = if base.len() > 512 { 7 } else { 1 };
        for i in (0..base.len()).step_by(step) {
            let mut m = base.clone();
            m[i] ^= 0xFF;
            parse_all(&m);
        }
    }
}
