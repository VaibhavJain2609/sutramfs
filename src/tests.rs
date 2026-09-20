use crate::*;

#[test]
fn signature_floor() {
    // The forensic contract requires a meaningful DB. Fail loudly if it
    // ever shrinks below 80 rows.
    assert!(SIGNATURES.len() >= 80, "only {} signatures", SIGNATURES.len());
}

#[test]
fn detects_common_types() {
    assert_eq!(detect(b"\x89PNG\x0D\x0A\x1A\x0Arest"), Some(MagicType::Png));
    assert_eq!(detect(b"MZ\x90\0..."), Some(MagicType::Pe));
    assert_eq!(detect(b"\x7fELF\x02\x01"), Some(MagicType::Elf));
    assert_eq!(detect(b"PK\x03\x04abcd"), Some(MagicType::Zip));
    assert_eq!(detect(b"%PDF-1.7"), Some(MagicType::Pdf));
    assert_eq!(detect(b"SQLite format 3\0x"), Some(MagicType::Sqlite));
    assert_eq!(detect(b"regfxxxx"), Some(MagicType::RegHive));
    assert_eq!(detect(b"ElfFile\0"), Some(MagicType::Evtx));
    assert_eq!(detect(b"Rar!\x1A\x07\x01\0"), Some(MagicType::Rar5));
    assert_eq!(detect(b"\x1F\x8B\x08"), Some(MagicType::Gzip));
    assert_eq!(detect(b"GIF89a...."), Some(MagicType::Gif89));
    assert_eq!(detect(b"bplist00.."), Some(MagicType::Bplist));
    assert_eq!(detect(b"\0asm\x01\0\0\0"), Some(MagicType::Wasm));
    assert_eq!(detect(b"#!/bin/sh\necho hi"), Some(MagicType::ShellScript));
    assert_eq!(detect(b"EVF\x09\x0d\x0a\xff\0"), Some(MagicType::Ewf));
    assert_eq!(detect(b"Salted__deadbeef"), Some(MagicType::OpenSslSalted));
    // ftyp brands
    let mut mp4 = vec![0, 0, 0, 0x20];
    mp4.extend_from_slice(b"ftypisom");
    assert_eq!(detect(&mp4), Some(MagicType::Mp4));
    let mut mov = vec![0, 0, 0, 0x20];
    mov.extend_from_slice(b"ftypqt  ");
    assert_eq!(detect(&mov), Some(MagicType::Mov));
    // RIFF
    assert_eq!(detect(b"RIFF\x10\0\0\0WAVEfmt "), Some(MagicType::Wav));
    assert_eq!(detect(b"RIFF\x10\0\0\0AVI LIST"), Some(MagicType::Avi));
    assert_eq!(detect(b"RIFF\x10\0\0\0WEBPVP8 "), Some(MagicType::WebP));
}

#[test]
fn cafebabe_disambiguation() {
    // Java class: minor 0, major 61 → CAFEBABE 0000 003D
    assert_eq!(
        detect(b"\xCA\xFE\xBA\xBE\0\0\0\x3D"),
        Some(MagicType::JavaClass)
    );
    // Mach-O fat: nfat_arch = 2
    assert_eq!(
        detect(b"\xCA\xFE\xBA\xBE\0\0\0\x02"),
        Some(MagicType::MachOFat)
    );
}

#[test]
fn luks_versions() {
    assert_eq!(
        detect(b"LUKS\xBA\xBE\0\x01"),
        Some(MagicType::Luks1)
    );
    assert_eq!(
        detect(b"LUKS\xBA\xBE\0\x02"),
        Some(MagicType::Luks2)
    );
}

#[test]
fn fs_and_offset_signatures() {
    let mut sector = vec![0u8; 0x9002];
    sector[3..11].copy_from_slice(b"NTFS    ");
    assert_eq!(detect(&sector), Some(MagicType::Ntfs));
    sector[3..11].copy_from_slice(b"EXFAT   ");
    assert_eq!(detect(&sector), Some(MagicType::ExFat));
    // ISO9660 at 0x8001
    let mut iso = vec![0u8; 0x8006];
    iso[0x8001..0x8006].copy_from_slice(b"CD001");
    assert_eq!(detect(&iso), Some(MagicType::Iso9660));
    // ext superblock
    let mut ext = vec![0u8; 0x440];
    ext[0x438] = 0x53;
    ext[0x439] = 0xEF;
    assert_eq!(detect(&ext), Some(MagicType::Ext));
}

#[test]
fn trailer_detection() {
    let mut dmg = vec![0u8; 600];
    dmg[596..600].copy_from_slice(b"koly");
    assert_eq!(detect(&dmg), Some(MagicType::Dmg));
    let mut vhd = vec![0u8; 600];
    vhd[592..600].copy_from_slice(b"conectix");
    assert_eq!(detect(&vhd), Some(MagicType::Vhd));
    // PNG with IEND trailer recognised as complete
    let png: &[u8] = b"\x89PNG\x0D\x0A\x1A\x0A....IEND\xAE\x42\x60\x82";
    assert!(has_trailer(MagicType::Png, png));
}

#[test]
fn verdict_consistent() {
    let v = check_entry("photo.png", b"\x89PNG\x0D\x0A\x1A\x0AIEND\xAE\x42\x60\x82");
    assert_eq!(v.declared, Some(MagicType::Png));
    assert_eq!(v.detected, Some(MagicType::Png));
    assert!(!v.mismatch);
    assert_eq!(v.severity, Severity::Info);
}

#[test]
fn verdict_container_not_mismatch() {
    // .docx with ZIP magic is EXPECTED — OOXML is a zip container.
    let v = check_entry("report.docx", b"PK\x03\x04\x14\0\0\0");
    assert!(!v.mismatch, "{:?}", v.reasons);
    assert_eq!(v.severity, Severity::Info);
    // .jar same story; .doc with OLE2 same story.
    let v = check_entry("app.jar", b"PK\x03\x04\x14\0\0\0");
    assert!(!v.mismatch);
    let v = check_entry("old.doc", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1");
    assert!(!v.mismatch);
}

#[test]
fn verdict_masquerade_high() {
    // .docx whose bytes are a Windows executable → High.
    let v = check_entry("resume.docx", b"MZ\x90\0\x03\0\0\0");
    assert!(v.mismatch);
    assert_eq!(v.severity, Severity::High);
    assert!(v.reasons[0].contains("masquerade"));
    // .png that is ELF → High.
    let v = check_entry("logo.png", b"\x7fELF\x02\x01\x01\0");
    assert!(v.mismatch);
    assert_eq!(v.severity, Severity::High);
    // .txt with a PE inside → High (text extension, binary content).
    let v = check_entry("notes.txt", b"MZ\x90\0\x03\0\0\0");
    assert!(v.mismatch);
    assert_eq!(v.severity, Severity::High);
}

#[test]
fn verdict_suspicious_not_code() {
    // .png that is really a zip → suspicious but not code.
    let v = check_entry("pic.png", b"PK\x03\x04aaaa");
    assert!(v.mismatch);
    assert_eq!(v.severity, Severity::Suspicious);
}

#[test]
fn verdict_no_magic_info() {
    let v = check_entry("readme.md", b"just some text");
    assert!(!v.mismatch);
    assert_eq!(v.severity, Severity::Info);
    assert_eq!(v.detected, None);
    let v = check_entry("noext", b"\x01\x02\x03\x04");
    assert_eq!(v.severity, Severity::Info);
}

#[test]
fn detect_all_polyglot() {
    // GIFAR-style: GIF header + ZIP appended — header sees GIF, EOCD at tail.
    let mut poly = b"GIF89a\x01\0\x01\0".to_vec();
    poly.extend_from_slice(b"PK\x03\x04junkjunk");
    poly.extend_from_slice(b"PK\x05\x06");
    let all = detect_all(&poly);
    assert!(all.contains(&MagicType::Gif89));
    let v = check_entry("evil.gif", &poly);
    assert!(v
        .reasons
        .iter()
        .any(|r| r.contains("polyglot") || r.contains("multiple")));
}

#[test]
fn whatsapp_crypt_declared_only() {
    // .crypt14 has a declared type but no stable magic — never a panic,
    // verdict explains itself.
    let v = check_entry("msgstore.db.crypt14", b"\xAA\xBB\xCC\xDD");
    assert_eq!(v.declared, Some(MagicType::WhatsAppCrypt));
    assert_eq!(v.severity, Severity::Info);
}
