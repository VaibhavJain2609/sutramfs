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
fn zip_subtype_detection() {
    // ODF: stored "mimetype" entry first → Odt (not generic Zip).
    let mut odt = b"PK\x03\x04".to_vec();
    odt.extend_from_slice(&[0x14, 0x00]); // version
    odt.extend_from_slice(&[0x00, 0x00]); // flags
    odt.extend_from_slice(&[0x00, 0x00]); // method = stored
    odt.extend_from_slice(&[0; 16]); // time/date/crc/sizes
    odt.extend_from_slice(&(8u16).to_le_bytes()); // name len
    odt.extend_from_slice(&(0u16).to_le_bytes()); // extra len
    odt.extend_from_slice(b"mimetype");
    odt.extend_from_slice(b"application/vnd.oasis.opendocument.text");
    assert_eq!(detect(&odt), Some(MagicType::Odt));
    // Verdict for the real name stays consistent.
    let v = check_entry("notes.odt", &odt);
    assert!(!v.mismatch, "{:?}", v.reasons);

    // EPUB
    let mut epub = odt.clone();
    epub.truncate(38);
    epub.extend_from_slice(b"application/epub+zip");
    assert_eq!(detect(&epub), Some(MagicType::Epub));

    // APK via first entry name
    let mut apk = b"PK\x03\x04".to_vec();
    apk.extend_from_slice(&[0x14, 0x00, 0x00, 0x00, 0x08, 0x00]);
    apk.extend_from_slice(&[0; 16]);
    apk.extend_from_slice(&(19u16).to_le_bytes());
    apk.extend_from_slice(&(0u16).to_le_bytes());
    apk.extend_from_slice(b"AndroidManifest.xml");
    assert_eq!(detect(&apk), Some(MagicType::Apk));
    // .apk with a real APK layout is consistent, not "just a zip".
    let v = check_entry("app.apk", &apk);
    assert!(!v.mismatch);

    // jar via META-INF first entry ("META-INF/MANIFEST.MF" is 20 bytes)
    let mut jar = apk.clone();
    jar.truncate(30);
    jar.splice(26..28, (20u16).to_le_bytes());
    jar.extend_from_slice(b"META-INF/MANIFEST.MF");
    assert_eq!(detect(&jar), Some(MagicType::Jar));

    // Unrecognised first entry → generic Zip.
    let mut z = apk.clone();
    z.splice(26..28, (7u16).to_le_bytes());
    z.truncate(30);
    z.extend_from_slice(b"foo.txt");
    assert_eq!(detect(&z), Some(MagicType::Zip));
}

#[test]
fn new_media_and_fs_signatures() {
    assert_eq!(detect(b"MThd\0\0\0\x06"), Some(MagicType::Midi));
    assert_eq!(
        detect(b"\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C"),
        Some(MagicType::Asf)
    );
    assert_eq!(detect(b"FORM\0\0\x10\0AIFFCOMM"), Some(MagicType::Aiff));
    assert_eq!(detect(b"\xFF\xF1\x50"), Some(MagicType::Aac)); // ADTS
    assert_eq!(detect(b"\xFF\xFB\x90"), Some(MagicType::Mp3)); // frame sync still MP3
    assert_eq!(detect(b"MSWIM\0\0\0rest"), Some(MagicType::Wim));
    assert_eq!(detect(b"\xED\xAB\xEE\xDBx"), Some(MagicType::Rpm));
    assert_eq!(detect(b"xar!\0"), Some(MagicType::Xar));
    assert_eq!(detect(b"0707010000"), Some(MagicType::Cpio));
    assert_eq!(detect(b"\x78\x9Crest"), Some(MagicType::Zlib));
    assert_eq!(detect(b"hsqs...."), Some(MagicType::Squashfs));
    assert_eq!(detect(b"\x45\x3D\xCD\x28"), Some(MagicType::Cramfs));
    assert_eq!(detect(b"ANDROID!boot"), Some(MagicType::AndroidBoot));
    assert_eq!(detect(b"\x3A\xFF\x26\xED"), Some(MagicType::AndroidSparse));
    assert_eq!(detect(b"INDX...."), Some(MagicType::NtfsIndx));
    assert_eq!(detect(b"RCRD...."), Some(MagicType::NtfsLog));
    assert_eq!(detect(b"LfLerest"), Some(MagicType::Evt));
    assert_eq!(detect(b"Bud1...."), Some(MagicType::DsStore));
    assert_eq!(detect(b"CMMM...."), Some(MagicType::Thumbcache));
    assert_eq!(detect(b"hibr...."), Some(MagicType::Hiberfil));
    assert_eq!(detect(b"MDMP...."), Some(MagicType::Crashdump));
    // ESE db: signature at offset 4
    assert_eq!(detect(b"\0\0\0\0\xEF\xCD\xAB\x89"), Some(MagicType::Esedb));
    // GPT header at LBA 1
    let mut disk = vec![0u8; 0x400];
    disk[0x200..0x208].copy_from_slice(b"EFI PART");
    assert_eq!(detect(&disk), Some(MagicType::Gpt));
    // JP2/JXL
    assert_eq!(
        detect(b"\x00\x00\x00\x0CjP  \x0D\x0A\x87\x0A"),
        Some(MagicType::Jp2)
    );
    assert_eq!(
        detect(b"\x00\x00\x00\x0CJXL \x0D\x0A\x87\x0A"),
        Some(MagicType::Jxl)
    );
    // HTML
    assert_eq!(detect(b"<!DOCTYPE html>\n"), Some(MagicType::Html));
    assert_eq!(detect(b"<html><body>"), Some(MagicType::Html));
}

#[test]
fn container_family_accepts() {
    // .heic whose brand reads as avif — same HEIF family, not suspicious.
    let mut f = vec![0, 0, 0, 0x20];
    f.extend_from_slice(b"ftypavif");
    let v = check_entry("img.heic", &f);
    assert!(!v.mismatch, "{:?}", v.reasons);
    // .plist that is an XML plist — legit.
    let v = check_entry("Info.plist", b"<?xml version=\"1.0\"?>");
    assert!(!v.mismatch);
    // .zip that is really a jar — same family, Info.
    let mut j = b"PK\x03\x04".to_vec();
    j.extend_from_slice(&[0x14, 0x00, 0x00, 0x00, 0x08, 0x00]);
    j.extend_from_slice(&[0; 16]);
    j.extend_from_slice(&(20u16).to_le_bytes());
    j.extend_from_slice(&(0u16).to_le_bytes());
    j.extend_from_slice(b"META-INF/MANIFEST.MF");
    let v = check_entry("libs.zip", &j);
    assert_eq!(v.detected, Some(MagicType::Jar));
    assert!(!v.mismatch, "{:?}", v.reasons);
    // .ps1 containing a PE → High (script extension masquerade).
    let v = check_entry("setup.ps1", b"MZ\x90\0\x03\0\0\0");
    assert!(v.mismatch);
    assert_eq!(v.severity, Severity::High);
    // .py with a real shebang → consistent (Script accepts ShellScript).
    let v = check_entry("tool.py", b"#!/usr/bin/env python3\n");
    assert!(!v.mismatch, "{:?}", v.reasons);
}

#[test]
fn trailer_note_only_with_size() {
    // Header-only probe of a big PNG must NOT claim "may be truncated".
    let hdr = *b"\x89PNG\x0D\x0A\x1A\x0A\x00\x00\x00\x0DIHDR";
    let v = check_entry("big.png", &hdr);
    assert!(!v.reasons.iter().any(|r| r.contains("trailer")));
    // Whole file without IEND → the note fires via check_entry_sized.
    let v = check_entry_sized("tiny.png", &hdr, hdr.len() as u64);
    assert!(v.reasons.iter().any(|r| r.contains("trailer")));
    // Whole file WITH the trailer → no note.
    let ok = *b"\x89PNG\x0D\x0A\x1A\x0A....IEND\xAE\x42\x60\x82";
    let v = check_entry_sized("ok.png", &ok, ok.len() as u64);
    assert!(!v.reasons.iter().any(|r| r.contains("trailer")));
}

#[test]
fn script_extension_masquerade() {
    // .bat containing ELF → High.
    let v = check_entry("runme.bat", b"\x7fELF\x02\x01");
    assert!(v.mismatch);
    assert_eq!(v.severity, Severity::High);
    // .bat that is plain text → Info (no magic, no panic).
    let v = check_entry("runme.bat", b"@echo off\r\ndir\r\n");
    assert!(!v.mismatch);
    assert_eq!(v.severity, Severity::Info);
}

#[test]
fn verdict_edge_reasons() {
    // Detected content with an unmapped extension → Info with detection note.
    let v = check_entry("blob.xyz", b"MZ\x90\0\x03\0\0\0");
    assert_eq!(v.declared, None);
    assert_eq!(v.detected, Some(MagicType::Pe));
    assert!(v.reasons[0].contains("no declared type"));
    // ODS/ODP subtype detection.
    let mk = |mime: &[u8]| {
        let mut z = b"PK\x03\x04".to_vec();
        z.extend_from_slice(&[0x14, 0, 0, 0, 0, 0]);
        z.extend_from_slice(&[0; 16]);
        z.extend_from_slice(&(8u16).to_le_bytes());
        z.extend_from_slice(&(0u16).to_le_bytes());
        z.extend_from_slice(b"mimetype");
        z.extend_from_slice(mime);
        z
    };
    assert_eq!(
        detect(&mk(b"application/vnd.oasis.opendocument.spreadsheet")),
        Some(MagicType::Ods)
    );
    assert_eq!(
        detect(&mk(b"application/vnd.oasis.opendocument.presentation")),
        Some(MagicType::Odp)
    );
    assert_eq!(
        detect(&mk(b"application/vnd.sun.xml.writer")),
        Some(MagicType::Odt)
    );
    assert_eq!(detect(&mk(b"application/x-unknown")), Some(MagicType::Zip));
}

#[test]
fn all_types_have_names_categories_and_self_accept() {
    use MagicType::*;
    let all = [
        Pe, Elf, MachO32, MachO64, MachOFat, Wasm, JavaClass, Dex, ShellScript, Script, Lnk,
        DyldCache, Pdf, PostScript, Rtf, Docx, Xlsx, Pptx, Doc, Xls, Ppt, Odt, Ods, Odp, Epub,
        OneNote, Msg, Pst, Chm, Mobi, Png, Jpeg, Gif87, Gif89, Bmp, TiffLe, TiffBe, WebP, Ico,
        Cur, Psd, Heic, Avif, Jp2, Jxl, Mp3, Wav, Avi, Mp4, Mov, ThreeGpp, Mkv, Flv, Ogg, Flac,
        Aac, Aiff, Midi, Asf, Zip, Jar, Apk, Gzip, Bzip2, Xz, SevenZ, Rar4, Rar5, Tar, Zstd,
        Lz4, Cab, Ar, Wim, Zlib, Cpio, Rpm, Xar, Ewf, Aff, Dmg, Luks1, Luks2, BitLocker,
        BitLockerToGo, Vmdk, Vhd, Vdi, Qcow, Iso9660, Udf, AndroidSparse, AndroidBoot, Fat,
        ExFat, Ntfs, Ext, Btrfs, F2fs, Apfs, HfsPlus, Xfs, NtfsMftRecord, NtfsIndx, NtfsLog,
        Squashfs, Cramfs, Gpt, Sqlite, SqliteWal, SqliteJournal, RegHive, Evtx, Prefetch,
        Bplist, Ole2, Sdb, Esedb, Thumbcache, DsStore, Evt, Hiberfil, Crashdump, Pem,
        OpenSslSalted, WhatsAppCrypt, Pkcs12, Xml, Html, PlainText, Pcap, PcapNg,
    ];
    for t in all {
        assert!(!t.name().is_empty(), "{t:?} has no name");
        let _ = t.category();
        let _ = t.is_code();
        // Every type must at least accept itself.
        assert!(t.accepts(t), "{t:?} does not accept itself");
    }
    // Spot-check category assignments.
    assert_eq!(Pe.category(), Category::Executable);
    assert_eq!(Script.category(), Category::Script);
    assert!(Pe.is_code() && Script.is_code() && !Png.is_code());
    assert_eq!(Esedb.category(), Category::Database);
    assert_eq!(Hiberfil.category(), Category::Artifact);
    assert_eq!(Squashfs.category(), Category::FileSystem);
}

#[test]
fn whatsapp_crypt_declared_only() {
    // .crypt14 has a declared type but no stable magic — never a panic,
    // verdict explains itself.
    let v = check_entry("msgstore.db.crypt14", b"\xAA\xBB\xCC\xDD");
    assert_eq!(v.declared, Some(MagicType::WhatsAppCrypt));
    assert_eq!(v.severity, Severity::Info);
}

#[test]
fn severity_ordering_and_suspicious_helper() {
    assert!(Severity::Info < Severity::Suspicious);
    assert!(Severity::Suspicious < Severity::High);
    assert!(!check_entry("a.png", b"\x89PNG\x0D\x0A\x1A\x0A").suspicious());
    assert!(check_entry("a.png", b"PK\x03\x04rest").suspicious());
    assert!(check_entry("a.png", b"MZ\x90\0").suspicious());
}

#[test]
fn extension_edge_cases() {
    // Dotfiles and trailing dots have no usable extension.
    assert_eq!(check_entry(".bashrc", b"x").declared, None);
    assert_eq!(check_entry("name.", b"x").declared, None);
    // Path components and case are handled.
    let v = check_entry("dir/sub/photo.PNG", b"\x89PNG\x0D\x0A\x1A\x0A");
    assert_eq!(v.declared, Some(MagicType::Png));
    assert!(!v.mismatch);
    let v = check_entry("back\\slash.jpg", b"\xFF\xD8\xFF\xE0");
    assert_eq!(v.declared, Some(MagicType::Jpeg));
    // Unmapped extension + no magic explains itself.
    let v = check_entry("blob.xyz", b"no known magic here");
    assert_eq!(v.declared, None);
    assert_eq!(v.detected, None);
    assert!(v.reasons[0].contains("unmapped"));
}

#[test]
fn accepts_cross_family_edges() {
    use MagicType::*;
    // Format families that legitimately overlap.
    assert!(Gif87.accepts(Gif89));
    assert!(Gif89.accepts(Gif87));
    assert!(TiffLe.accepts(TiffBe));
    assert!(TiffBe.accepts(TiffLe));
    assert!(Mov.accepts(Mp4));
    assert!(ThreeGpp.accepts(Mp4));
    assert!(Mp4.accepts(Mov));
    assert!(Mp4.accepts(ThreeGpp));
    assert!(!Mp4.accepts(Zip));
    assert!(Pst.accepts(Ole2));
    assert!(Msg.accepts(Ole2));
    assert!(Bplist.accepts(Xml));
    assert!(Html.accepts(Xml));
    assert!(!Xml.accepts(Html));
    assert!(!PlainText.accepts(Png));
    assert!(!Png.accepts(Jpeg));
    assert!(Script.accepts(ShellScript));
    for t in [Jar, Apk, Odt, Ods, Odp, Epub] {
        assert!(Zip.accepts(t), "zip must accept {t:?}");
    }
    // The same rules through real verdicts.
    assert!(!check_entry("a.gif", b"GIF87a....").mismatch);
    assert!(!check_entry("a.tif", b"MM\0*....").mismatch);
    let mut f = vec![0, 0, 0, 0x20];
    f.extend_from_slice(b"ftypisom");
    assert!(!check_entry("a.mov", &f).mismatch);
    let mut f = vec![0, 0, 0, 0x20];
    f.extend_from_slice(b"ftyp3gp4");
    assert!(!check_entry("a.mp4", &f).mismatch);
}

#[test]
fn detect_special_edge_cases() {
    // Too-short buffers never match specials and never panic.
    assert_eq!(detect(b""), None);
    assert_eq!(detect(b"RIFF"), None);
    assert_eq!(detect(b"\xCA\xFE\xBA\xBE\0\0"), None); // < 8 bytes
    // The bare 6-byte LUKS magic still matches the table row.
    assert_eq!(detect(b"LUKS\xBA\xBE"), Some(MagicType::Luks1));
    // Unknown RIFF form type is still a RIFF media file.
    assert_eq!(detect(b"RIFF\x10\0\0\0XXXX"), Some(MagicType::Wav));
    // A FORM that is not AIFF/AIFC is nothing we name.
    assert_eq!(detect(b"FORM\0\0\x10\08SVXCOMM"), None);
    // Reserved MPEG version/layer bits are neither MP3 nor AAC.
    assert_eq!(detect(b"\xFF\xE1\x00\x00"), None);
    assert_eq!(detect(b"\xFF\xE8\x00\x00"), None);
}

#[test]
fn zip_subtype_edge_cases() {
    let hdr = |name: &[u8], method: u16| {
        let mut z = b"PK\x03\x04".to_vec();
        z.extend_from_slice(&[0x14, 0x00]); // version
        z.extend_from_slice(&[0x00, 0x00]); // flags
        z.extend_from_slice(&method.to_le_bytes());
        z.extend_from_slice(&[0; 16]); // time/date/crc/sizes
        z.extend_from_slice(&(name.len() as u16).to_le_bytes());
        z.extend_from_slice(&(0u16).to_le_bytes());
        z.extend_from_slice(name);
        z
    };
    // A *compressed* "mimetype" entry is not an ODF marker.
    let mut z = hdr(b"mimetype", 8);
    z.extend_from_slice(b"application/epub+zip");
    assert_eq!(detect(&z), Some(MagicType::Zip));
    // classes.dex / resources.arsc also identify APKs.
    assert_eq!(detect(&hdr(b"classes.dex", 8)), Some(MagicType::Apk));
    assert_eq!(detect(&hdr(b"resources.arsc", 0)), Some(MagicType::Apk));
    // Legacy OpenOffice MIME strings map to ODF types.
    let mut z = hdr(b"mimetype", 0);
    z.extend_from_slice(b"application/vnd.sun.xml.calc");
    assert_eq!(detect(&z), Some(MagicType::Ods));
    let mut z = hdr(b"mimetype", 0);
    z.extend_from_slice(b"application/vnd.sun.xml.impress");
    assert_eq!(detect(&z), Some(MagicType::Odp));
    // A name_len that overruns the buffer degrades to generic Zip — no panic.
    let mut z = b"PK\x03\x04".to_vec();
    z.extend_from_slice(&[0x14, 0x00, 0x00, 0x00, 0x08, 0x00]);
    z.extend_from_slice(&[0; 16]);
    z.extend_from_slice(&(0xFFFFu16).to_le_bytes());
    z.extend_from_slice(&(0u16).to_le_bytes());
    assert_eq!(detect(&z), Some(MagicType::Zip));
    // Buffer shorter than a local-file header still identifies as Zip.
    assert_eq!(detect(b"PK\x03\x04"), Some(MagicType::Zip));
}

#[test]
fn trailer_edge_cases() {
    // Trailer search tolerates a few trailing pad bytes.
    let mut png = b"\x89PNG\x0D\x0A\x1A\x0Adata".to_vec();
    png.extend_from_slice(b"IEND\xAE\x42\x60\x82");
    png.extend_from_slice(b"\0\0\0\0");
    assert!(has_trailer(MagicType::Png, &png));
    // Buffer shorter than the trailer → false, no panic.
    assert!(!has_trailer(MagicType::Png, b"xx"));
    // A kind with no trailer entry is simply false.
    assert!(!has_trailer(MagicType::Elf, b"whatever"));
    // GIF's single-byte trailer.
    assert!(has_trailer(MagicType::Gif89, b"GIF89a...\x3B"));
    // A lone EOCD tail means *some* zip lives here even without a PK header —
    // the appended-archive / SFX-stub case.
    let mut junk = vec![0u8; 200];
    junk.extend_from_slice(b"PK\x05\x06");
    assert_eq!(detect(&junk), Some(MagicType::Zip));
    // A whole-file zip without an EOCD raises no trailer note (Zip is
    // excluded — truncation of the central directory is routine).
    let v = check_entry_sized("a.zip", b"PK\x03\x04xxxx", 12);
    assert!(!v.reasons.iter().any(|r| r.contains("trailer")));
}

#[test]
fn subtype_detection_is_not_a_polyglot_flag() {
    // A well-formed ODF container must NOT be flagged "multiple
    // signatures": the PK row and the subtype answer describe the same
    // bytes, and its own EOCD trailer is the same archive.
    let mut odt = b"PK\x03\x04".to_vec();
    odt.extend_from_slice(&[0x14, 0x00, 0x00, 0x00, 0x00, 0x00]); // stored
    odt.extend_from_slice(&[0; 16]);
    odt.extend_from_slice(&(8u16).to_le_bytes());
    odt.extend_from_slice(&(0u16).to_le_bytes());
    odt.extend_from_slice(b"mimetype");
    odt.extend_from_slice(b"application/vnd.oasis.opendocument.text");
    odt.extend_from_slice(&[0u8; 64]);
    odt.extend_from_slice(b"PK\x05\x06"); // EOCD inside the 1 KiB tail window
    assert_eq!(detect_all(&odt), vec![MagicType::Odt]);
    let v = check_entry("notes.odt", &odt);
    assert_eq!(v.severity, Severity::Info, "{:?}", v.reasons);
    // LUKS2 likewise: the versioned answer replaces the generic LUKS row.
    assert_eq!(detect_all(b"LUKS\xBA\xBE\0\x02"), vec![MagicType::Luks2]);
    // …while a real GIF+ZIP appended-archive still reports both signatures.
    let mut poly = b"GIF89a\x01\0\x01\0".to_vec();
    poly.extend_from_slice(&[0u8; 40]);
    poly.extend_from_slice(b"PK\x05\x06");
    let all = detect_all(&poly);
    assert!(all.contains(&MagicType::Gif89));
    assert!(all.contains(&MagicType::Zip));
}
