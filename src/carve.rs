//! Carve boundary knowledge: given a detected [`MagicType`], how far does
//! the carved object extend?
//!
//! This module is declarative — it describes *how* to bound each format;
//! the crate stays I/O-free and `sutram-fs` interprets [`CarveBound`]
//! against a `ByteSource`.

use crate::MagicType;

/// Field encoding for [`CarveBound::Declared`].
#[derive(Debug, Clone, Copy)]
pub enum DeclField {
    /// Little-endian u32.
    U32Le,
    /// Big-endian u32.
    U32Be,
    /// Little-endian u64.
    U64Le,
}

/// How a carved hit's byte extent is bounded.
#[derive(Debug, Clone, Copy)]
pub enum CarveBound {
    /// Exact fixed-size record (e.g. NTFS MFT `FILE` records).
    Fixed(u64),
    /// Scan forward for any footer byte string; extent ends just past
    /// the match. `eol` additionally absorbs a trailing run through the
    /// next line ending (`%%EOF\r\n`, PEM `END …-----` markers).
    Trailer(&'static [&'static [u8]], bool),
    /// ZIP: scan for EOCD `PK\x05\x06`; extent = record + 22 +
    /// `comment_len` (u16LE at record+20).
    ZipEocd,
    /// Total size declared at a fixed header field:
    /// `extent = field * mult + add`. Zero or implausibly large fields
    /// are rejected by the interpreter.
    Declared {
        offset: usize,
        field: DeclField,
        mult: u64,
        add: u64,
    },
    /// RIFF/AIFF container: u32 size at +4, extent = size + 8 (rounded
    /// up to an even boundary). `be` distinguishes AIFF/`FORM` from RIFF.
    Riff { be: bool },
    /// PNG chunk chain (`len u32BE | type | data | crc`) until IEND
    /// (inclusive of its CRC).
    PngChunks,
    /// ISO-BMFF/QuickTime box walk (`size u32BE | type u32`; size==1 →
    /// 64-bit largesize, size==0 → to end of carve window).
    IsoBmff,
    /// ELF: end of the section-header table (or program headers when
    /// `e_shnum` is 0); 32/64-bit and endian-aware.
    ElfEnd,
    /// PE/COFF: `max(pointer_to_raw_data + size_of_raw_data)` over the
    /// section table, resolved via `e_lfanew`.
    PeEnd,
    /// SQLite3: `page_size (u16BE @16, 1→65536) * page_count (u32BE @28)`.
    SqliteSize,
    /// POSIX tar: 512-byte header blocks, octal size @124, members padded
    /// to 512 bytes; the stream ends at two zero blocks.
    TarEnd,
    /// libpcap: 24-byte global header then `[16-byte hdr + incl_len]`
    /// packet records until truncated or end of window.
    PcapEnd,
    /// No reliable bound — the extent runs to the next signature hit or
    /// the per-type cap, whichever comes first (scalpel semantics).
    ToNextHit,
}

/// A type's carving policy.
pub struct CarveSpec {
    /// How the extent is bounded.
    pub bound: CarveBound,
    /// Hard cap on the carved extent — also the safety limit for
    /// footer scans when no terminator is found.
    pub max: u64,
    /// Primary file extension for carved filenames (`"jpg"`, `"sqlite"`,
    /// …); empty for non-file structures (superblocks, MFT records).
    pub ext: &'static str,
}

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

const fn spec(bound: CarveBound, max: u64, ext: &'static str) -> CarveSpec {
    CarveSpec { bound, max, ext }
}

/// The carving policy for `kind`. Every [`MagicType`] maps to a spec —
/// filesystem/boot-sector types are reported as fixed small extents
/// (structural evidence, not extractable files).
pub fn carve_spec(kind: MagicType) -> CarveSpec {
    use CarveBound::*;
    use MagicType::*;
    const IMAGE: u64 = 256 * MIB;
    const DOC: u64 = 256 * MIB;
    const MEDIA: u64 = 4 * GIB;
    const ARCHIVE: u64 = 4 * GIB;
    const SMALL: u64 = 16 * MIB;

    match kind {
        // ---- bounded images ---------------------------------------------
        Png => spec(PngChunks, IMAGE, "png"),
        Jpeg => spec(Trailer(&[b"\xFF\xD9"], false), IMAGE, "jpg"),
        // The GIF trailer is a lone \x3B — first match wins; embedded
        // 0x3B bytes in LZW data can under-bound a carve (known limit).
        Gif87 | Gif89 => spec(Trailer(&[b"\x3B"], false), 64 * MIB, "gif"),
        Bmp => spec(Declared { offset: 2, field: DeclField::U32Le, mult: 1, add: 0 }, IMAGE, "bmp"),
        TiffLe | TiffBe => spec(ToNextHit, IMAGE, "tif"),
        WebP => spec(Riff { be: false }, IMAGE, "webp"),
        Ico => spec(ToNextHit, SMALL, "ico"),
        Cur => spec(ToNextHit, SMALL, "cur"),
        // PSD: u32BE "length of layer+mask section" at 14, then the image
        // data section follows — declared sizes inside are section-scoped,
        // not file-scoped; cap to next hit.
        Psd => spec(ToNextHit, IMAGE, "psd"),
        Jp2 => spec(IsoBmff, IMAGE, "jp2"),
        Jxl => spec(IsoBmff, IMAGE, "jxl"),
        Heic => spec(IsoBmff, IMAGE, "heic"),
        Avif => spec(IsoBmff, IMAGE, "avif"),

        // ---- bounded documents ------------------------------------------
        Pdf => spec(Trailer(&[b"%%EOF"], true), DOC, "pdf"),
        PostScript => spec(Trailer(&[b"%%EOF"], true), DOC, "ps"),
        Rtf => spec(Trailer(&[b"}"], false), DOC, "rtf"),
        Zip | Jar | Apk | Docx | Xlsx | Pptx | Odt | Ods | Odp | Epub => {
            spec(ZipEocd, ARCHIVE, "zip")
        }
        Ole2 | Doc | Xls | Ppt | Msg => spec(ToNextHit, DOC, "ole2"),
        Pst => spec(ToNextHit, DOC, "pst"),
        Chm => spec(ToNextHit, DOC, "chm"),
        OneNote => spec(ToNextHit, DOC, "one"),
        Mobi => spec(ToNextHit, DOC, "mobi"),

        // ---- media --------------------------------------------------------
        Wav => spec(Riff { be: false }, MEDIA, "wav"),
        Avi => spec(Riff { be: false }, MEDIA, "avi"),
        Aiff => spec(Riff { be: true }, MEDIA, "aif"),
        Mp4 => spec(IsoBmff, MEDIA, "mp4"),
        Mov => spec(IsoBmff, MEDIA, "mov"),
        ThreeGpp => spec(IsoBmff, MEDIA, "3gp"),
        Mkv => spec(ToNextHit, MEDIA, "mkv"),
        Flv => spec(ToNextHit, MEDIA, "flv"),
        Asf => spec(ToNextHit, MEDIA, "asf"),
        Ogg => spec(ToNextHit, MEDIA, "ogg"),
        Flac => spec(ToNextHit, MEDIA, "flac"),
        Mp3 => spec(ToNextHit, MEDIA, "mp3"),
        Aac => spec(ToNextHit, MEDIA, "aac"),
        Midi => spec(ToNextHit, SMALL, "mid"),

        // ---- archives -----------------------------------------------------
        Gzip => spec(ToNextHit, ARCHIVE, "gz"),
        Bzip2 => spec(ToNextHit, ARCHIVE, "bz2"),
        Xz => spec(ToNextHit, ARCHIVE, "xz"),
        SevenZ => spec(ToNextHit, ARCHIVE, "7z"),
        Rar4 | Rar5 => spec(ToNextHit, ARCHIVE, "rar"),
        Tar => spec(TarEnd, ARCHIVE, "tar"),
        Zstd => spec(ToNextHit, ARCHIVE, "zst"),
        Lz4 => spec(ToNextHit, ARCHIVE, "lz4"),
        Cab => spec(Declared { offset: 8, field: DeclField::U32Le, mult: 1, add: 0 }, ARCHIVE, "cab"),
        Ar => spec(ToNextHit, ARCHIVE, "a"),
        Wim => spec(ToNextHit, ARCHIVE, "wim"),
        Zlib => spec(ToNextHit, ARCHIVE, "zz"),
        Cpio => spec(ToNextHit, ARCHIVE, "cpio"),
        Rpm => spec(ToNextHit, ARCHIVE, "rpm"),
        Xar => spec(ToNextHit, ARCHIVE, "pkg"),
        Squashfs => spec(
            Declared { offset: 40, field: DeclField::U64Le, mult: 1, add: 0 },
            ARCHIVE,
            "sqfs",
        ),

        // ---- executables --------------------------------------------------
        Pe => spec(PeEnd, 256 * MIB, "exe"),
        Elf => spec(ElfEnd, 256 * MIB, "elf"),
        MachO32 | MachO64 | MachOFat => spec(ToNextHit, 64 * MIB, "bin"),
        Wasm => spec(ToNextHit, SMALL, "wasm"),
        JavaClass => spec(ToNextHit, SMALL, "class"),
        Dex => spec(Declared { offset: 32, field: DeclField::U32Le, mult: 1, add: 0 }, SMALL, "dex"),
        ShellScript => spec(ToNextHit, SMALL, "sh"),
        Script => spec(ToNextHit, SMALL, "txt"),
        Lnk => spec(ToNextHit, SMALL, "lnk"),
        DyldCache => spec(ToNextHit, 4 * GIB, "dyld"),

        // ---- databases / artifacts ----------------------------------------
        Sqlite => spec(SqliteSize, 4 * GIB, "sqlite"),
        SqliteWal => spec(ToNextHit, DOC, "wal"),
        SqliteJournal => spec(ToNextHit, DOC, "journal"),
        // regf: total hbin size u32LE at 0x28; file = 4096 header + hbins.
        RegHive => spec(
            Declared { offset: 40, field: DeclField::U32Le, mult: 1, add: 4096 },
            DOC,
            "dat",
        ),
        Evtx => spec(ToNextHit, DOC, "evtx"),
        Prefetch => spec(
            Declared { offset: 12, field: DeclField::U32Le, mult: 1, add: 0 },
            SMALL,
            "pf",
        ),
        Bplist => spec(ToNextHit, DOC, "plist"),
        Sdb => spec(ToNextHit, SMALL, "sdb"),
        Esedb => spec(ToNextHit, DOC, "edb"),
        Thumbcache => spec(ToNextHit, DOC, "db"),
        DsStore => spec(ToNextHit, SMALL, "ds_store"),
        Evt => spec(ToNextHit, DOC, "evt"),
        Hiberfil => spec(ToNextHit, 16 * GIB, "sys"),
        Crashdump => spec(ToNextHit, 16 * GIB, "dmp"),

        // ---- captures -----------------------------------------------------
        Pcap => spec(PcapEnd, MEDIA, "pcap"),
        PcapNg => spec(ToNextHit, MEDIA, "pcapng"),

        // ---- crypto / text -------------------------------------------------
        Pem => spec(Trailer(&[b"-----END "], true), SMALL, "pem"),
        OpenSslSalted => spec(ToNextHit, DOC, "enc"),
        WhatsAppCrypt => spec(ToNextHit, DOC, "crypt14"),
        Pkcs12 => spec(ToNextHit, SMALL, "p12"),
        Xml => spec(ToNextHit, DOC, "xml"),
        Html => spec(ToNextHit, DOC, "html"),
        PlainText => spec(ToNextHit, DOC, "txt"),

        // ---- disk / forensic images ---------------------------------------
        // PVD at 0x8000: both-endian volume-space-size u32LE at +0x50;
        // volume = space_size * 2048 bytes measured from the image start.
        Iso9660 => spec(
            Declared { offset: 0x8050, field: DeclField::U32Le, mult: 2048, add: 0 },
            8 * GIB,
            "iso",
        ),
        AndroidSparse => spec(ToNextHit, 16 * GIB, "img"),
        AndroidBoot => spec(ToNextHit, 64 * MIB, "img"),
        Dmg => spec(ToNextHit, MEDIA, "dmg"),
        Vmdk => spec(ToNextHit, SMALL, "vmdk"),
        Ewf | Aff | Vhd | Vdi | Qcow | Udf | Luks1 | Luks2 | BitLocker | BitLockerToGo => {
            spec(ToNextHit, 32 * GIB, "img")
        }

        // ---- filesystem structures: fixed evidence excerpts ---------------
        Fat | ExFat | Ntfs | Ext | Btrfs | F2fs | Apfs | HfsPlus | Xfs | Gpt => {
            spec(Fixed(4096), 4096, "")
        }
        NtfsMftRecord => spec(Fixed(1024), 1024, "mft"),
        NtfsIndx => spec(Fixed(4096), 4096, "indx"),
        NtfsLog => spec(Fixed(4096), 4096, "rcrd"),
        Cramfs => spec(ToNextHit, 2 * GIB, "cramfs"),
    }
}

/// Primary file extension for a carved `kind` — empty for non-file
/// structures (filesystem superblocks, MFT records, boot sectors).
pub fn ext(kind: MagicType) -> &'static str {
    carve_spec(kind).ext
}
