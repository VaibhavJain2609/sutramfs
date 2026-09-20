//! The [`MagicType`] vocabulary — one variant per detectable file type.

/// Broad category of a [`MagicType`]; drives severity decisions (executables
/// and scripts hiding under document/image extensions are `High`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    /// Native/bytecode executables and loadable code.
    Executable,
    /// Interpreted script sources or script containers.
    Script,
    /// Documents: PDF, OOXML, OLE2 office, text-ish formats.
    Document,
    /// Still images.
    Image,
    /// Audio.
    Audio,
    /// Video / multimedia containers.
    Video,
    /// Archives and compressed containers.
    Archive,
    /// Disk / VM / forensic image formats.
    DiskImage,
    /// Filesystem structures (boot sectors, superblocks).
    FileSystem,
    /// Databases.
    Database,
    /// Forensic/OS artefacts: registry hives, EVTX, prefetch, LNK, plist…
    Artifact,
    /// Cryptographic material or encrypted containers.
    Crypto,
    /// Marked-up or delimited text.
    Text,
    /// Anything else.
    Data,
}

/// A known, nameable file type. `detect()` returns these; `check_entry()`
/// compares a *declared* type (from the extension) against the *detected*
/// one.
///
/// Container families matter for masquerade analysis: `Docx`/`Xlsx`/… are
/// ZIP-family types — `detect()` will report `Zip` for their bytes, and
/// [`crate::check_entry`] encodes the "expected container" rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MagicType {
    // --- executables / code ---
    /// DOS/PE Windows executable (`MZ`, confirmed `PE\0\0` when available).
    Pe,
    /// ELF executable/shared object.
    Elf,
    /// Mach-O 32-bit.
    MachO32,
    /// Mach-O 64-bit.
    MachO64,
    /// Mach-O universal/fat binary.
    MachOFat,
    /// WebAssembly module.
    Wasm,
    /// JVM class file.
    JavaClass,
    /// Android Dalvik/ART dex.
    Dex,
    /// Unix shebang script (`#!`).
    ShellScript,
    /// Windows .lnk shortcut (execution artefact).
    Lnk,
    /// macOS dyld shared cache.
    DyldCache,

    // --- documents ---
    /// PDF.
    Pdf,
    /// PostScript.
    PostScript,
    /// Rich Text Format.
    Rtf,
    /// OOXML word processing (docx/docm/dotx) — ZIP container.
    Docx,
    /// OOXML spreadsheet — ZIP container.
    Xlsx,
    /// OOXML presentation — ZIP container.
    Pptx,
    /// Legacy OLE2/CFB Word document.
    Doc,
    /// Legacy OLE2/CFB Excel workbook.
    Xls,
    /// Legacy OLE2/CFB PowerPoint.
    Ppt,
    /// OpenDocument text — ZIP container.
    Odt,
    /// OpenDocument spreadsheet — ZIP container.
    Ods,
    /// OpenDocument presentation — ZIP container.
    Odp,
    /// EPUB ebook — ZIP container.
    Epub,
    /// Microsoft OneNote.
    OneNote,
    /// Outlook MSG (OLE2 container).
    Msg,
    /// Outlook PST (`!BDN`).
    Pst,

    // --- images ---
    /// PNG.
    Png,
    /// JPEG.
    Jpeg,
    /// GIF87a.
    Gif87,
    /// GIF89a.
    Gif89,
    /// BMP/DIB.
    Bmp,
    /// TIFF little-endian.
    TiffLe,
    /// TIFF big-endian.
    TiffBe,
    /// WebP (RIFF).
    WebP,
    /// Windows icon.
    Ico,
    /// Windows cursor.
    Cur,
    /// Photoshop PSD.
    Psd,
    /// HEIC/HEIF (ftyp).
    Heic,
    /// AVIF (ftyp).
    Avif,

    // --- audio / video ---
    /// MP3 (ID3v2 tag or MPEG audio frame sync).
    Mp3,
    /// WAV (RIFF WAVE).
    Wav,
    /// AVI (RIFF).
    Avi,
    /// MP4/M4A/M4V (ftyp ISO-BMFF).
    Mp4,
    /// QuickTime MOV (ftyp `qt  `).
    Mov,
    /// 3GPP (ftyp 3gp*).
    ThreeGpp,
    /// Matroska/WebM (EBML).
    Mkv,
    /// Flash video.
    Flv,
    /// Ogg container.
    Ogg,
    /// FLAC audio.
    Flac,

    // --- archives / compression ---
    /// ZIP (also the container for docx/jar/apk/epub/…).
    Zip,
    /// Java archive — ZIP container.
    Jar,
    /// Android package — ZIP container.
    Apk,
    /// gzip.
    Gzip,
    /// bzip2.
    Bzip2,
    /// xz.
    Xz,
    /// 7-Zip.
    SevenZ,
    /// RAR 4.x.
    Rar4,
    /// RAR 5+.
    Rar5,
    /// POSIX ustar tar.
    Tar,
    /// Zstandard.
    Zstd,
    /// LZ4 frame.
    Lz4,
    /// Microsoft Cabinet.
    Cab,
    /// Unix ar archive (`!<arch>`).
    Ar,

    // --- disk / forensic images ---
    /// Expert Witness Format segment (E01).
    Ewf,
    /// AFF forensic image.
    Aff,
    /// Apple DMG (koly trailer / hdif).
    Dmg,
    /// LUKS1 encrypted volume.
    Luks1,
    /// LUKS2 encrypted volume.
    Luks2,
    /// BitLocker full-volume encryption.
    BitLocker,
    /// BitLocker To Go.
    BitLockerToGo,
    /// VMDK sparse extent descriptor.
    Vmdk,
    /// VHD (`conectix` footer).
    Vhd,
    /// VirtualBox VDI.
    Vdi,
    /// QEMU qcow/qcow2.
    Qcow,
    /// ISO 9660 optical image.
    Iso9660,
    /// UDF optical image.
    Udf,

    // --- filesystems ---
    /// FAT12/16/32 boot sector.
    Fat,
    /// exFAT boot sector.
    ExFat,
    /// NTFS boot sector.
    Ntfs,
    /// ext2/3/4 superblock.
    Ext,
    /// btrfs superblock.
    Btrfs,
    /// F2FS superblock.
    F2fs,
    /// APFS container superblock (NXSB).
    Apfs,
    /// HFS+ volume header (`H+`/`HX`).
    HfsPlus,
    /// XFS superblock.
    Xfs,
    /// NTFS MFT record (`FILE`).
    NtfsMftRecord,

    // --- databases ---
    /// SQLite 3 database.
    Sqlite,
    /// SQLite write-ahead log.
    SqliteWal,
    /// SQLite rollback journal.
    SqliteJournal,

    // --- forensic artefacts ---
    /// Windows registry hive (`regf`).
    RegHive,
    /// Windows event log (`ElfFile`) or chunk (`ElfChnk`).
    Evtx,
    /// Windows prefetch (`SCCA` / `MAM\x04`).
    Prefetch,
    /// Binary plist (`bplist00`).
    Bplist,
    /// Generic OLE2/CFB container (doc/xls/ppt/msg/msi/…).
    Ole2,
    /// Windows shell shim database (`sdb`).
    Sdb,

    // --- crypto / encoded ---
    /// PEM-armoured key/cert (`-----BEGIN `).
    Pem,
    /// OpenSSL salted format (`Salted__`).
    OpenSslSalted,
    /// WhatsApp encrypted backup (crypt12/14/15 — declared by extension;
    /// header structure is versioned, not magic-stable).
    WhatsAppCrypt,
    /// PKCS#12 key store.
    Pkcs12,

    // --- text / misc ---
    /// XML document.
    Xml,
    /// Generic text-like content (declared-by-extension only).
    PlainText,
    /// Capture file: libpcap.
    Pcap,
    /// Capture file: pcapng.
    PcapNg,
}

impl MagicType {
    /// Stable short name for reports.
    pub fn name(self) -> &'static str {
        use MagicType::*;
        match self {
            Pe => "PE/COFF Windows executable",
            Elf => "ELF executable",
            MachO32 => "Mach-O 32-bit",
            MachO64 => "Mach-O 64-bit",
            MachOFat => "Mach-O universal binary",
            Wasm => "WebAssembly module",
            JavaClass => "Java class",
            Dex => "Android dex",
            ShellScript => "shell script",
            Lnk => "Windows shortcut (LNK)",
            DyldCache => "dyld shared cache",
            Pdf => "PDF",
            PostScript => "PostScript",
            Rtf => "RTF",
            Docx => "OOXML document (docx)",
            Xlsx => "OOXML spreadsheet (xlsx)",
            Pptx => "OOXML presentation (pptx)",
            Doc => "OLE2 Word document",
            Xls => "OLE2 Excel workbook",
            Ppt => "OLE2 PowerPoint",
            Odt => "OpenDocument text",
            Ods => "OpenDocument spreadsheet",
            Odp => "OpenDocument presentation",
            Epub => "EPUB ebook",
            OneNote => "OneNote",
            Msg => "Outlook MSG",
            Pst => "Outlook PST",
            Png => "PNG image",
            Jpeg => "JPEG image",
            Gif87 => "GIF87a image",
            Gif89 => "GIF89a image",
            Bmp => "BMP image",
            TiffLe | TiffBe => "TIFF image",
            WebP => "WebP image",
            Ico => "Windows icon",
            Cur => "Windows cursor",
            Psd => "Photoshop PSD",
            Heic => "HEIC/HEIF image",
            Avif => "AVIF image",
            Mp3 => "MP3 audio",
            Wav => "WAV audio",
            Avi => "AVI video",
            Mp4 => "MP4/ISO-BMFF media",
            Mov => "QuickTime MOV",
            ThreeGpp => "3GPP media",
            Mkv => "Matroska/WebM",
            Flv => "Flash video",
            Ogg => "Ogg container",
            Flac => "FLAC audio",
            Zip => "ZIP archive",
            Jar => "Java archive",
            Apk => "Android package",
            Gzip => "gzip",
            Bzip2 => "bzip2",
            Xz => "xz",
            SevenZ => "7-Zip",
            Rar4 => "RAR4 archive",
            Rar5 => "RAR5 archive",
            Tar => "tar archive",
            Zstd => "zstd",
            Lz4 => "LZ4 frame",
            Cab => "MS Cabinet",
            Ar => "ar archive",
            Ewf => "EWF forensic image",
            Aff => "AFF forensic image",
            Dmg => "Apple DMG image",
            Luks1 => "LUKS1 encrypted volume",
            Luks2 => "LUKS2 encrypted volume",
            BitLocker => "BitLocker volume",
            BitLockerToGo => "BitLocker To Go volume",
            Vmdk => "VMDK descriptor",
            Vhd => "VHD image",
            Vdi => "VirtualBox VDI",
            Qcow => "qcow image",
            Iso9660 => "ISO9660 image",
            Udf => "UDF image",
            Fat => "FAT filesystem",
            ExFat => "exFAT filesystem",
            Ntfs => "NTFS filesystem",
            Ext => "ext filesystem",
            Btrfs => "btrfs filesystem",
            F2fs => "F2FS filesystem",
            Apfs => "APFS container",
            HfsPlus => "HFS+/HFSX volume",
            Xfs => "XFS filesystem",
            NtfsMftRecord => "NTFS MFT record",
            Sqlite => "SQLite3 database",
            SqliteWal => "SQLite WAL",
            SqliteJournal => "SQLite journal",
            RegHive => "registry hive",
            Evtx => "Windows event log",
            Prefetch => "Windows prefetch",
            Bplist => "binary plist",
            Ole2 => "OLE2/CFB container",
            Sdb => "shim database",
            Pem => "PEM key/cert",
            OpenSslSalted => "OpenSSL salted data",
            WhatsAppCrypt => "WhatsApp encrypted backup",
            Pkcs12 => "PKCS#12 keystore",
            Xml => "XML document",
            PlainText => "text data",
            Pcap => "pcap capture",
            PcapNg => "pcapng capture",
        }
    }

    /// Category used for severity scoring.
    pub fn category(self) -> Category {
        use MagicType::*;
        match self {
            Pe | Elf | MachO32 | MachO64 | MachOFat | Wasm | JavaClass | Dex | DyldCache => {
                Category::Executable
            }
            ShellScript | Lnk => Category::Script,
            Pdf | PostScript | Rtf | Docx | Xlsx | Pptx | Doc | Xls | Ppt | Odt | Ods | Odp
            | Epub | OneNote | Msg | Pst => Category::Document,
            Png | Jpeg | Gif87 | Gif89 | Bmp | TiffLe | TiffBe | WebP | Ico | Cur | Psd | Heic
            | Avif => Category::Image,
            Mp3 | Wav | Flac | Ogg => Category::Audio,
            Avi | Mp4 | Mov | ThreeGpp | Mkv | Flv => Category::Video,
            Zip | Jar | Apk | Gzip | Bzip2 | Xz | SevenZ | Rar4 | Rar5 | Tar | Zstd | Lz4 | Cab
            | Ar => Category::Archive,
            Ewf | Aff | Dmg | Luks1 | Luks2 | BitLocker | BitLockerToGo | Vmdk | Vhd | Vdi
            | Qcow | Iso9660 | Udf => Category::DiskImage,
            Fat | ExFat | Ntfs | Ext | Btrfs | F2fs | Apfs | HfsPlus | Xfs | NtfsMftRecord => {
                Category::FileSystem
            }
            Sqlite | SqliteWal | SqliteJournal => Category::Database,
            RegHive | Evtx | Prefetch | Bplist | Ole2 | Sdb | Pcap | PcapNg => Category::Artifact,
            Pem | OpenSslSalted | WhatsAppCrypt | Pkcs12 => Category::Crypto,
            Xml | PlainText => Category::Text,
        }
    }

    /// Is this type code-carrying (executable or script)? A file *declared*
    /// as a document/image but *detected* as one of these is `High` severity.
    pub fn is_code(self) -> bool {
        matches!(self.category(), Category::Executable | Category::Script)
    }

    /// Types `detect()` can legitimately report for content *declared* as
    /// `self`. Encodes the "expected container" rules: a docx IS a zip, a doc
    /// IS an OLE2/CFB container, a jar/apk/epub is a zip, etc.
    pub fn accepts(self, detected: MagicType) -> bool {
        use MagicType::*;
        if self == detected {
            return true;
        }
        match self {
            // ZIP-family formats: content magic is `PK\x03\x04`.
            Docx | Xlsx | Pptx | Jar | Apk | Odt | Ods | Odp | Epub => detected == Zip,
            // OLE2-family formats: content magic is D0 CF 11 E0.
            Doc | Xls | Ppt | Msg => detected == Ole2,
            // PST is its own signature; also accept Ole2 for forward-compat.
            Pst => detected == Ole2,
            // A GIF may declare gif but detect as either revision.
            Gif87 => detected == Gif89,
            Gif89 => detected == Gif87,
            // TIFF either endianness.
            TiffLe => detected == TiffBe,
            TiffBe => detected == TiffLe,
            // MP4-family brands overlap.
            Mov | ThreeGpp => detected == Mp4,
            Mp4 => matches!(detected, Mov | ThreeGpp),
            // Plain text/xml have no magic — a *detected* binary under a text
            // extension is never acceptable.
            PlainText | Xml => false,
            _ => false,
        }
    }
}
