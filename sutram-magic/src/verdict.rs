//! Detection engine and the extension↔content [`MagicVerdict`] logic.

use crate::table::{EXT_TO_TYPE, SIGNATURES, TRAILERS};
use crate::MagicType;

/// How alarming a [`MagicVerdict`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Consistent, unmapped, or simply "no known magic" — informational.
    Info,
    /// Extension and content disagree, but neither side is code —
    /// e.g. `.png` that is really a zip.
    Suspicious,
    /// Content is code-carrying (PE/ELF/Mach-O/script) under a non-executable
    /// extension — classic masquerade/evasion.
    High,
}

/// The verdict [`check_entry`] returns for one file.
#[derive(Debug, Clone)]
pub struct MagicVerdict {
    /// Type implied by the filename extension, if the extension is known.
    pub declared: Option<MagicType>,
    /// Type detected from content, if any signature matched.
    pub detected: Option<MagicType>,
    /// `declared` and `detected` disagree beyond container rules.
    pub mismatch: bool,
    /// Worst-severity assessment.
    pub severity: Severity,
    /// Human-readable explanations — suitable for a report/court exhibit.
    pub reasons: Vec<String>,
}

impl MagicVerdict {
    /// `true` when the verdict deserves an examiner's attention.
    pub fn suspicious(&self) -> bool {
        self.severity >= Severity::Suspicious
    }
}

/// Identify a buffer by its leading bytes (and trailer bytes when the buffer
/// spans the end of a small file). Returns `None` for unrecognised content —
/// that is itself meaningful, see [`check_entry`].
pub fn detect(buf: &[u8]) -> Option<MagicType> {
    if buf.is_empty() {
        return None;
    }
    if let Some(t) = detect_special(buf) {
        return Some(t);
    }
    // Longest magic wins so `PK\x03\x04`-vs-`PK`-family and similar stay sane.
    let mut best: Option<&crate::Signature> = None;
    for s in SIGNATURES {
        if let Some(field) = buf.get(s.offset..s.offset + s.magic.len()) {
            if field == s.magic
                && best.is_none_or(|b| s.magic.len() >= b.magic.len())
            {
                best = Some(s);
            }
        }
    }
    if let Some(s) = best {
        return Some(s.kind);
    }
    // Trailer-only types (DMG `koly`, VHD `conectix`) when the buffer happens
    // to include the tail of the file.
    trailer_detect(buf)
}

/// All types whose signatures match — >1 means a possible **polyglot** file
/// (e.g. a ZIP/PE concatenation, a GIFAR). [`detect`] reports the strongest
/// single answer; this exposes the ambiguity for forensic review.
pub fn detect_all(buf: &[u8]) -> Vec<MagicType> {
    let mut out = Vec::new();
    let special = detect_special(buf);
    if let Some(t) = special {
        out.push(t);
    }
    for s in SIGNATURES {
        // A table row that merely restates what the special check already
        // decided from the same leading bytes is *one* signature, not two:
        // the generic `PK` row vs an ODF/APK subtype answer, the generic
        // LUKS row vs the versioned LUKS1/LUKS2 answer.
        if special.is_some_and(|t| row_subsumed_by_special(t, s)) {
            continue;
        }
        if let Some(field) = buf.get(s.offset..s.offset + s.magic.len()) {
            if field == s.magic && !out.contains(&s.kind) {
                out.push(s.kind);
            }
        }
    }
    if let Some(t) = trailer_detect(buf) {
        // An EOCD trailer under an identified ZIP-subtype container is the
        // same archive, not an appended second one.
        let subsumed = t == MagicType::Zip && out.iter().any(|&x| is_zip_subtype(x));
        if !subsumed && !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

/// Types `zip_subtype` may return — archive containers whose `PK` header and
/// `EOCD` trailer belong to the *same* signature, not independent hits.
fn is_zip_subtype(t: MagicType) -> bool {
    matches!(
        t,
        MagicType::Apk
            | MagicType::Jar
            | MagicType::Odt
            | MagicType::Ods
            | MagicType::Odp
            | MagicType::Epub
    )
}

/// `true` when table row `s` only re-describes leading bytes that `special`
/// already interpreted (a ZIP container subtype or the LUKS version check).
fn row_subsumed_by_special(special: MagicType, s: &crate::Signature) -> bool {
    if s.offset != 0 {
        return false;
    }
    if is_zip_subtype(special) {
        return s.kind == MagicType::Zip;
    }
    matches!(special, MagicType::Luks1 | MagicType::Luks2) && s.kind == MagicType::Luks1
}

/// Check whether `buf`'s tail carries `kind`'s trailer signature
/// (`IEND`, `%%EOF`, `koly`, …). Searching a bounded suffix window keeps the
/// check cheap; a trailer in the *middle* is not a footer.
pub fn has_trailer(kind: MagicType, buf: &[u8]) -> bool {
    let tail = &buf[buf.len().saturating_sub(1024)..];
    TRAILERS
        .iter()
        .filter(|(k, _)| *k == kind)
        .any(|(_, t)| {
            if t.is_empty() || tail.len() < t.len() {
                return false;
            }
            // Exact footer…
            if tail[tail.len() - t.len()..] == **t {
                return true;
            }
            // …or footer followed by a little padding.
            tail.windows(t.len()).rev().take(8).any(|w| w == *t)
        })
}

/// Look for trailer-only types in the tail of `buf` — DMG `koly`, VHD
/// `conectix`, and ZIP `EOCD` (a file *ending* in an end-of-central-directory
/// record contains a zip, whatever its header says — this is what exposes
/// appended-archive polyglots and self-extracting stubs).
fn trailer_detect(buf: &[u8]) -> Option<MagicType> {
    let tail = &buf[buf.len().saturating_sub(1024)..];
    for (kind, t) in TRAILERS {
        if matches!(kind, MagicType::Dmg | MagicType::Vhd | MagicType::Zip)
            && tail.len() >= t.len()
            && &tail[tail.len() - t.len()..] == *t
        {
            return Some(*kind);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Signatures needing interpretation rather than a fixed byte string.
// ---------------------------------------------------------------------------

fn detect_special(buf: &[u8]) -> Option<MagicType> {
    // RIFF container: `RIFF` + size + form type.
    if buf.len() >= 12 && &buf[0..4] == b"RIFF" {
        return Some(match &buf[8..12] {
            b"WAVE" => MagicType::Wav,
            b"AVI " => MagicType::Avi,
            b"WEBP" => MagicType::WebP,
            _ => MagicType::Wav, // unknown RIFF form — still a RIFF media file
        });
    }
    // IFF/FORM container (big-endian cousin of RIFF): AIFF audio.
    if buf.len() >= 12 && &buf[0..4] == b"FORM" {
        return match &buf[8..12] {
            b"AIFF" | b"AIFC" => Some(MagicType::Aiff),
            _ => None,
        };
    }
    // ZIP local-file-header subtypes: the *first entry name* identifies the
    // container (ODF/EPUB `mimetype`, APK `AndroidManifest.xml`, jar
    // `META-INF/…`). Falls through to the `PK` table rows on no match.
    if let Some(t) = zip_subtype(buf) {
        return Some(t);
    }
    // ISO-BMFF `ftyp` box at offset 4.
    if buf.len() >= 12 && &buf[4..8] == b"ftyp" {
        let brand = &buf[8..12];
        return Some(match brand {
            b"qt  " => MagicType::Mov,
            b"heic" | b"heix" | b"hevc" | b"mif1" | b"msf1" | b"crx " => MagicType::Heic,
            b"avif" | b"avis" => MagicType::Avif,
            b if b.starts_with(b"3gp") || b.starts_with(b"3g2") => MagicType::ThreeGpp,
            _ => MagicType::Mp4,
        });
    }
    // CA FE BA BE collision: Java class vs Mach-O universal binary.
    // Class: minor u16@4, major u16@6 (44..=~80). Fat: nfat_arch u32@4 (1..=32).
    if buf.len() >= 8 && &buf[0..4] == b"\xCA\xFE\xBA\xBE" {
        let nfat = u32::from_be_bytes(buf[4..8].try_into().unwrap_or([0; 4]));
        let major = u16::from_be_bytes(buf[6..8].try_into().unwrap_or([0; 2]));
        if (1..=32).contains(&nfat) && !(44..=80).contains(&major) {
            return Some(MagicType::MachOFat);
        }
        return Some(MagicType::JavaClass);
    }
    // LUKS: magic + big-endian version u16 at 6.
    if buf.len() >= 8 && &buf[0..6] == b"LUKS\xBA\xBE" {
        let ver = u16::from_be_bytes(buf[6..8].try_into().unwrap_or([0; 2]));
        return Some(if ver == 2 {
            MagicType::Luks2
        } else {
            MagicType::Luks1
        });
    }
    // MPEG audio frame sync (headerless MP3): 11 sync bits + sane
    // version/layer bits. ID3-tagged files match the `ID3` row instead.
    if buf.len() >= 2 && buf[0] == 0xFF && (buf[1] & 0xE0) == 0xE0 {
        let version = (buf[1] >> 3) & 0x03;
        let layer = (buf[1] >> 1) & 0x03;
        if version != 1 && layer != 0 {
            return Some(MagicType::Mp3);
        }
        // ADTS AAC: sync + layer bits == 00 (`FF F0`–`FF F9` family), which
        // the MP3 rule above deliberately excludes.
        if (buf[1] & 0xF6) == 0xF0 {
            return Some(MagicType::Aac);
        }
    }
    None
}

/// Identify the ZIP container's payload type from the *first* local-file
/// header — the name (and, for ODF/EPUB, the stored `mimetype` content)
/// distinguishes ODF documents, EPUB, APK and jar from a generic archive.
/// Returns `None` when the first entry gives no answer (→ generic Zip).
fn zip_subtype(buf: &[u8]) -> Option<MagicType> {
    // Local file header: sig(4) ver(2) flags(2) method(2) mtime(2) mdate(2)
    // crc(4) csize(4) usize(4) namelen(2) extralen(2) name[n] extra[m] data…
    if buf.len() < 30 || &buf[0..4] != b"PK\x03\x04" {
        return None;
    }
    let method = u16::from_le_bytes(buf[8..10].try_into().ok()?);
    let name_len = u16::from_le_bytes(buf[26..28].try_into().ok()?) as usize;
    let extra_len = u16::from_le_bytes(buf[28..30].try_into().ok()?) as usize;
    let name = buf.get(30..30usize.checked_add(name_len)?)?;
    match name {
        b"AndroidManifest.xml" | b"classes.dex" | b"resources.arsc" => Some(MagicType::Apk),
        b"mimetype" if method == 0 => {
            // ODF/EPUB store the mime string uncompressed as the first entry.
            let data = buf.get(30 + name_len + extra_len..)?;
            let t = if data.starts_with(b"application/epub+zip") {
                MagicType::Epub
            } else if data.starts_with(b"application/vnd.oasis.opendocument.text")
                || data.starts_with(b"application/vnd.sun.xml.writer")
            {
                MagicType::Odt
            } else if data.starts_with(b"application/vnd.oasis.opendocument.spreadsheet")
                || data.starts_with(b"application/vnd.sun.xml.calc")
            {
                MagicType::Ods
            } else if data.starts_with(b"application/vnd.oasis.opendocument.presentation")
                || data.starts_with(b"application/vnd.sun.xml.impress")
            {
                MagicType::Odp
            } else {
                return None;
            };
            Some(t)
        }
        n if n.starts_with(b"META-INF/") => Some(MagicType::Jar),
        _ => None,
    }
}

/// Extract the lowercase extension (without dot) from a filename.
/// `None` for dotfiles (`.bashrc`) and extensionless names.
fn extension(name: &str) -> Option<&str> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let (stem, ext) = base.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() {
        return None;
    }
    Some(ext)
}

/// Compare a filename's declared type with its content's detected type.
///
/// `header` should be as many leading bytes as are cheaply available
/// (≥ 512 B is a good floor; the FAT parser passes 4 KiB). The verdict never
/// fails — a file with no signature gets `detected: None` and an `Info`
/// reason rather than a pass/fail answer.
///
/// Container rules (`MagicType::accepts`): `.docx` whose bytes are `PK` is
/// **not** a mismatch — OOXML is a ZIP container. `.doc` expecting OLE2
/// likewise. The inverse (a `.docx` that is really `MZ`) is `High`.
pub fn check_entry(name: &str, header: &[u8]) -> MagicVerdict {
    check_entry_inner(name, header, None)
}

/// Like [`check_entry`] but the caller states the file's *total* size, so
/// trailer verification (PNG `IEND`, PDF `%%EOF`, JPEG `FFD9`, …) only runs
/// when `header` actually contains the whole file. Passing a 4 KiB header
/// of a 1 MiB file produces no spurious "truncated" notes.
pub fn check_entry_sized(name: &str, header: &[u8], total_size: u64) -> MagicVerdict {
    check_entry_inner(name, header, Some(total_size))
}

fn check_entry_inner(
    name: &str,
    header: &[u8],
    total_size: Option<u64>,
) -> MagicVerdict {
    let ext = extension(name).map(|e| e.to_ascii_lowercase());
    let declared = ext
        .as_deref()
        .and_then(|e| EXT_TO_TYPE.iter().find(|(x, _)| *x == e).map(|(_, t)| *t));
    let detected = detect(header);
    let all = detect_all(header);
    let mut reasons = Vec::new();
    let mut mismatch = false;
    let mut severity = Severity::Info;

    let e = ext.as_deref().unwrap_or("?");
    match (declared, detected) {
        (Some(d), Some(x)) if d.accepts(x) => {
            reasons.push(format!(
                "extension '.{e}' expects {}; content magic {} — consistent{}",
                d.name(),
                x.name(),
                if x != d {
                    " (container format match)"
                } else {
                    ""
                }
            ));
        }
        (Some(d), Some(x)) => {
            mismatch = true;
            severity = if x.is_code() {
                Severity::High
            } else {
                Severity::Suspicious
            };
            reasons.push(format!(
                "extension '.{e}' implies {}; magic {} → {} — possible masquerade/evasion",
                d.name(),
                magic_label(header),
                x.name()
            ));
        }
        (Some(d), None) => {
            reasons.push(format!(
                "extension '.{e}' implies {}; no known magic in first {} bytes \
                 (text file, empty, truncated, or unknown format)",
                d.name(),
                header.len()
            ));
        }
        (None, Some(x)) => {
            reasons.push(format!(
                "no declared type for this name; content detected as {}",
                x.name()
            ));
        }
        (None, None) => {
            if let Some(e) = ext.as_deref() {
                reasons.push(format!(
                    "extension '.{e}' unmapped and no known magic signature — \
                     nothing to verify"
                ));
            } else {
                reasons.push(format!(
                    "no extension and no known magic in first {} bytes",
                    header.len()
                ));
            }
        }
    }

    // Polyglot note: more than one signature present.
    if all.len() > 1 {
        reasons.push(format!(
            "multiple signatures present ({}) — possible polyglot file",
            all.iter().map(|t| t.name()).collect::<Vec<_>>().join(", ")
        ));
        if severity < Severity::Suspicious {
            severity = Severity::Suspicious;
        }
    }

    // Missing-trailer note — only when the caller confirmed the buffer is
    // the *whole* file (`check_entry_sized` with total_size ≤ header len).
    // A header-only probe can never prove a footer is missing.
    let whole_file = total_size.is_some_and(|t| t <= header.len() as u64);
    if let (Some(x), true) = (detected, whole_file) {
        if TRAILERS.iter().any(|(k, _)| *k == x)
            && !has_trailer(x, header)
            && !matches!(x, MagicType::Zip)
        {
            reasons.push(format!(
                "no {} trailer found — file may be truncated or partially overwritten",
                x.name()
            ));
        }
    }

    MagicVerdict {
        declared,
        detected,
        mismatch,
        severity,
        reasons,
    }
}

/// Short printable form of the leading magic for reason strings.
fn magic_label(header: &[u8]) -> String {
    let n = header.len().min(4);
    header[..n]
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}
