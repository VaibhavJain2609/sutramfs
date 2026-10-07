//! Windows `.lnk` (Shell Link) parser — MS-SHLLINK.
//!
//! Forensic value: the header stores the **target file's** MAC FILETIMEs
//! and size at the moment the link was created/last resolved; `LinkInfo`
//! preserves the original volume serial + path; StringData keeps the
//! invocation arguments; and the `TrackerDataBlock` carries the creating
//! machine's **NetBIOS name** plus droid GUIDs that embed the MAC address
//! and a v1 UUID timestamp — attribution gold.
//!
//! Unknown `ExtraData` blocks (console, property-store, shim, …) are not
//! decoded but are enumerated with offset/size/signature so nothing is
//! silently dropped.

use crate::common::{
    ansi_str, filetime, guid_string, guid_v1_mac_time, read_to_end_bounded, slice_at, utf16_str,
    ArtifactTimestamp, Cursor, Error, Result, DEFAULT_MAX_INPUT,
};
use std::io::Read;

/// Size of the fixed ShellLinkHeader.
pub const HEADER_SIZE: usize = 0x4C;
/// The mandatory link CLSID, `{00021401-0000-0000-C000-000000000046}` in
/// on-disk (mixed-endian) byte order.
pub const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// `LinkFlags` bits (MS-SHLLINK 2.1.1).
pub mod flags {
    pub const HAS_LINK_TARGET_ID_LIST: u32 = 1 << 0;
    pub const HAS_LINK_INFO: u32 = 1 << 1;
    pub const HAS_NAME: u32 = 1 << 2;
    pub const HAS_RELATIVE_PATH: u32 = 1 << 3;
    pub const HAS_WORKING_DIR: u32 = 1 << 4;
    pub const HAS_ARGUMENTS: u32 = 1 << 5;
    pub const HAS_ICON_LOCATION: u32 = 1 << 6;
    pub const IS_UNICODE: u32 = 1 << 7;
    pub const EXPAND_ENV_VARS: u32 = 1 << 10;
    pub const RUN_AS_USER: u32 = 1 << 13;
    pub const HAS_EXP_ICON: u32 = 1 << 14;
    pub const ENABLE_TARGET_METADATA: u32 = 1 << 17;
    pub const FORCE_NO_LINK_TRACK: u32 = 1 << 19;
}

/// `ExtraData` block signatures.
pub mod block_sig {
    pub const ENVIRONMENT_VARIABLE: u32 = 0xA000_0001;
    pub const CONSOLE: u32 = 0xA000_0002;
    pub const TRACKER: u32 = 0xA000_0003;
    pub const CONSOLE_FE: u32 = 0xA000_0004;
    pub const SPECIAL_FOLDER: u32 = 0xA000_0005;
    pub const DARWIN: u32 = 0xA000_0006;
    pub const ICON_ENVIRONMENT: u32 = 0xA000_0007;
    pub const SHIM: u32 = 0xA000_0008;
    pub const PROPERTY_STORE: u32 = 0xA000_0009;
    pub const KNOWN_FOLDER: u32 = 0xA000_000B;
    pub const VISTA_ID_LIST: u32 = 0xA000_000C;

    /// Human-readable block name for reporting.
    pub fn name(sig: u32) -> &'static str {
        match sig {
            ENVIRONMENT_VARIABLE => "EnvironmentVariableDataBlock",
            CONSOLE => "ConsoleDataBlock",
            TRACKER => "TrackerDataBlock",
            CONSOLE_FE => "ConsoleFEDataBlock",
            SPECIAL_FOLDER => "SpecialFolderDataBlock",
            DARWIN => "DarwinDataBlock",
            ICON_ENVIRONMENT => "IconEnvironmentDataBlock",
            SHIM => "ShimDataBlock",
            PROPERTY_STORE => "PropertyStoreDataBlock",
            KNOWN_FOLDER => "KnownFolderDataBlock",
            VISTA_ID_LIST => "VistaAndAboveIDListDataBlock",
            _ => "Unknown",
        }
    }
}

/// Quick signature check: correct header size DWORD and link CLSID.
/// Reads only the fixed header — safe for triage.
pub fn detect(data: &[u8]) -> bool {
    data.len() >= HEADER_SIZE
        && u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == HEADER_SIZE as u32
        && data[4..20] == LINK_CLSID
}

/// The parsed `LinkInfo` volumeID substructure.
#[derive(Debug, Clone)]
pub struct VolumeId {
    /// Absolute offset of the volumeID record.
    pub offset: usize,
    /// DRIVE_* type (3 = fixed, 4 = remote, …).
    pub drive_type: u32,
    /// Volume serial number as hex string (`"a1b2-c3d4"` style is a
    /// display concern; this is the raw serial in `0x` hex).
    pub serial: u32,
    /// Volume label (ANSI, or Unicode when `label_unicode` was used).
    pub label: String,
    /// True when the label came from the Unicode offset field.
    pub label_is_unicode: bool,
}

/// The parsed `LINKINFO` structure.
#[derive(Debug, Clone)]
pub struct LinkInfo {
    /// Absolute offset of the LINKINFO structure.
    pub offset: usize,
    /// Declared structure size.
    pub size: u32,
    /// Raw LINKINFO flags (bit 0 = VolumeID present, bit 1 =
    /// CommonNetworkRelativeLink present).
    pub flags: u32,
    /// Volume information, when flagged present and decodable.
    pub volume_id: Option<VolumeId>,
    /// ANSI local base path (e.g. `C:\dir\file.exe`).
    pub local_base_path: Option<String>,
    /// UTF-16 local base path (LINKINFO header ≥ 0x24).
    pub local_base_path_unicode: Option<String>,
    /// Trailing path component common to all views of the target.
    pub common_path_suffix: Option<String>,
    /// UTF-16 common path suffix (LINKINFO header ≥ 0x24).
    pub common_path_suffix_unicode: Option<String>,
    /// CommonNetworkRelativeLink block offset, when present (decoded
    /// only to its offset/size — flags, device name are rarely used and
    /// left to `extra` consumers).
    pub common_network_rel_link_offset: Option<usize>,
}

/// A decoded LinkTargetIDList.
#[derive(Debug, Clone)]
pub struct LinkTargetIdList {
    /// Absolute offset of the `IDListSize` field.
    pub offset: usize,
    /// Declared byte size of the ID list (excluding the size field).
    pub size: u16,
    /// Number of ItemID structures (terminal 0x0000 not counted).
    pub item_count: usize,
}

/// The distributed link tracker properties — machine attribution.
#[derive(Debug, Clone)]
pub struct TrackerData {
    /// Absolute offset of the TrackerDataBlock.
    pub offset: usize,
    /// NetBIOS name of the machine where the target last resided.
    pub machine_id: String,
    /// Droid volume GUID (current location).
    pub droid_volume: String,
    /// Droid file GUID (current location) — a v1 UUID embedding the
    /// machine MAC and creation timestamp.
    pub droid_file: String,
    /// Birth droid volume GUID (creation location).
    pub birth_droid_volume: String,
    /// Birth droid file GUID (creation location).
    pub birth_droid_file: String,
    /// MAC address decoded from `droid_file` when it is a v1 UUID.
    pub mac: Option<String>,
    /// MAC address decoded from `birth_droid_file` when it is a v1 UUID.
    pub birth_mac: Option<String>,
    /// v1-UUID timestamp inside `droid_file` (when decodable).
    pub droid_file_time: Option<ArtifactTimestamp>,
    /// v1-UUID timestamp inside `birth_droid_file` (when decodable).
    pub birth_droid_file_time: Option<ArtifactTimestamp>,
}

/// One undecoded `ExtraData` block (console, property-store, shim, …).
#[derive(Debug, Clone)]
pub struct ExtraBlock {
    /// Absolute offset of the block's size field.
    pub offset: usize,
    /// Declared block size (includes the 8-byte size+signature header).
    pub size: u32,
    /// Block signature (`block_sig::*`).
    pub signature: u32,
    /// Human-readable signature name.
    pub name: &'static str,
}

/// A fully parsed `.lnk` file.
#[derive(Debug, Clone)]
pub struct LnkFile {
    /// Raw `LinkFlags` dword.
    pub link_flags: u32,
    /// Raw `FileAttributes` dword (FILE_ATTRIBUTE_* of the target).
    pub file_attributes: u32,
    /// Target creation time (header `CreationTime`).
    pub target_ctime: ArtifactTimestamp,
    /// Target access time (header `AccessTime`).
    pub target_atime: ArtifactTimestamp,
    /// Target write time (header `WriteTime`).
    pub target_mtime: ArtifactTimestamp,
    /// Target file size in bytes (low 32 bits per spec).
    pub target_size: u32,
    /// `IconIndex`.
    pub icon_index: i32,
    /// `ShowCommand` (1 = normal, 3 = maximised, 7 = minimised).
    pub show_command: u32,
    /// `HotKey` virtual-key code + modifiers.
    pub hotkey: u16,
    /// Link CLSID as a GUID string (always the standard link CLSID for a
    /// successfully parsed file).
    pub clsid: String,
    /// True when StringData is UTF-16LE (`IsUnicode`); false = ANSI.
    pub unicode_strings: bool,
    /// LinkTargetIDList summary, when `HasLinkTargetIDList`.
    pub id_list: Option<LinkTargetIdList>,
    /// LINKINFO, when `HasLinkInfo`.
    pub link_info: Option<LinkInfo>,
    /// StringData `NAME_STRING` (the link's own description).
    pub name: Option<String>,
    /// StringData `RELATIVE_PATH`.
    pub relative_path: Option<String>,
    /// StringData `WORKING_DIR`.
    pub working_dir: Option<String>,
    /// StringData `COMMAND_LINE_ARGUMENTS`.
    pub arguments: Option<String>,
    /// StringData `ICON_LOCATION`.
    pub icon_location: Option<String>,
    /// TrackerDataBlock, when present and decodable.
    pub tracker: Option<TrackerData>,
    /// Every ExtraData block seen (including the decoded tracker block),
    /// in file order. The final TerminalBlock is not listed.
    pub extra_blocks: Vec<ExtraBlock>,
    /// Non-fatal problems encountered while parsing optional sections.
    /// A parse that produced an `LnkFile` may still carry warnings here.
    pub warnings: Vec<String>,
    /// Absolute offset just past the last consumed byte (end of the
    /// TerminalBlock, or end of meaningful data).
    pub end_offset: usize,
}

impl LnkFile {
    /// Parse a `.lnk` file from a byte slice.
    ///
    /// The fixed header is strict (a bad header means this is not a
    /// link); all trailing sections are lenient — a corrupt optional
    /// block is skipped and recorded in [`LnkFile::warnings`].
    pub fn parse(data: &[u8]) -> Result<LnkFile> {
        if data.len() < HEADER_SIZE {
            return Err(Error::Truncated {
                offset: 0,
                needed: HEADER_SIZE as u64,
                available: data.len() as u64,
            });
        }
        let mut c = Cursor::new(data);
        let header_size = c.u32()?;
        if header_size != HEADER_SIZE as u32 {
            return Err(Error::Corrupt {
                offset: 0,
                msg: format!("bad header size {header_size:#x}"),
            });
        }
        let clsid_raw = c.bytes(16)?;
        if clsid_raw != LINK_CLSID {
            return Err(Error::Corrupt {
                offset: 4,
                msg: format!("bad link CLSID {}", guid_string(clsid_raw)),
            });
        }
        let link_flags = c.u32()?;
        let file_attributes = c.u32()?;
        let ctime = filetime(c.u64()?);
        let atime = filetime(c.u64()?);
        let mtime = filetime(c.u64()?);
        let target_size = c.u32()?;
        let icon_index = c.i32()?;
        let show_command = c.u32()?;
        let hotkey = c.u16()?;
        c.skip(10)?; // reserved

        let mut f = LnkFile {
            link_flags,
            file_attributes,
            target_ctime: ctime,
            target_atime: atime,
            target_mtime: mtime,
            target_size,
            icon_index,
            show_command,
            hotkey,
            clsid: guid_string(&LINK_CLSID),
            unicode_strings: link_flags & flags::IS_UNICODE != 0,
            id_list: None,
            link_info: None,
            name: None,
            relative_path: None,
            working_dir: None,
            arguments: None,
            icon_location: None,
            tracker: None,
            extra_blocks: Vec::new(),
            warnings: Vec::new(),
            end_offset: HEADER_SIZE,
        };

        let mut pos = HEADER_SIZE;

        // LinkTargetIDList.
        if link_flags & flags::HAS_LINK_TARGET_ID_LIST != 0 {
            match parse_id_list(data, pos) {
                Ok((idl, next)) => {
                    f.id_list = Some(idl);
                    pos = next;
                }
                Err(e) => {
                    f.warnings.push(format!("id list at {pos:#x}: {e}"));
                    // Cannot know its length; nothing after it is
                    // locatable — stop here.
                    f.end_offset = pos;
                    return Ok(f);
                }
            }
        }

        // LINKINFO.
        if link_flags & flags::HAS_LINK_INFO != 0 {
            match parse_link_info(data, pos) {
                Ok((li, next)) => {
                    pos = next;
                    f.link_info = Some(li);
                }
                Err(e) => {
                    f.warnings.push(format!("link info at {pos:#x}: {e}"));
                    f.end_offset = pos;
                    return Ok(f);
                }
            }
        }

        // StringData — five counted strings in flag order.
        let string_flags = [
            (flags::HAS_NAME, "name"),
            (flags::HAS_RELATIVE_PATH, "relative_path"),
            (flags::HAS_WORKING_DIR, "working_dir"),
            (flags::HAS_ARGUMENTS, "arguments"),
            (flags::HAS_ICON_LOCATION, "icon_location"),
        ];
        for (flag, which) in string_flags {
            if link_flags & flag == 0 {
                continue;
            }
            match parse_counted_string(data, pos, f.unicode_strings) {
                Ok((s, next)) => {
                    pos = next;
                    match which {
                        "name" => f.name = Some(s),
                        "relative_path" => f.relative_path = Some(s),
                        "working_dir" => f.working_dir = Some(s),
                        "arguments" => f.arguments = Some(s),
                        _ => f.icon_location = Some(s),
                    }
                }
                Err(e) => {
                    f.warnings.push(format!("{which} string at {pos:#x}: {e}"));
                    f.end_offset = pos;
                    return Ok(f);
                }
            }
        }

        // ExtraData blocks.
        parse_extra_data(data, pos, &mut f);
        Ok(f)
    }

    /// Parse from any `Read`, bounded at `DEFAULT_MAX_INPUT` bytes.
    pub fn from_reader(r: impl Read) -> Result<LnkFile> {
        Self::parse(&read_to_end_bounded(r, DEFAULT_MAX_INPUT)?)
    }

    /// True when the link requests `RunAsUser`.
    pub fn run_as_user(&self) -> bool {
        self.link_flags & flags::RUN_AS_USER != 0
    }
}

/// Parse `IDListSize` + IDList at `pos`; returns the summary and the
/// offset just past the list.
fn parse_id_list(data: &[u8], pos: usize) -> Result<(LinkTargetIdList, usize)> {
    let mut c = Cursor::at(data, pos);
    let size = c.u16()? as usize;
    let body = c.bytes(size)?;
    // Count ItemIDs: each is a u16 size ≥ 2 + payload; list ends with 0.
    let mut item_count = 0usize;
    let mut p = 0usize;
    while p + 2 <= body.len() {
        let sz = u16::from_le_bytes([body[p], body[p + 1]]) as usize;
        if sz == 0 {
            break;
        }
        if sz < 2 || p + sz > body.len() {
            break; // malformed interior — count what we have
        }
        item_count += 1;
        p += sz;
    }
    Ok((
        LinkTargetIdList {
            offset: pos,
            size: size as u16,
            item_count,
        },
        pos + 2 + size,
    ))
}

/// Read a NUL-terminated string at `linkinfo_off + rel`, bounded by the
/// LINKINFO extent.
fn linkinfo_str(data: &[u8], base: usize, end: usize, rel: u32, unicode: bool) -> Option<String> {
    let off = base.checked_add(rel as usize)?;
    if rel == 0 || off >= end || off >= data.len() {
        return None;
    }
    let limit = end.min(data.len());
    let raw = &data[off..limit];
    Some(if unicode { utf16_str(raw) } else { ansi_str(raw) })
}

/// Parse LINKINFO at `pos`; returns the structure and offset just past it.
fn parse_link_info(data: &[u8], pos: usize) -> Result<(LinkInfo, usize)> {
    let mut c = Cursor::at(data, pos);
    let size = c.u32()? as usize;
    if size < 0x1C {
        return Err(Error::Corrupt {
            offset: pos as u64,
            msg: format!("link info size {size:#x} < 0x1c"),
        });
    }
    let end = pos
        .checked_add(size)
        .filter(|e| *e <= data.len())
        .ok_or(Error::Truncated {
            offset: pos as u64,
            needed: size as u64,
            available: data.len().saturating_sub(pos) as u64,
        })?;
    let header_size = c.u32()?;
    let li_flags = c.u32()?;
    let volume_id_off = c.u32()?;
    let local_base_off = c.u32()?;
    let common_net_rel_off = c.u32()?;
    let common_suffix_off = c.u32()?;
    let (local_base_u_off, common_suffix_u_off) = if header_size >= 0x24 {
        (c.u32()?, c.u32()?)
    } else {
        (0, 0)
    };

    // VolumeID.
    let mut volume_id = None;
    if li_flags & 1 != 0 && volume_id_off >= 0x1C {
        if let Some(voff) = pos.checked_add(volume_id_off as usize) {
            if let Ok(vraw) = slice_at(data, voff, 0x10.min(end.saturating_sub(voff))) {
                let mut vc = Cursor::new(vraw);
                if let (Ok(vsize), Ok(drive_type), Ok(serial), Ok(label_off)) =
                    (vc.u32(), vc.u32(), vc.u32(), vc.u32())
                {
                    if vsize >= 0x10 {
                        let (label, uni) = if label_off == 0x14 && vsize >= 0x14 {
                            // Unicode label at offset stored at +0x10.
                            let luo = slice_at(data, voff + 0x10, 4)
                                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                                .unwrap_or(0);
                            (
                                linkinfo_str(data, voff, end, luo, true).unwrap_or_default(),
                                true,
                            )
                        } else {
                            (
                                linkinfo_str(data, voff, end, label_off, false)
                                    .unwrap_or_default(),
                                false,
                            )
                        };
                        volume_id = Some(VolumeId {
                            offset: voff,
                            drive_type,
                            serial,
                            label,
                            label_is_unicode: uni,
                        });
                    }
                }
            }
        }
    }

    let common_net_rel = if li_flags & 2 != 0 && common_net_rel_off >= 0x14 {
        pos.checked_add(common_net_rel_off as usize)
            .filter(|o| *o < end)
    } else {
        None
    };

    Ok((
        LinkInfo {
            offset: pos,
            size: size as u32,
            flags: li_flags,
            volume_id,
            local_base_path: linkinfo_str(data, pos, end, local_base_off, false),
            local_base_path_unicode: linkinfo_str(data, pos, end, local_base_u_off, true),
            common_path_suffix: linkinfo_str(data, pos, end, common_suffix_off, false),
            common_path_suffix_unicode: linkinfo_str(data, pos, end, common_suffix_u_off, true),
            common_network_rel_link_offset: common_net_rel,
        },
        end,
    ))
}

/// Parse one counted StringData string at `pos`.
fn parse_counted_string(data: &[u8], pos: usize, unicode: bool) -> Result<(String, usize)> {
    let mut c = Cursor::at(data, pos);
    let chars = c.u16()? as usize;
    let bytes_needed = if unicode { chars.saturating_mul(2) } else { chars };
    let raw = c.bytes(bytes_needed)?;
    let s = if unicode { utf16_str(raw) } else { ansi_str(raw) };
    Ok((s, pos + 2 + bytes_needed))
}

/// Walk ExtraData blocks; fills `f.extra_blocks`, `f.tracker`,
/// `f.end_offset`. Never fails — unparseable tails become warnings.
fn parse_extra_data(data: &[u8], mut pos: usize, f: &mut LnkFile) {
    // A corrupt size field could loop backwards; bound iterations too.
    for _ in 0..64 {
        let hdr = match slice_at(data, pos, 4) {
            Ok(h) => h,
            Err(_) => break,
        };
        let size = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
        if size == 0 {
            // TerminalBlock.
            f.end_offset = pos + 4;
            return;
        }
        if size < 8 {
            f.warnings
                .push(format!("extra data block at {pos:#x}: size {size:#x} < 8"));
            break;
        }
        let sig = match slice_at(data, pos + 4, 4) {
            Ok(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            Err(_) => {
                f.warnings
                    .push(format!("extra data block at {pos:#x}: truncated signature"));
                break;
            }
        };
        let block_end = match pos.checked_add(size).filter(|e| *e <= data.len()) {
            Some(e) => e,
            None => {
                f.warnings
                    .push(format!("extra data block at {pos:#x}: size overruns file"));
                break;
            }
        };
        if sig == block_sig::TRACKER && f.tracker.is_none() {
            match parse_tracker(&data[pos..block_end], pos) {
                Ok(t) => f.tracker = Some(t),
                Err(e) => f.warnings.push(format!("tracker block at {pos:#x}: {e}")),
            }
        }
        f.extra_blocks.push(ExtraBlock {
            offset: pos,
            size: size as u32,
            signature: sig,
            name: block_sig::name(sig),
        });
        pos = block_end;
        f.end_offset = pos;
    }
}

/// Decode a TrackerDataBlock body (block including its 8-byte header).
fn parse_tracker(block: &[u8], off: usize) -> Result<TrackerData> {
    if block.len() < 0x60 {
        return Err(Error::Corrupt {
            offset: off as u64,
            msg: format!("tracker block {} bytes < 0x60", block.len()),
        });
    }
    let machine_id = ansi_str(&block[16..32]);
    let droid_volume = guid_string(&block[32..48]);
    let droid_file = guid_string(&block[48..64]);
    let birth_droid_volume = guid_string(&block[64..80]);
    let birth_droid_file = guid_string(&block[80..96]);
    let (mac, droid_file_time) = match guid_v1_mac_time(&block[48..64]) {
        Some((m, t)) => (Some(m), Some(filetime(t))),
        None => (None, None),
    };
    let (birth_mac, birth_droid_file_time) = match guid_v1_mac_time(&block[80..96]) {
        Some((m, t)) => (Some(m), Some(filetime(t))),
        None => (None, None),
    };
    Ok(TrackerData {
        offset: off,
        machine_id,
        droid_volume,
        droid_file,
        birth_droid_volume,
        birth_droid_file,
        mac,
        birth_mac,
        droid_file_time,
        birth_droid_file_time,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn w16(b: &mut Vec<u8>, v: u16) {
        b.extend_from_slice(&v.to_le_bytes());
    }
    fn w32(b: &mut Vec<u8>, v: u32) {
        b.extend_from_slice(&v.to_le_bytes());
    }
    fn w64(b: &mut Vec<u8>, v: u64) {
        b.extend_from_slice(&v.to_le_bytes());
    }

    /// Build a minimal but complete LNK: header + idlist + linkinfo +
    /// all five unicode strings + tracker + unknown extra block.
    fn sample_lnk() -> Vec<u8> {
        let mut b = Vec::new();
        // Header.
        w32(&mut b, 0x4C);
        b.extend_from_slice(&LINK_CLSID);
        w32(
            &mut b,
            flags::HAS_LINK_TARGET_ID_LIST
                | flags::HAS_LINK_INFO
                | flags::HAS_NAME
                | flags::HAS_RELATIVE_PATH
                | flags::HAS_WORKING_DIR
                | flags::HAS_ARGUMENTS
                | flags::HAS_ICON_LOCATION
                | flags::IS_UNICODE,
        );
        w32(&mut b, 0x20); // file attributes: archive
        w64(&mut b, 132_000_000_000_000_000); // ctime
        w64(&mut b, 132_000_001_000_000_000); // atime
        w64(&mut b, 132_000_002_000_000_000); // mtime
        w32(&mut b, 12_345); // target size
        w32(&mut b, 7); // icon index
        w32(&mut b, 1); // show normal
        w16(&mut b, 0x163); // hotkey ctrl+alt+f1-ish
        b.extend_from_slice(&[0; 10]); // reserved
        assert_eq!(b.len(), HEADER_SIZE);

        // IDList: one item (size 4) + terminal.
        let idl = [4u8, 0, 0xAA, 0xBB, 0, 0];
        w16(&mut b, idl.len() as u16);
        b.extend_from_slice(&idl);

        // LINKINFO with volumeID + local base path (ANSI, header 0x1C).
        let li_start = b.len();
        let mut li = Vec::new();
        w32(&mut li, 0); // size (patch)
        w32(&mut li, 0x1C); // header size
        w32(&mut li, 1); // flags: volumeID
        w32(&mut li, 0x1C); // volumeID offset
        let base_path = b"C:\\tools\\evil.exe\0";
        let vol = 0x1C;
        let base_off = vol + 0x10; // volumeID is 16 bytes
        let suffix_off = base_off + base_path.len();
        w32(&mut li, base_off as u32); // local base path off
        w32(&mut li, 0); // no net rel link
        w32(&mut li, suffix_off as u32); // common suffix off
        assert_eq!(li.len(), 0x1C);
        // volumeID
        w32(&mut li, 0x10); // volumeID size
        w32(&mut li, 3); // DRIVE_FIXED
        w32(&mut li, 0xDEADBEEF); // serial
        w32(&mut li, 0x10); // label off == size → empty label
        assert_eq!(li.len(), base_off);
        li.extend_from_slice(base_path);
        assert_eq!(li.len(), suffix_off);
        li.extend_from_slice(b"evil.exe\0");
        let li_len = li.len() as u32;
        li[0..4].copy_from_slice(&li_len.to_le_bytes());
        b.extend_from_slice(&li);

        // StringData (unicode): five counted strings.
        for s in ["desc", "..\\evil.exe", "C:\\tools", "-x --y", "%windir%\\i.ico"] {
            w16(&mut b, s.chars().count() as u16);
            for u in s.encode_utf16() {
                w16(&mut b, u);
            }
        }

        // TrackerDataBlock.
        w32(&mut b, 0x60);
        w32(&mut b, block_sig::TRACKER);
        w32(&mut b, 0x58); // length
        w32(&mut b, 0); // version
        let mut m = *b"EVILBOX-1\0\0\0\0\0\0\0";
        m[15] = 0;
        b.extend_from_slice(&m);
        // droid volume guid (not v1)
        b.extend_from_slice(&[0x11; 16]);
        // droid file guid: v1, node = 00:0c:29:aa:bb:cc
        let mut g = [0u8; 16];
        g[0..4].copy_from_slice(&0x12345678u32.to_le_bytes());
        g[4..6].copy_from_slice(&0x9abcu16.to_le_bytes());
        g[6..8].copy_from_slice(&0x1defu16.to_le_bytes()); // version 1
        g[8] = 0x80;
        g[9] = 0x00;
        g[10..16].copy_from_slice(&[0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc]);
        b.extend_from_slice(&g);
        b.extend_from_slice(&[0x22; 16]); // birth volume
        b.extend_from_slice(&g); // birth file (same v1)

        // An unknown extra block, then terminal.
        w32(&mut b, 12);
        w32(&mut b, 0xA000_00FF);
        w32(&mut b, 0x41414141);
        w32(&mut b, 0); // terminal
        let _ = li_start;
        b
    }

    #[test]
    fn parses_full_lnk() {
        let f = LnkFile::parse(&sample_lnk()).expect("parse");
        assert!(detect(&sample_lnk()));
        assert_eq!(f.target_size, 12_345);
        assert_eq!(f.show_command, 1);
        assert_eq!(f.icon_index, 7);
        assert_eq!(f.hotkey, 0x163);
        assert!(f.unicode_strings);
        assert_eq!(f.target_mtime.raw_encoding, "ntfs-filetime");
        assert_eq!(f.target_mtime.granularity, Duration::from_nanos(100));
        assert!(f.target_mtime.value.is_some());
        // idlist
        let idl = f.id_list.expect("idlist");
        assert_eq!(idl.item_count, 1);
        assert_eq!(idl.offset, HEADER_SIZE);
        // linkinfo
        let li = f.link_info.expect("linkinfo");
        let vol = li.volume_id.expect("volume id");
        assert_eq!(vol.drive_type, 3);
        assert_eq!(vol.serial, 0xDEADBEEF);
        assert_eq!(li.local_base_path.as_deref(), Some("C:\\tools\\evil.exe"));
        assert_eq!(li.common_path_suffix.as_deref(), Some("evil.exe"));
        // strings
        assert_eq!(f.name.as_deref(), Some("desc"));
        assert_eq!(f.relative_path.as_deref(), Some("..\\evil.exe"));
        assert_eq!(f.working_dir.as_deref(), Some("C:\\tools"));
        assert_eq!(f.arguments.as_deref(), Some("-x --y"));
        assert_eq!(f.icon_location.as_deref(), Some("%windir%\\i.ico"));
        // tracker
        let t = f.tracker.expect("tracker");
        assert_eq!(t.machine_id, "EVILBOX-1");
        assert_eq!(t.mac.as_deref(), Some("00:0c:29:aa:bb:cc"));
        assert!(t.droid_file_time.is_some());
        // extra blocks: tracker + unknown
        assert_eq!(f.extra_blocks.len(), 2);
        assert_eq!(f.extra_blocks[0].name, "TrackerDataBlock");
        assert_eq!(f.extra_blocks[1].name, "Unknown");
        assert!(f.warnings.is_empty());
        assert_eq!(f.end_offset, sample_lnk().len());
    }

    #[test]
    fn ansi_strings_when_not_unicode() {
        let mut b = Vec::new();
        w32(&mut b, 0x4C);
        b.extend_from_slice(&LINK_CLSID);
        w32(&mut b, flags::HAS_ARGUMENTS); // ANSI, no idlist/linkinfo
        b.extend_from_slice(&[0; 0x4C - 24]); // rest of header zeroed
        w16(&mut b, 3);
        b.extend_from_slice(b"/v\0"[..3].as_ref());
        w32(&mut b, 0);
        let f = LnkFile::parse(&b).expect("parse");
        assert!(!f.unicode_strings);
        assert_eq!(f.arguments.as_deref(), Some("/v")); // NUL-terminated
    }

    #[test]
    fn rejects_bad_signature() {
        assert!(matches!(
            LnkFile::parse(b"tiny"),
            Err(Error::Truncated { .. })
        ));
        let mut b = vec![0u8; 0x60];
        assert!(matches!(
            LnkFile::parse(&b),
            Err(Error::Corrupt { .. })
        ));
        b[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
        assert!(!detect(&b));
        assert!(matches!(LnkFile::parse(&b), Err(Error::Corrupt { .. })));
    }

    #[test]
    fn truncated_mid_strings_no_panic() {
        let full = sample_lnk();
        for cut in [
            HEADER_SIZE,
            HEADER_SIZE + 1,
            HEADER_SIZE + 4,
            full.len() - 20,
            full.len() - 1,
        ] {
            let r = LnkFile::parse(&full[..cut]);
            // Must never panic; partial results or an error both fine.
            if let Ok(f) = r {
                assert!(f.end_offset <= cut);
            }
        }
    }

    #[test]
    fn corrupt_extra_block_warns_not_fails() {
        let mut b = sample_lnk();
        // Corrupt the unknown block's size to overrun.
        let pos = b.len() - 16; // start of unknown block
        b[pos..pos + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let f = LnkFile::parse(&b).expect("parse");
        assert!(!f.warnings.is_empty());
        assert!(f.tracker.is_some()); // earlier block still decoded
    }

    #[test]
    fn fuzz_no_panic() {
        let base = sample_lnk();
        // Single-byte corruptions across the file.
        for i in 0..base.len() {
            for v in [0x00, 0xFF, 0x41] {
                let mut m = base.clone();
                m[i] ^= v;
                let _ = LnkFile::parse(&m);
            }
        }
        // Random truncations.
        for cut in 0..base.len() {
            let _ = LnkFile::parse(&base[..cut]);
        }
    }
}
