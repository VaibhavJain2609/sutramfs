//! The partition-layer orchestrator: [`analyze`] classifies a seized Android
//! image and exposes every mountable partition as a [`NamedSource`].
//!
//! Detection order (outermost layer wins `AndroidLayout::container`):
//!
//! 1. **Android sparse** (`0xED26FF3A`) — decoded via `sutram-io`'s
//!    `SparseFile`, then the decoded image is analysed again (a sparse
//!    `super.img` is the common factory-image shape).
//! 2. **Dynamic partitions** — `liblp` geometry magic at `0x1000`/`0x2000`
//!    → [`lp::logical_partitions_verbose`].
//! 3. **GPT** (or MBR) via `sutram-io`'s partition parser → `OffsetView`
//!    per partition + Android name heuristics.
//! 4. **Raw** — bare filesystem/vbmeta blob; exposed as a single
//!    `image` partition so callers can mount it directly.
//!
//! vbmeta is looked for in `vbmeta*` GPT partitions, then via the `AVBf`
//! footer at the tail of `boot*` partitions, then at offset 0 of a Raw
//! image. `crypt_ftr` / `metadata` encryption signals are flagged in
//! [`AndroidLayout::crypto`] — flagged, never decrypted.

use std::collections::BTreeMap;
use std::sync::Arc;

use sutram_fs::FsError;
use sutram_io::{ByteSource, OffsetView, TableKind};

use crate::fbe::{find_crypt_footer, CryptFooter, CryptoKind};
use crate::lp;
use crate::names::{classify_name, has_slot_suffix, PartitionRole};
use crate::sparse;
use crate::vbmeta::{self, VbmetaInfo};
use crate::Result;

/// Guard against adversarial sparse-in-sparse nesting.
const MAX_CONTAINER_DEPTH: u32 = 4;

/// Partition attribute bitmask — values match `LP_PARTITION_ATTR_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Attrs(pub u32);

impl Attrs {
    /// No attributes.
    pub const NONE: Attrs = Attrs(0);
    /// `LP_PARTITION_ATTR_READONLY` / GPT read-only bit.
    pub const READONLY: u32 = 1 << 0;
    /// `LP_PARTITION_ATTR_SLOT_SUFFIXED` (LP: suffix applied from slot) or a
    /// GPT name carrying `_a`/`_b`.
    pub const SLOT_SUFFIXED: u32 = 1 << 1;
    /// `LP_PARTITION_ATTR_UPDATED` — created/updated by a snapshot OTA.
    pub const UPDATED: u32 = 1 << 2;
    /// `LP_PARTITION_ATTR_DISABLED` — must not be mapped.
    pub const DISABLED: u32 = 1 << 3;

    /// `LP_PARTITION_ATTR_READONLY` set.
    pub fn readonly(self) -> bool {
        self.0 & Self::READONLY != 0
    }
    /// Slot-suffix flag set (LP) or name carried `_a`/`_b` (GPT).
    pub fn slot_suffixed(self) -> bool {
        self.0 & Self::SLOT_SUFFIXED != 0
    }
    /// `LP_PARTITION_ATTR_UPDATED` set.
    pub fn updated(self) -> bool {
        self.0 & Self::UPDATED != 0
    }
    /// `LP_PARTITION_ATTR_DISABLED` set.
    pub fn disabled(self) -> bool {
        self.0 & Self::DISABLED != 0
    }
}

/// One mountable partition: name + provenance metadata + a `ByteSource`
/// view (`OffsetView` for GPT/MBR, `SparseFile` for logical partitions).
pub struct NamedSource {
    /// Partition name — LP name (slot suffix applied when flagged), GPT
    /// label, or `partN`/`image` fallbacks. Sanitised for path safety.
    pub name: String,
    /// LP update group (e.g. `google_dynamic_partitions_a`); empty for
    /// GPT/MBR/Raw.
    pub group: String,
    /// Attribute bits (readonly / slot-suffixed / updated / disabled).
    pub attrs: Attrs,
    /// Read-only view of exactly this partition's bytes.
    pub source: Arc<dyn ByteSource>,
    /// Android role heuristic from [`classify_name`].
    pub role: PartitionRole,
    /// Extra provenance: table GUIDs, byte offsets, extent counts, …
    pub meta: BTreeMap<String, String>,
}

/// Which container format wrapped the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerKind {
    /// Android sparse image (`img2simg`). The partition list was computed
    /// on the *decoded* image; `warnings` note the decoded inner layout.
    Sparse,
    /// `liblp` dynamic-partition super image.
    Super,
    /// No container/partition layer — a bare filesystem or vbmeta blob.
    Raw,
    /// GPT-partitioned device image (physical partitions).
    Gpt,
}

impl ContainerKind {
    /// Short label.
    pub fn as_str(self) -> &'static str {
        match self {
            ContainerKind::Sparse => "sparse",
            ContainerKind::Super => "super",
            ContainerKind::Raw => "raw",
            ContainerKind::Gpt => "gpt",
        }
    }
}

/// A flagged encryption artefact — never decrypted, only reported.
#[derive(Debug)]
pub struct CryptoFinding {
    /// What kind of artefact was seen.
    pub kind: CryptoKind,
    /// Partition the artefact belongs to ("" = whole image).
    pub partition: String,
    /// Human-readable note (also pushed into `warnings`).
    pub note: String,
    /// Parsed `crypt_ftr`, when the finding is a footer.
    pub footer: Option<CryptFooter>,
}

/// Result of [`analyze`] — the partition-layer contract for downstream
/// filesystem parsers.
pub struct AndroidLayout {
    /// Outermost container format encountered.
    pub container: ContainerKind,
    /// Mountable partition views in table order.
    pub partitions: Vec<NamedSource>,
    /// vbmeta info when an AVB blob was found (partition or Raw blob).
    pub vbmeta: Option<VbmetaInfo>,
    /// Non-fatal findings — checksum mismatches, decode notes, quirks.
    pub warnings: Vec<String>,
    /// Encryption artefacts flagged (FDE/FBE footers, metadata partition).
    pub crypto: Vec<CryptoFinding>,
}

/// Analyse an Android image: classify the container and return every
/// mountable partition plus vbmeta/crypto findings.
///
/// Lenient: a recognisable-but-corrupt layer degrades to warnings rather
/// than aborting the whole layout; truly unparseable inputs return `Err`.
pub fn analyze(src: Arc<dyn ByteSource>) -> Result<AndroidLayout> {
    analyze_layer(src, 0)
}

fn analyze_layer(src: Arc<dyn ByteSource>, depth: u32) -> Result<AndroidLayout> {
    if depth > MAX_CONTAINER_DEPTH {
        return Err(FsError::unsupported(
            "container nesting deeper than 4 levels",
        ));
    }

    // --- 1. Android sparse -------------------------------------------------
    if sparse::is_android_sparse(src.as_ref()) {
        let (decoded, header, mut warnings) = sparse::inspect_sparse(src.clone())?;
        warnings.push(format!(
            "android sparse image: {} chunks, {} B blocks, {:#x} B decoded",
            header.total_chunks,
            header.block_size,
            decoded.len()
        ));
        let mut inner = analyze_layer(sutram_io::into_arc(decoded), depth + 1)?;
        warnings.append(&mut inner.warnings);
        inner.warnings = warnings;
        inner.container = ContainerKind::Sparse;
        return Ok(inner);
    }

    // --- 2. liblp super image ----------------------------------------------
    if has_lp_geometry(src.as_ref()) {
        match lp::logical_partitions_verbose(src.clone()) {
            Ok((parts, mut warnings)) => {
                let mut crypto = Vec::new();
                flag_metadata_partition(&parts, &mut crypto, &mut warnings);
                return Ok(AndroidLayout {
                    container: ContainerKind::Super,
                    partitions: parts,
                    vbmeta: None,
                    warnings,
                    crypto,
                });
            }
            Err(e) => {
                // Geometry looked like LP but no slot decoded — still a super
                // image, just damaged. Report honestly rather than falling
                // through to Raw and losing the classification.
                return Ok(AndroidLayout {
                    container: ContainerKind::Super,
                    partitions: Vec::new(),
                    vbmeta: None,
                    warnings: vec![format!("LP metadata unreadable: {e}")],
                    crypto: Vec::new(),
                });
            }
        }
    }

    // --- 3. GPT / MBR -------------------------------------------------------
    match sutram_io::partitions(src.as_ref()) {
        Ok(list) if !list.is_empty() => {
            let gpt = list.iter().any(|p| p.table == TableKind::Gpt);
            let mut warnings = Vec::new();
            if !gpt {
                warnings
                    .push("MBR partition table on Android image (unusual — GPT expected)".into());
            }
            let mut parts = Vec::with_capacity(list.len());
            for p in list {
                let view = match OffsetView::new(src.clone(), p.offset, p.size) {
                    Ok(v) => v,
                    Err(e) => {
                        warnings.push(format!("partition {} skipped: {e}", p.index));
                        continue;
                    }
                };
                let name = p
                    .label
                    .clone()
                    .map(|s| sutram_fs::util::sanitize_name(&s))
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| format!("part{}", p.index));
                let mut attrs = Attrs::NONE;
                if has_slot_suffix(&name) {
                    attrs.0 |= Attrs::SLOT_SUFFIXED;
                }
                let mut meta = BTreeMap::new();
                meta.insert("index".into(), p.index.to_string());
                meta.insert("offset".into(), format!("{:#x}", p.offset));
                meta.insert("size".into(), format!("{:#x}", p.size));
                meta.insert(
                    "table".into(),
                    match p.table {
                        TableKind::Gpt => "gpt",
                        TableKind::Mbr => "mbr",
                    }
                    .into(),
                );
                if let Some(g) = &p.type_guid {
                    meta.insert("type_guid".into(), g.clone());
                }
                if let Some(g) = &p.partition_guid {
                    meta.insert("partition_guid".into(), g.clone());
                }
                if p.bootable {
                    meta.insert("bootable".into(), "true".into());
                }
                parts.push(NamedSource {
                    role: classify_name(&name),
                    name,
                    group: String::new(),
                    attrs,
                    source: Arc::new(view),
                    meta,
                });
            }

            // vbmeta: dedicated partitions first, then boot-tail footers.
            let mut vbmeta_info = None;
            for p in &parts {
                if p.role == PartitionRole::Vbmeta {
                    match vbmeta::parse(p.source.as_ref()) {
                        Ok(info) => {
                            vbmeta_info = Some(info);
                            break;
                        }
                        Err(e) => warnings.push(format!("vbmeta partition {}: {e}", p.name)),
                    }
                }
            }
            if vbmeta_info.is_none() {
                for p in &parts {
                    if p.role == PartitionRole::Boot || p.role == PartitionRole::InitBoot {
                        if let Some(info) = vbmeta::find_vbmeta(p.source.as_ref()) {
                            vbmeta_info = Some(info);
                            break;
                        }
                    }
                }
            }
            if let Some(v) = &mut vbmeta_info {
                warnings.extend(v.warnings.iter().cloned());
                if v.dm_verity != vbmeta::DmVerityState::Enabled {
                    warnings.push(format!(
                        "vbmeta: dm-verity state is {} — verified boot weakened",
                        v.dm_verity.as_str()
                    ));
                }
            }

            // Encryption flags: `metadata` partition + crypt_ftr on userdata.
            let mut crypto = Vec::new();
            flag_metadata_partition(&parts, &mut crypto, &mut warnings);
            for p in &parts {
                if p.role == PartitionRole::Userdata {
                    flag_crypt_footer(p.source.as_ref(), &p.name, &mut crypto, &mut warnings);
                }
            }

            // Expand logical partitions inside physical `super` partitions —
            // on modern devices system/vendor/userdata live there, not in
            // the GPT itself.
            let mut logical = Vec::new();
            for p in &parts {
                if p.role != PartitionRole::Super {
                    continue;
                }
                match lp::logical_partitions_verbose(p.source.clone()) {
                    Ok((lp_parts, lp_warnings)) => {
                        for w in lp_warnings {
                            warnings.push(format!("{}: {w}", p.name));
                        }
                        warnings.push(format!(
                            "{}: expanded {} logical partitions from super",
                            p.name,
                            lp_parts.len()
                        ));
                        for mut lp in lp_parts {
                            lp.meta.insert("nested_in".into(), p.name.clone());
                            if let Some(base) = p.meta.get("offset") {
                                lp.meta.insert("parent_offset".into(), base.clone());
                            }
                            logical.push(lp);
                        }
                    }
                    Err(e) => warnings.push(format!(
                        "partition '{}': no readable LP metadata ({e})",
                        p.name
                    )),
                }
            }
            parts.extend(logical);

            return Ok(AndroidLayout {
                container: if gpt {
                    ContainerKind::Gpt
                } else {
                    ContainerKind::Raw
                },
                partitions: parts,
                vbmeta: vbmeta_info,
                warnings,
                crypto,
            });
        }
        Ok(_) => {}
        Err(e) => {
            // Corrupt partition table — still classify as Raw with a note.
            let mut warnings = vec![format!("partition table unreadable: {e}")];
            return Ok(raw_layout(src, &mut warnings));
        }
    }

    // --- 4. Raw --------------------------------------------------------------
    let mut warnings = Vec::new();
    Ok(raw_layout(src, &mut warnings))
}

/// `true` when a *plausible* LP geometry sits at either copy offset.
///
/// Bare magic is not enough: on a full-disk GPT image, offset 0x1000 falls
/// inside the GPT entry array where a type GUID could collide with
/// `0x616C4467`. Requiring the whole geometry struct to validate
/// (struct_size, sector-aligned max size, sane slot count) excludes that.
fn has_lp_geometry(src: &dyn ByteSource) -> bool {
    lp::read_geometry(src).is_ok()
}

/// Bare image: one `image` partition + tail/vbmeta probes.
fn raw_layout(src: Arc<dyn ByteSource>, warnings: &mut Vec<String>) -> AndroidLayout {
    let mut meta = BTreeMap::new();
    meta.insert("offset".into(), "0x0".into());
    meta.insert("size".into(), format!("{:#x}", src.len()));
    // Content hint: run the signature table over the first 4 KiB so callers
    // see e.g. "this raw blob is really a zip" without a second probe.
    if let Ok(head) = src.read_slice(0, 4096) {
        if let Some(t) = sutram_magic::detect(&head) {
            meta.insert("detected_magic".into(), t.name().to_string());
        }
    }
    let parts = vec![NamedSource {
        name: "image".into(),
        group: String::new(),
        attrs: Attrs::NONE,
        source: src.clone(),
        role: PartitionRole::Other,
        meta,
    }];

    let mut vbmeta_info = vbmeta::find_vbmeta(src.as_ref());
    if let Some(v) = &vbmeta_info {
        warnings.extend(v.warnings.iter().cloned());
        if v.dm_verity != vbmeta::DmVerityState::Enabled {
            warnings.push(format!(
                "vbmeta: dm-verity state is {} — verified boot weakened",
                v.dm_verity.as_str()
            ));
        }
    }

    let mut crypto = Vec::new();
    flag_crypt_footer(src.as_ref(), "", &mut crypto, warnings);

    AndroidLayout {
        container: ContainerKind::Raw,
        partitions: parts,
        vbmeta: vbmeta_info.take(),
        warnings: std::mem::take(warnings),
        crypto,
    }
}

fn flag_metadata_partition(
    parts: &[NamedSource],
    crypto: &mut Vec<CryptoFinding>,
    warnings: &mut Vec<String>,
) {
    for p in parts {
        if p.role == PartitionRole::Metadata {
            let note = format!(
                "partition '{}': FBE metadata-encryption keyblob store — \
                 userdata may be metadata-encrypted",
                p.name
            );
            warnings.push(note.clone());
            crypto.push(CryptoFinding {
                kind: CryptoKind::MetadataPartition,
                partition: p.name.clone(),
                note,
                footer: None,
            });
        }
    }
}

fn flag_crypt_footer(
    src: &dyn ByteSource,
    partition: &str,
    crypto: &mut Vec<CryptoFinding>,
    warnings: &mut Vec<String>,
) {
    if let Some(f) = find_crypt_footer(src) {
        let where_ = if partition.is_empty() {
            "image".to_string()
        } else {
            format!("partition '{partition}'")
        };
        let note = format!(
            "{where_}: crypt_ftr footer (v{}.{}, type {}, cipher '{}') — \
             encrypted userdata; contents not decrypted",
            f.version.0, f.version.1, f.crypt_type, f.crypto_type_name
        );
        warnings.push(note.clone());
        crypto.push(CryptoFinding {
            kind: CryptoKind::CryptFooter,
            partition: partition.to_string(),
            note,
            footer: Some(f),
        });
    }
}
