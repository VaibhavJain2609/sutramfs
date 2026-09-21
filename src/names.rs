//! Android partition-name heuristics.
//!
//! GPT carries arbitrary vendor/extra type GUIDs (handled by `sutram-io`),
//! but on Android the *name* is what an examiner keys on: `boot`,
//! `vendor`, `system`, `userdata`, `super`, `metadata`, `persist`, …
//! plus the A/B `_a`/`_b` slot suffixes and OEM variants like
//! `vendor_boot`, `system_ext`, `init_boot`. [`classify_name`] maps a name
//! to a coarse [`PartitionRole`]; [`split_slot_suffix`] separates the base
//! name from its slot suffix.

/// Coarse functional role of an Android partition, derived from its name.
///
/// `Other` covers OEM-specific names the table does not know; the raw name
/// is always preserved on [`crate::NamedSource::name`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionRole {
    /// Kernel/ramdisk boot image (`boot`, `boot_a`, …).
    Boot,
    /// Recovery image.
    Recovery,
    /// Kernel+ramdisk for the generic kernel image path (`init_boot`).
    InitBoot,
    /// `vendor_boot` / `vendor_kernel_boot` ramdisk partitions.
    VendorBoot,
    /// Verified-boot metadata (`vbmeta`, `vbmeta_a`, `vbmeta_system`, …).
    Vbmeta,
    /// DTBO (device-tree overlay) partition.
    Dtbo,
    /// Physical container for dynamic partitions (`super`).
    Super,
    /// `system` / `system_ext` logical partitions.
    System,
    /// `vendor` logical partition.
    Vendor,
    /// `product` logical partition.
    Product,
    /// `odm` logical partition.
    Odm,
    /// `vendor_dlkm` / `system_dlkm` / `odm_dlkm` kernel-module partitions.
    Dlkm,
    /// `userdata`/`data` — the FBE-protected data area.
    Userdata,
    /// `metadata` — holds the FBE metadata-encryption keyblobs.
    Metadata,
    /// `persist` — factory calibration/persistent data.
    Persist,
    /// `cache`.
    Cache,
    /// `misc` — bootloader control block.
    Misc,
    /// `modem`/`radio`/`modemst*` — baseband firmware and config.
    Modem,
    /// `frp` — factory-reset-protection partition.
    Frp,
    /// `splash`/`logo`/`bootlogo` — display assets.
    Logo,
    /// `pvmfw`/`bl31`/`tz*`/`xbl*`/`aboot`/other boot-chain blobs.
    Bootloader,
    /// Anything not matched by the heuristics.
    Other,
}

impl PartitionRole {
    /// Short stable label for reports/`meta` values.
    pub fn as_str(self) -> &'static str {
        match self {
            PartitionRole::Boot => "boot",
            PartitionRole::Recovery => "recovery",
            PartitionRole::InitBoot => "init_boot",
            PartitionRole::VendorBoot => "vendor_boot",
            PartitionRole::Vbmeta => "vbmeta",
            PartitionRole::Dtbo => "dtbo",
            PartitionRole::Super => "super",
            PartitionRole::System => "system",
            PartitionRole::Vendor => "vendor",
            PartitionRole::Product => "product",
            PartitionRole::Odm => "odm",
            PartitionRole::Dlkm => "dlkm",
            PartitionRole::Userdata => "userdata",
            PartitionRole::Metadata => "metadata",
            PartitionRole::Persist => "persist",
            PartitionRole::Cache => "cache",
            PartitionRole::Misc => "misc",
            PartitionRole::Modem => "modem",
            PartitionRole::Frp => "frp",
            PartitionRole::Logo => "logo",
            PartitionRole::Bootloader => "bootloader",
            PartitionRole::Other => "other",
        }
    }
}

/// Split an A/B slot suffix off a partition name.
///
/// Returns `(base, slot)` where `slot` is `Some('a'|'b'|…)` when the name
/// ends in `_<letter>` (Android only ever ships `_a`/`_b`, but `_c` exists
/// on A/B/C test devices — accept any lowercase letter).
///
/// Names that merely *contain* underscores (`vendor_boot`, `init_boot`)
/// are untouched — only a trailing `_x` single-letter suffix is split.
pub fn split_slot_suffix(name: &str) -> (&str, Option<char>) {
    let b = name.as_bytes();
    if b.len() >= 3 {
        let last = b[b.len() - 1];
        if b[b.len() - 2] == b'_' && last.is_ascii_lowercase() {
            return (&name[..b.len() - 2], Some(last as char));
        }
    }
    (name, None)
}

/// `true` when the name carries a trailing A/B `_<slot>` suffix.
///
/// Case-insensitive on the slot letter (`Boot_A` counts) to stay
/// consistent with [`classify_name`].
pub fn has_slot_suffix(name: &str) -> bool {
    split_slot_suffix(&name.to_ascii_lowercase()).1.is_some()
}

/// Classify an Android partition name into a [`PartitionRole`].
///
/// Matching is on the de-suffixed base name (so `boot_a` → [`Boot`]) and
/// covers common OEM spellings (`vendor_boot`, `system_ext`, `userdata`…).
/// Prefix matches are used for families like `vbmeta_system`,
/// `modemst1`/`modemst2`, `xbl_a`-style Qualcomm chains.
pub fn classify_name(name: &str) -> PartitionRole {
    // Lowercase first so vendor case variants (`Boot_A`, `SUPER`) still
    // de-suffix and classify — the split itself is case-sensitive on the
    // slot letter.
    let lower = name.to_ascii_lowercase();
    let (base, _slot) = split_slot_suffix(&lower);
    let n = base;

    let role = match n {
        "boot" => PartitionRole::Boot,
        "recovery" => PartitionRole::Recovery,
        "init_boot" => PartitionRole::InitBoot,
        "vendor_boot" | "vendor_kernel_boot" => PartitionRole::VendorBoot,
        "vbmeta" => PartitionRole::Vbmeta,
        "vbmeta_system" | "vbmeta_vendor" | "vbmeta_vendor_dlkm" | "vbmeta_system_dlkm" => {
            PartitionRole::Vbmeta
        }
        "dtbo" => PartitionRole::Dtbo,
        "super" => PartitionRole::Super,
        "system" | "system_ext" | "system_other" => PartitionRole::System,
        "vendor" | "vendor_other" => PartitionRole::Vendor,
        "product" => PartitionRole::Product,
        "odm" => PartitionRole::Odm,
        "vendor_dlkm" | "system_dlkm" | "odm_dlkm" | "dlkm" => PartitionRole::Dlkm,
        "userdata" | "data" | "userdata_orig" => PartitionRole::Userdata,
        "metadata" => PartitionRole::Metadata,
        "persist" | "persistbak" | "persist_backup" => PartitionRole::Persist,
        "cache" => PartitionRole::Cache,
        "misc" => PartitionRole::Misc,
        "modem" | "radio" | "modemst1" | "modemst2" | "fsg" | "modem_a" | "md1img"
        | "mdm1m9kefs1" => PartitionRole::Modem,
        "frp" => PartitionRole::Frp,
        "splash" | "logo" | "bootlogo" | "imagefv" => PartitionRole::Logo,
        _ => PartitionRole::Other,
    };
    if role != PartitionRole::Other {
        return role;
    }
    // Bootloader-chain blobs (Qualcomm/Mediatek/Exynos naming families).
    for p in [
        "xbl",
        "abl",
        "aboot",
        "sbl",
        "bl31",
        "bl2",
        "tz",
        "hyp",
        "aop",
        "cmnlib",
        "keymaster",
        "lksecapp",
        "uefi",
        "pvmfw",
        "mcupm",
        "tee",
        "gz",
        "scp",
        "spmfw",
        "sspm",
        "preloader",
        "lk",
    ] {
        if n == p || n.starts_with(p) {
            let rest = &n[p.len()..];
            if rest.is_empty() || rest.starts_with('_') || rest.as_bytes()[0].is_ascii_digit() {
                return PartitionRole::Bootloader;
            }
        }
    }
    PartitionRole::Other
}

/// Android GPT partitions whose presence implies a feature an examiner
/// should note. Returns a short tag or `None`.
pub fn notable_flag(name: &str) -> Option<&'static str> {
    match classify_name(name) {
        PartitionRole::Metadata => {
            Some("metadata partition present — FBE metadata encryption in use")
        }
        PartitionRole::Frp => Some("frp partition — factory-reset protection"),
        _ => None,
    }
}
