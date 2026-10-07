//! `sutram-fs` domain types → protobuf wire types.
//!
//! Vocabulary is carried as lowercase strings (`"live"`, `"fat"`,
//! `"partially_overwritten"`) so clients written before a new variant
//! exists still decode. Nothing here panics on malformed input — the types
//! are already validated by the parsers.

use std::collections::HashMap;

use sutram_fs::{
    DetectConfidence, EntryKind, FsEntry, FsEntryStatus, FsError, FsInfo, FsTimestamp,
    RecoveryState, Severity, Timestamps,
};
use tonic::Status;

use crate::pb;

/// `DetectConfidence` → wire string.
pub fn confidence_str(c: DetectConfidence) -> &'static str {
    match c {
        DetectConfidence::None => "none",
        DetectConfidence::Low => "low",
        DetectConfidence::Medium => "medium",
        DetectConfidence::High => "high",
        DetectConfidence::Certain => "certain",
    }
}

/// `EntryKind` → wire string.
pub fn kind_str(k: EntryKind) -> &'static str {
    match k {
        EntryKind::File => "file",
        EntryKind::Directory => "directory",
        EntryKind::Symlink => "symlink",
        EntryKind::Other => "other",
    }
}

/// `EntryKind` ← wire string (`"dir"` accepted as an alias).
pub fn kind_from_str(s: &str) -> Option<EntryKind> {
    match s {
        "file" => Some(EntryKind::File),
        "directory" | "dir" => Some(EntryKind::Directory),
        "symlink" => Some(EntryKind::Symlink),
        "other" => Some(EntryKind::Other),
        _ => None,
    }
}

fn ts(t: &FsTimestamp) -> pb::TimestampProto {
    pb::TimestampProto {
        has_value: t.value.is_some(),
        unix_nanos: t.value.unwrap_or(0),
        raw_value: t.raw_value,
        raw_encoding: t.raw_encoding.to_string(),
        granularity_nanos: u64::try_from(t.granularity.as_nanos()).unwrap_or(u64::MAX),
    }
}

fn timestamps(ts: &Timestamps) -> Option<pb::TimestampsProto> {
    Some(pb::TimestampsProto {
        modified: ts.modified.as_ref().map(ts_proto),
        accessed: ts.accessed.as_ref().map(ts_proto),
        created: ts.created.as_ref().map(ts_proto),
        changed: ts.changed.as_ref().map(ts_proto),
        deleted: ts.deleted.as_ref().map(ts_proto),
    })
}

fn ts_proto(t: &FsTimestamp) -> pb::TimestampProto {
    ts(t)
}

fn magic(m: &sutram_fs::MagicVerdict) -> pb::MagicVerdictProto {
    pb::MagicVerdictProto {
        present: true,
        declared: m.declared.map(|t| t.name().to_string()).unwrap_or_default(),
        detected: m.detected.map(|t| t.name().to_string()).unwrap_or_default(),
        mismatch: m.mismatch,
        severity: match m.severity {
            Severity::Info => "info",
            Severity::Suspicious => "suspicious",
            Severity::High => "high",
        }
        .to_string(),
        reasons: m.reasons.clone(),
    }
}

/// One walked entry → `FsEntryProto`.
pub fn entry_to_proto(e: &FsEntry) -> pb::FsEntryProto {
    let (status, recovery, recovered, total) = match e.status {
        FsEntryStatus::Live => ("live", "", 0, 0),
        FsEntryStatus::Deleted { recovery } => match recovery {
            RecoveryState::Intact => ("deleted", "intact", e.size, e.size),
            RecoveryState::PartiallyOverwritten {
                recovered_bytes,
                total_bytes,
            } => ("deleted", "partially_overwritten", recovered_bytes, total_bytes),
            RecoveryState::Unrecoverable => ("deleted", "unrecoverable", 0, e.size),
            RecoveryState::Unknown => ("deleted", "unknown", 0, 0),
        },
    };
    pb::FsEntryProto {
        path: e.path.clone(),
        name: e.name.clone(),
        entry_id: e.entry_id,
        kind: kind_str(e.kind).to_string(),
        size: e.size,
        disk_offset: e.disk_offset,
        allocated_ranges: e
            .allocated_ranges
            .iter()
            .map(|&(offset, len)| pb::Range { offset, len })
            .collect(),
        timestamps: timestamps(&e.timestamps),
        status: status.to_string(),
        recovery: recovery.to_string(),
        recovered_bytes: recovered,
        total_bytes: total,
        meta: e.meta.clone(),
        magic: e.magic.as_ref().map(magic),
        error: String::new(),
    }
}

/// A lenient-mode walk error → `FsEntryProto` with only `error` populated.
pub fn error_to_proto(err: &FsError) -> pb::FsEntryProto {
    pb::FsEntryProto {
        error: err.to_string(),
        ..Default::default()
    }
}

/// `FsInfo` → `FsInfoProto`; `meta` carries evidence correlation ids.
pub fn info_to_proto(info: &FsInfo, meta: HashMap<String, String>) -> pb::FsInfoProto {
    pb::FsInfoProto {
        fs_type: info.fs_type.clone(),
        label: info.label.clone().unwrap_or_default(),
        uuid: info.uuid.clone().unwrap_or_default(),
        block_size: info.block_size,
        total_blocks: info.total_blocks,
        has_free_blocks: info.free_blocks.is_some(),
        free_blocks: info.free_blocks.unwrap_or(0),
        has_total_nodes: info.total_nodes.is_some(),
        total_nodes: info.total_nodes.unwrap_or(0),
        fs_meta: info.meta.clone(),
        meta,
    }
}

/// `MountOptionsProto` → `MountOptions` (absent message = daemon defaults).
pub fn mount_options(o: Option<&pb::MountOptionsProto>) -> sutram_fs::MountOptions {
    match o {
        Some(p) => sutram_fs::MountOptions {
            strict: p.strict,
            check_magic: p.check_magic,
            include_orphans: p.include_orphans,
        },
        None => sutram_fs::MountOptions::default(),
    }
}

/// Map a parser-layer error to the closest gRPC status.
pub fn status_err(e: &FsError) -> Status {
    match e {
        FsError::NotFound { .. } => Status::not_found(e.to_string()),
        FsError::InvalidInput { .. } => Status::invalid_argument(e.to_string()),
        FsError::Unsupported { .. } => Status::unimplemented(e.to_string()),
        FsError::Corrupt { .. } | FsError::Truncated { .. } => {
            Status::failed_precondition(e.to_string())
        }
        FsError::Io(_) => Status::internal(e.to_string()),
    }
}

/// Status for an unknown/expired handle id.
pub fn unknown_handle(id: &str) -> Status {
    Status::not_found(format!("mount handle '{id}' unknown or expired"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::Duration;
    use sutram_fs::{FsTimestamp, Timestamps};

    fn entry(kind: EntryKind, status: FsEntryStatus) -> FsEntry {
        FsEntry {
            path: "/X.TXT".into(),
            name: "X.TXT".into(),
            entry_id: 7,
            kind,
            size: 42,
            disk_offset: 0x400,
            allocated_ranges: vec![(0x800, 512)],
            timestamps: Timestamps {
                modified: Some(FsTimestamp {
                    value: Some(1_700_000_000_000_000_000),
                    raw_value: 0x55AA,
                    raw_encoding: "fat-dos-datetime",
                    granularity: Duration::from_secs(2),
                }),
                ..Default::default()
            },
            status,
            meta: HashMap::from([("hidden".into(), "true".into())]),
            magic: None,
        }
    }

    #[test]
    fn live_entry_converts() {
        let p = entry_to_proto(&entry(EntryKind::File, FsEntryStatus::Live));
        assert_eq!(p.kind, "file");
        assert_eq!(p.status, "live");
        assert!(p.recovery.is_empty());
        assert_eq!(p.allocated_ranges.len(), 1);
        let t = p.timestamps.unwrap().modified.unwrap();
        assert!(t.has_value);
        assert_eq!(t.granularity_nanos, 2_000_000_000);
        assert_eq!(p.meta.get("hidden").unwrap(), "true");
        assert!(p.error.is_empty());
    }

    #[test]
    fn deleted_partial_carries_bytes() {
        let e = entry(
            EntryKind::File,
            FsEntryStatus::Deleted {
                recovery: RecoveryState::PartiallyOverwritten {
                    recovered_bytes: 100,
                    total_bytes: 700,
                },
            },
        );
        let p = entry_to_proto(&e);
        assert_eq!(p.status, "deleted");
        assert_eq!(p.recovery, "partially_overwritten");
        assert_eq!(p.recovered_bytes, 100);
        assert_eq!(p.total_bytes, 700);
    }

    #[test]
    fn error_records_only_set_error() {
        let p = error_to_proto(&FsError::corrupt(0x10, "bad dirent"));
        assert!(p.path.is_empty());
        assert!(p.error.contains("0x10"));
        assert!(p.error.contains("bad dirent"));
    }

    #[test]
    fn kind_roundtrip() {
        for k in [
            EntryKind::File,
            EntryKind::Directory,
            EntryKind::Symlink,
            EntryKind::Other,
        ] {
            assert_eq!(kind_from_str(kind_str(k)), Some(k));
        }
        assert_eq!(kind_from_str("dir"), Some(EntryKind::Directory));
        assert_eq!(kind_from_str("bogus"), None);
    }

    #[test]
    fn status_mapping() {
        assert_eq!(
            status_err(&FsError::NotFound { path: "/x".into() }).code(),
            tonic::Code::NotFound
        );
        assert_eq!(
            status_err(&FsError::InvalidInput { msg: "x".into() }).code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            status_err(&FsError::unsupported("aes-xts")).code(),
            tonic::Code::Unimplemented
        );
        assert_eq!(
            status_err(&FsError::corrupt(0x10, "bad")).code(),
            tonic::Code::FailedPrecondition
        );
        assert_eq!(
            status_err(&FsError::truncated(0x20, 512, 100)).code(),
            tonic::Code::FailedPrecondition
        );
        assert_eq!(
            status_err(&FsError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "disk gone"
            )))
            .code(),
            tonic::Code::Internal
        );
    }

    #[test]
    fn unknown_handle_is_not_found() {
        let s = unknown_handle("mh-dead");
        assert_eq!(s.code(), tonic::Code::NotFound);
        assert!(s.message().contains("mh-dead"));
    }

    #[test]
    fn confidence_strings_cover_all() {
        for (c, want) in [
            (DetectConfidence::None, "none"),
            (DetectConfidence::Low, "low"),
            (DetectConfidence::Medium, "medium"),
            (DetectConfidence::High, "high"),
            (DetectConfidence::Certain, "certain"),
        ] {
            assert_eq!(confidence_str(c), want);
        }
    }

    #[test]
    fn deleted_recovery_variants() {
        let intact = entry_to_proto(&entry(
            EntryKind::File,
            FsEntryStatus::Deleted {
                recovery: RecoveryState::Intact,
            },
        ));
        assert_eq!(intact.recovery, "intact");
        assert_eq!(intact.recovered_bytes, 42);
        assert_eq!(intact.total_bytes, 42);

        let gone = entry_to_proto(&entry(
            EntryKind::File,
            FsEntryStatus::Deleted {
                recovery: RecoveryState::Unrecoverable,
            },
        ));
        assert_eq!(gone.recovery, "unrecoverable");
        assert_eq!(gone.recovered_bytes, 0);
        assert_eq!(gone.total_bytes, 42);

        let unk = entry_to_proto(&entry(
            EntryKind::File,
            FsEntryStatus::Deleted {
                recovery: RecoveryState::Unknown,
            },
        ));
        assert_eq!(unk.recovery, "unknown");
        assert_eq!(unk.recovered_bytes, 0);
        assert_eq!(unk.total_bytes, 0);
    }

    #[test]
    fn magic_verdict_converts() {
        let mut e = entry(EntryKind::File, FsEntryStatus::Live);
        e.magic = Some(sutram_fs::MagicVerdict {
            declared: Some(sutram_fs::MagicType::PlainText),
            detected: Some(sutram_fs::MagicType::Pe),
            mismatch: true,
            severity: Severity::High,
            reasons: vec!["PE under .txt".into()],
        });
        let p = entry_to_proto(&e);
        let m = p.magic.expect("verdict");
        assert!(m.present);
        assert_eq!(m.declared, "text data");
        assert_eq!(m.detected, "PE/COFF Windows executable");
        assert!(m.mismatch);
        assert_eq!(m.severity, "high");
        assert_eq!(m.reasons, ["PE under .txt"]);

        // Other severities map too.
        e.magic = Some(sutram_fs::MagicVerdict {
            declared: None,
            detected: None,
            mismatch: false,
            severity: Severity::Suspicious,
            reasons: vec![],
        });
        assert_eq!(entry_to_proto(&e).magic.unwrap().severity, "suspicious");
        e.magic = Some(sutram_fs::MagicVerdict {
            declared: None,
            detected: None,
            mismatch: false,
            severity: Severity::Info,
            reasons: vec![],
        });
        let m = entry_to_proto(&e).magic.unwrap();
        assert_eq!(m.severity, "info");
        assert!(m.declared.is_empty() && m.detected.is_empty());
    }

    #[test]
    fn unset_timestamp_slot_is_explicit() {
        let mut e = entry(EntryKind::File, FsEntryStatus::Live);
        e.timestamps = Timestamps {
            modified: Some(FsTimestamp {
                value: None,
                raw_value: 0,
                raw_encoding: "fat-dos-datetime",
                granularity: Duration::MAX, // saturates u64 nanos
            }),
            ..Default::default()
        };
        let p = entry_to_proto(&e);
        let t = p.timestamps.as_ref().unwrap().modified.as_ref().unwrap();
        assert!(!t.has_value);
        assert_eq!(t.unix_nanos, 0);
        assert_eq!(t.granularity_nanos, u64::MAX);
        assert!(p.timestamps.as_ref().unwrap().accessed.is_none());
    }

    #[test]
    fn mount_options_maps_proto() {
        // Absent proto → parser-layer defaults (lenient, magic, orphans).
        let d = mount_options(None);
        assert!(!d.strict && d.check_magic && d.include_orphans);
        let p = mount_options(Some(&pb::MountOptionsProto {
            strict: true,
            check_magic: false,
            include_orphans: false,
        }));
        assert!(p.strict && !p.check_magic && !p.include_orphans);
    }

    #[test]
    fn info_to_proto_optional_fields() {
        let full = FsInfo {
            fs_type: "STUB".into(),
            label: Some("LABEL".into()),
            uuid: Some("uuid-1".into()),
            block_size: 4096,
            total_blocks: 128,
            free_blocks: Some(64),
            total_nodes: Some(32),
            meta: HashMap::from([("note".into(), "v".into())]),
        };
        let meta = HashMap::from([("evidence_id".into(), "EV".into())]);
        let p = info_to_proto(&full, meta);
        assert_eq!(p.fs_type, "STUB");
        assert_eq!(p.label, "LABEL");
        assert_eq!(p.uuid, "uuid-1");
        assert!(p.has_free_blocks && p.free_blocks == 64);
        assert!(p.has_total_nodes && p.total_nodes == 32);
        assert_eq!(p.fs_meta.get("note").unwrap(), "v");
        assert_eq!(p.meta.get("evidence_id").unwrap(), "EV");

        // Sparse info: has_* flags flip off, strings default to "".
        let p = info_to_proto(&FsInfo::default(), HashMap::new());
        assert!(!p.has_free_blocks && !p.has_total_nodes);
        assert!(p.label.is_empty() && p.uuid.is_empty());
    }
}
