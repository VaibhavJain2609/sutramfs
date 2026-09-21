//! `Report` → [`Json`] tree. Layout is deliberately flat and stable — keys
//! appear in reading order and never disappear (empty sections are `[]`
//! rather than absent) so downstream tooling can rely on the shape.

use crate::json::Json;
use crate::report::{severity_label, Report};

/// Build the JSON value for `r` (see [`Report::to_json`]).
///
/// [`Report::to_json`]: crate::Report::to_json
pub fn report_json(r: &Report) -> Json {
    let volume = Json::Obj(vec![
        ("fs_type".into(), Json::s(r.volume.fs_type.clone())),
        ("label".into(), Json::opt(r.volume.label.clone(), Json::s)),
        ("uuid".into(), Json::opt(r.volume.uuid.clone(), Json::s)),
        ("block_size".into(), Json::Num(r.volume.block_size)),
        ("total_blocks".into(), Json::Num(r.volume.total_blocks)),
        (
            "free_blocks".into(),
            Json::opt(r.volume.free_blocks, Json::Num),
        ),
        (
            "total_nodes".into(),
            Json::opt(r.volume.total_nodes, Json::Num),
        ),
        ("image_size".into(), Json::Num(r.volume.image_size)),
        (
            "meta".into(),
            Json::Obj(
                r.volume
                    .meta
                    .iter()
                    .map(|(k, v)| (k.clone(), Json::s(v.clone())))
                    .collect(),
            ),
        ),
    ]);

    let c = &r.census;
    let census = Json::Obj(vec![
        ("total_entries".into(), Json::Num(c.total_entries as u64)),
        ("live".into(), Json::Num(c.live as u64)),
        ("deleted".into(), Json::Num(c.deleted as u64)),
        ("files".into(), Json::Num(c.files as u64)),
        ("directories".into(), Json::Num(c.directories as u64)),
        ("symlinks".into(), Json::Num(c.symlinks as u64)),
        ("other".into(), Json::Num(c.other as u64)),
        (
            "recovery_intact".into(),
            Json::Num(c.recovery_intact as u64),
        ),
        (
            "recovery_partial".into(),
            Json::Num(c.recovery_partial as u64),
        ),
        (
            "recovery_unrecoverable".into(),
            Json::Num(c.recovery_unrecoverable as u64),
        ),
        (
            "recovery_unknown".into(),
            Json::Num(c.recovery_unknown as u64),
        ),
        ("live_bytes".into(), Json::Num(c.live_bytes)),
        ("deleted_bytes".into(), Json::Num(c.deleted_bytes)),
        ("walk_errors".into(), Json::Num(c.walk_errors as u64)),
    ]);

    let d = &r.deleted;
    let deleted = Json::Obj(vec![
        ("intact".into(), Json::Num(d.intact as u64)),
        ("partial".into(), Json::Num(d.partial as u64)),
        ("lost".into(), Json::Num(d.lost as u64)),
        ("recovered_bytes".into(), Json::Num(d.recovered_bytes)),
        ("total_bytes".into(), Json::Num(d.total_bytes)),
        (
            "rows".into(),
            Json::Arr(
                d.rows
                    .iter()
                    .map(|row| {
                        Json::Obj(vec![
                            ("path".into(), Json::s(row.path.clone())),
                            ("size".into(), Json::Num(row.size)),
                            ("recovery".into(), Json::s(row.recovery.clone())),
                            (
                                "recovered_bytes".into(),
                                Json::Num(row.recovered_bytes),
                            ),
                            ("total_bytes".into(), Json::Num(row.total_bytes)),
                            ("disk_offset".into(), Json::Num(row.disk_offset)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ]);

    let mismatches = Json::Arr(
        r.magic_mismatches
            .iter()
            .map(|m| {
                Json::Obj(vec![
                    ("path".into(), Json::s(m.path.clone())),
                    (
                        "declared".into(),
                        Json::opt(m.declared.clone(), Json::s),
                    ),
                    (
                        "detected".into(),
                        Json::opt(m.detected.clone(), Json::s),
                    ),
                    (
                        "severity".into(),
                        Json::s(severity_label(m.severity)),
                    ),
                    (
                        "reasons".into(),
                        Json::Arr(m.reasons.iter().map(|s| Json::s(s.clone())).collect()),
                    ),
                    ("size".into(), Json::Num(m.size)),
                    ("deleted".into(), Json::Bool(m.deleted)),
                ])
            })
            .collect(),
    );

    let anomalies = Json::Arr(
        r.anomalies
            .iter()
            .map(|a| {
                Json::Obj(vec![
                    ("path".into(), Json::s(a.path.clone())),
                    ("kind".into(), Json::s(a.kind.clone())),
                    ("detail".into(), Json::s(a.detail.clone())),
                ])
            })
            .collect(),
    );

    let files = Json::Arr(
        r.files
            .iter()
            .map(|f| {
                Json::Obj(vec![
                    ("path".into(), Json::s(f.path.clone())),
                    ("kind".into(), Json::s(f.kind.clone())),
                    ("status".into(), Json::s(f.status.clone())),
                    ("recovery".into(), Json::s(f.recovery.clone())),
                    ("size".into(), Json::Num(f.size)),
                    ("sha256".into(), Json::opt(f.sha256.clone(), Json::s)),
                    ("hashed_bytes".into(), Json::Num(f.hashed_bytes)),
                    ("disk_offset".into(), Json::Num(f.disk_offset)),
                    (
                        "allocated_ranges".into(),
                        Json::Arr(
                            f.allocated_ranges
                                .iter()
                                .map(|&(off, len)| {
                                    Json::Arr(vec![Json::Num(off), Json::Num(len)])
                                })
                                .collect(),
                        ),
                    ),
                    ("modified_ns".into(), Json::opt(f.modified_ns, Json::Int)),
                    ("accessed_ns".into(), Json::opt(f.accessed_ns, Json::Int)),
                    ("created_ns".into(), Json::opt(f.created_ns, Json::Int)),
                    (
                        "meta".into(),
                        Json::Obj(
                            f.meta
                                .iter()
                                .map(|(k, v)| (k.clone(), Json::s(v.clone())))
                                .collect(),
                        ),
                    ),
                ])
            })
            .collect(),
    );

    Json::Obj(vec![
        ("title".into(), Json::s(r.title.clone())),
        ("tool".into(), Json::s(r.tool.clone())),
        (
            "generated_unix_secs".into(),
            Json::Int(r.generated_unix_secs),
        ),
        ("image_desc".into(), Json::s(r.image_desc.clone())),
        ("volume".into(), volume),
        ("census".into(), census),
        ("deleted".into(), deleted),
        ("magic_mismatches".into(), mismatches),
        ("anomalies".into(), anomalies),
        ("files".into(), files),
        ("examiner_notes".into(), Json::s(r.examiner_notes.clone())),
    ])
}
