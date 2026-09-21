//! PyO3 Python bindings — the `sutramfs` module. Built only with the
//! `python` cargo feature; mirrors the C API surface:
//!
//! ```python
//! import sutramfs
//! sutramfs.detect("/evidence/disk.img")       # → dict
//! img = sutramfs.open_image("/evidence/disk.img")
//! img.fs_type                                # → "fat"
//! img.info()                                 # → dict
//! img.entries()                              # → [dict, …]
//! img.read("/HELLO.TXT")                     # → bytes
//! ```

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{IntoPyDict, PyBytes, PyDict};

use crate::core;
use crate::json;

/// `sutramfs.detect(path)` — probe every parser, return
/// `{"filesystem":…,"confidence":…,"candidates":[[name,conf],…]}` as a
/// dict, or `None` when nothing matches.
#[pyfunction]
fn detect(py: Python<'_>, path: &str) -> PyResult<PyObject> {
    let file = sutram_io::FileSource::open(path)
        .map_err(|e| PyRuntimeError::new_err(format!("open {path}: {e}")))?;
    let candidates = core::detect_all(&file);
    let d = PyDict::new_bound(py);
    let best = candidates.first();
    match best {
        Some((n, c)) if *c >= sutram_fs::DetectConfidence::Medium => {
            d.set_item("filesystem", n)?;
            d.set_item("confidence", conf_name(*c))?;
        }
        _ => {
            d.set_item("filesystem", py.None())?;
            d.set_item("confidence", py.None())?;
        }
    }
    let cands: Vec<(&str, &str)> = candidates
        .iter()
        .map(|(n, c)| (*n, conf_name(*c)))
        .collect();
    d.set_item("candidates", cands)?;
    Ok(d.unbind().into())
}

fn conf_name(c: sutram_fs::DetectConfidence) -> &'static str {
    use sutram_fs::DetectConfidence as D;
    match c {
        D::None => "none",
        D::Low => "low",
        D::Medium => "medium",
        D::High => "high",
        D::Certain => "certain",
    }
}

/// A mounted filesystem image.
#[pyclass(name = "SutramImage")]
struct PyImage {
    inner: core::Mounted,
}

/// `sutramfs.open_image(path, fs_type=None, partition=None)` — mount an
/// image, auto-detecting the filesystem unless `fs_type` names a parser.
#[pyfunction]
#[pyo3(signature = (path, fs_type=None, partition=None))]
fn open_image(path: &str, fs_type: Option<&str>, partition: Option<usize>) -> PyResult<PyImage> {
    core::open(path, fs_type, partition)
        .map(|m| PyImage { inner: m })
        .map_err(PyRuntimeError::new_err)
}

#[pymethods]
impl PyImage {
    /// Short name of the parser that mounted the image.
    #[getter]
    fn fs_type(&self) -> &'static str {
        self.inner.parser_name
    }

    /// Volume info as a dict.
    fn info<'py>(&self, py: Python<'py>) -> PyResult<PyObject> {
        let d = PyDict::new_bound(py);
        let i = self.inner.fs.info();
        d.set_item("parser", self.inner.parser_name)?;
        d.set_item("fs_type", &i.fs_type)?;
        d.set_item("label", &i.label)?;
        d.set_item("uuid", &i.uuid)?;
        d.set_item("block_size", i.block_size)?;
        d.set_item("total_blocks", i.total_blocks)?;
        d.set_item("free_blocks", i.free_blocks)?;
        d.set_item("total_nodes", i.total_nodes)?;
        d.set_item("meta", i.meta.clone().into_py_dict_bound(py))?;
        Ok(d.unbind().into())
    }

    /// All entries (live + deleted + orphans) as a list of dicts.
    /// `max_entries` bounds memory on huge images (default 1 000 000).
    #[pyo3(signature = (max_entries=1_000_000))]
    fn entries<'py>(&self, py: Python<'py>, max_entries: u64) -> PyResult<Vec<PyObject>> {
        let mut out = Vec::new();
        let mut n = 0u64;
        core::for_each_entry(&self.inner, |item| {
            if n >= max_entries {
                return;
            }
            match item {
                Ok(e) => {
                    if let Ok(d) = entry_dict(py, e) {
                        out.push(d);
                        n += 1;
                    }
                }
                Err(msg) => {
                    let d = PyDict::new_bound(py);
                    let _ = d.set_item("error", msg);
                    out.push(d.unbind().into());
                    n += 1;
                }
            }
        });
        Ok(out)
    }

    /// Read a file's content by path (leading `/` optional), bounded to
    /// `max_bytes` (default 256 MiB).
    #[pyo3(signature = (path, max_bytes=268_435_456))]
    fn read<'py>(&self, py: Python<'py>, path: &str, max_bytes: u64) -> PyResult<PyObject> {
        let data = core::read_file_by_path(&self.inner, path, max_bytes)
            .map_err(PyRuntimeError::new_err)?;
        Ok(PyBytes::new_bound(py, &data).unbind().into())
    }

    /// Entry enumeration as JSONL text (same shape as the C API).
    #[pyo3(signature = (max_entries=1_000_000))]
    fn entries_jsonl(&self, max_entries: u64) -> String {
        let mut out = String::new();
        let mut n = 0u64;
        core::for_each_entry(&self.inner, |item| {
            if n >= max_entries {
                return;
            }
            match item {
                Ok(e) => out.push_str(&json::entry_json(e)),
                Err(msg) => out.push_str(&json::error_json(&msg)),
            }
            out.push('\n');
            n += 1;
        });
        out
    }
}

/// Build a `dict` mirroring `json::entry_json`'s field names.
fn entry_dict<'py>(py: Python<'py>, e: &sutram_fs::FsEntry) -> PyResult<PyObject> {
    let d = PyDict::new_bound(py);
    d.set_item("path", &e.path)?;
    d.set_item("name", &e.name)?;
    d.set_item("entry_id", e.entry_id)?;
    d.set_item(
        "kind",
        match e.kind {
            sutram_fs::EntryKind::File => "file",
            sutram_fs::EntryKind::Directory => "directory",
            sutram_fs::EntryKind::Symlink => "symlink",
            sutram_fs::EntryKind::Other => "other",
        },
    )?;
    d.set_item("size", e.size)?;
    d.set_item("disk_offset", e.disk_offset)?;
    let ranges: Vec<(u64, u64)> = e.allocated_ranges.clone();
    d.set_item("allocated_ranges", ranges)?;

    match e.status {
        sutram_fs::FsEntryStatus::Live => d.set_item("status", "live")?,
        sutram_fs::FsEntryStatus::Deleted { recovery } => {
            let st = PyDict::new_bound(py);
            let rec = PyDict::new_bound(py);
            match recovery {
                sutram_fs::RecoveryState::Intact => rec.set_item("recovery", "intact")?,
                sutram_fs::RecoveryState::PartiallyOverwritten {
                    recovered_bytes,
                    total_bytes,
                } => {
                    rec.set_item("recovery", "partial")?;
                    rec.set_item("recovered_bytes", recovered_bytes)?;
                    rec.set_item("total_bytes", total_bytes)?;
                }
                sutram_fs::RecoveryState::Unrecoverable => {
                    rec.set_item("recovery", "unrecoverable")?
                }
                sutram_fs::RecoveryState::Unknown => rec.set_item("recovery", "unknown")?,
            }
            st.set_item("deleted", rec)?;
            d.set_item("status", st)?;
        }
    }

    let ts = PyDict::new_bound(py);
    for (name, t) in [
        ("modified", &e.timestamps.modified),
        ("accessed", &e.timestamps.accessed),
        ("created", &e.timestamps.created),
        ("changed", &e.timestamps.changed),
        ("deleted", &e.timestamps.deleted),
    ] {
        match t {
            None => ts.set_item(name, py.None())?,
            Some(t) => {
                let td = PyDict::new_bound(py);
                td.set_item("value_ns", t.value)?;
                td.set_item("raw_value", t.raw_value)?;
                td.set_item("raw_encoding", t.raw_encoding)?;
                td.set_item("granularity_ns", t.granularity.as_nanos())?;
                ts.set_item(name, td)?;
            }
        }
    }
    d.set_item("timestamps", ts)?;

    d.set_item("meta", e.meta.clone().into_py_dict_bound(py))?;

    match &e.magic {
        None => d.set_item("magic", py.None())?,
        Some(m) => {
            let md = PyDict::new_bound(py);
            md.set_item("declared", m.declared.map(|t| format!("{t:?}")))?;
            md.set_item("detected", m.detected.map(|t| format!("{t:?}")))?;
            md.set_item("mismatch", m.mismatch)?;
            md.set_item("severity", format!("{:?}", m.severity))?;
            md.set_item("reasons", m.reasons.clone())?;
            d.set_item("magic", md)?;
        }
    }
    Ok(d.unbind().into())
}

/// The `sutramfs` extension module.
#[pymodule]
fn sutramfs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(detect, m)?)?;
    m.add_function(wrap_pyfunction!(open_image, m)?)?;
    m.add_class::<PyImage>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
