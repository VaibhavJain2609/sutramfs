//! The streaming `walk()` iterator: replays the mount-time plan (live
//! trees, then old-generation trees), building each `FsEntry` lazily so
//! per-file work (magic header reads) happens on demand.

use sutram_fs::{FsEntry, FsError, Result};

use crate::fs::{BtrfsFs, EntryLoc};

/// One item in the walk plan.
#[derive(Debug)]
pub(crate) enum PlanItem {
    /// Emit the entry at this location.
    Entry(EntryLoc),
    /// A deferred error record (lenient mode emits it mid-stream; strict
    /// mode terminates the walk on it).
    Error(FsError),
}

/// Streaming iterator over the mount plan.
pub(crate) struct Walk<'m> {
    fs: &'m BtrfsFs,
    /// Position in `fs.plan`.
    idx: usize,
    finished: bool,
}

impl<'m> Walk<'m> {
    pub(crate) fn new(fs: &'m BtrfsFs) -> Self {
        Walk {
            fs,
            idx: 0,
            finished: false,
        }
    }
}

impl Iterator for Walk<'_> {
    type Item = Result<FsEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.finished {
                return None;
            }
            let idx = self.idx;
            let item = self.fs.plan_item(idx)?;
            self.idx += 1;
            match item {
                PlanItem::Entry(loc) => {
                    let mut e = self.fs.build_entry(loc);
                    e.entry_id = idx as u64;
                    return Some(Ok(e));
                }
                PlanItem::Error(_) => {
                    // Fetch the error (it's stored in the plan).
                    if let Some(e) = self.fs.plan_error(idx) {
                        if self.fs.opts.strict {
                            self.finished = true;
                        }
                        return Some(Err(e));
                    }
                }
            }
        }
    }
}
