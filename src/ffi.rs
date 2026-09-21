//! The C FFI surface — the only place `unsafe` appears in this crate.
//!
//! Soundness contract:
//! * Every exported function validates all pointers (NULL → error/NULL,
//!   never deref).
//! * No Rust panic may cross the boundary: every body runs inside
//!   `catch_unwind` and reports via `sutram_last_error`.
//! * Ownership is documented per function in `include/sutram.h`: strings
//!   and buffers returned to C must be freed with `sutram_free_string` /
//!   `sutram_free_bytes`; handles with `sutram_close`. Borrowed pointers
//!   (`sutram_last_error`, `sutram_fs_type`, `sutram_version`) are never
//!   freed by the caller.
//! * Callback `user` pointers are passed through verbatim; we never
//!   dereference them.
#![warn(unsafe_op_in_unsafe_fn)]

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::ptr;

use crate::core;
use crate::json;

/// The mounted-filesystem handle (`SutramFs` in the header).
pub struct SutramFs {
    inner: core::Mounted,
    /// NUL-terminated parser name for `sutram_fs_type` (Rust `&str`
    /// slices are not NUL-terminated, so we cannot hand out `as_ptr()`).
    name_c: CString,
}

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

fn set_err(msg: impl Into<String>) {
    let msg = msg.into();
    LAST_ERROR.with(|e| {
        // Errors must not contain NUL — JSON/error text never does, but
        // strip defensively rather than panic inside an error path.
        let sanitized: String = msg.chars().filter(|&c| c != '\0').collect();
        *e.borrow_mut() = CString::new(sanitized).unwrap_or_default();
    });
}

fn clear_err() {
    LAST_ERROR.with(|e| *e.borrow_mut() = CString::default());
}

/// Borrow a `&str` from a C string pointer; `None` when NULL.
/// (Lossy conversion: non-UTF-8 bytes become U+FFFD rather than failing.)
fn cstr_lossy<'a>(p: *const c_char) -> Option<std::borrow::Cow<'a, str>> {
    if p.is_null() {
        return None;
    }
    // SAFETY: caller guarantees `p` is a valid NUL-terminated C string.
    // We never store the pointer or write through it.
    Some(unsafe { CStr::from_ptr(p) }.to_string_lossy())
}

fn into_raw_string(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(e) => {
            // Interior NUL in our own output — should be impossible for
            // JSON; surface it as an error rather than abort.
            set_err(format!("internal: string contained NUL ({e})"));
            ptr::null_mut()
        }
    }
}

/// Run `f`, converting `Err`/panic into `set_err` + `or` fallback.
fn ffi<T>(f: impl FnOnce() -> Result<T, String>, or: T) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => {
            clear_err();
            v
        }
        Ok(Err(e)) => {
            set_err(e);
            or
        }
        Err(_) => {
            set_err("internal panic (input may be malformed; this is a bug)");
            or
        }
    }
}

// ---------------------------------------------------------------------------
// Version / errors
// ---------------------------------------------------------------------------

/// Crate version string — borrowed, do not free.
#[no_mangle]
pub unsafe extern "C" fn sutram_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// Last error message on this thread — borrowed, do not free.
/// NULL when the previous call succeeded.
#[no_mangle]
pub unsafe extern "C" fn sutram_last_error() -> *const c_char {
    LAST_ERROR.with(|e| {
        let b = e.borrow();
        if b.as_bytes().is_empty() {
            ptr::null()
        } else {
            b.as_ptr()
        }
    })
}

// ---------------------------------------------------------------------------
// detect / open / close
// ---------------------------------------------------------------------------

/// Detect the filesystem on `path`; returns a JSON string (free with
/// `sutram_free_string`) or NULL on error.
#[no_mangle]
pub unsafe extern "C" fn sutram_detect(path: *const c_char) -> *mut c_char {
    ffi(
        || {
            let path = cstr_lossy(path).ok_or("path must be a valid C string")?;
            let file = sutram_io::FileSource::open(Path::new(path.as_ref()))
                .map_err(|e| format!("open {path}: {e}"))?;
            Ok(into_raw_string(json::detect_json(&core::detect_all(&file))))
        },
        ptr::null_mut(),
    )
}

/// Open and mount `path` with the best-detected parser.
/// Returns a handle or NULL (see `sutram_last_error`).
#[no_mangle]
pub unsafe extern "C" fn sutram_open_image(path: *const c_char) -> *mut SutramFs {
    // SAFETY: same contract as sutram_open_image_ex — `path` must be a
    // valid C string or NULL.
    unsafe { sutram_open_image_ex(path, ptr::null(), -1) }
}

/// Open `path` with explicit options: `fs_name` = parser short name or
/// NULL for auto-detect; `partition` = 0-based partition index or -1 for
/// the whole image. Returns a handle or NULL.
#[no_mangle]
pub unsafe extern "C" fn sutram_open_image_ex(
    path: *const c_char,
    fs_name: *const c_char,
    partition: i64,
) -> *mut SutramFs {
    ffi(
        || {
            let path = cstr_lossy(path).ok_or("path must be a valid C string")?;
            let name = cstr_lossy(fs_name).map(|s| s.into_owned());
            let part = if partition < 0 {
                None
            } else {
                Some(partition as usize)
            };
            let m = core::open(&path, name.as_deref(), part)?;
            let name_c = CString::new(m.parser_name)
                .map_err(|_| "internal: parser name contained NUL".to_string())?;
            Ok(Box::into_raw(Box::new(SutramFs {
                inner: m,
                name_c,
            })))
        },
        ptr::null_mut(),
    )
}

/// Free a handle from `sutram_open_image*`; NULL-safe.
#[no_mangle]
pub unsafe extern "C" fn sutram_close(fs: *mut SutramFs) {
    if fs.is_null() {
        return;
    }
    // SAFETY: `fs` came from Box::into_raw in sutram_open_image_ex; we own
    // it again and drop it once. Callers must not use it afterwards.
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(fs));
    }));
}

/// Parser name that mounted this image (`"fat"`, `"ntfs"`, …) — borrowed
/// (valid while the handle lives); NULL on NULL input.
#[no_mangle]
pub unsafe extern "C" fn sutram_fs_type(fs: *mut SutramFs) -> *const c_char {
    if fs.is_null() {
        set_err("fs handle is NULL");
        return ptr::null();
    }
    // SAFETY: non-NULL handle from sutram_open_image_ex, still owned by
    // the caller; we only read the CString name.
    unsafe { &*fs }.name_c.as_ptr()
}

/// Volume info as a JSON string (free with `sutram_free_string`).
#[no_mangle]
pub unsafe extern "C" fn sutram_info_json(fs: *mut SutramFs) -> *mut c_char {
    ffi(
        || {
            if fs.is_null() {
                return Err("fs handle is NULL".into());
            }
            // SAFETY: valid owned handle; read-only access.
            let m = unsafe { &*fs };
            Ok(into_raw_string(json::info_json(
                &m.inner.fs.info(),
                m.inner.parser_name,
            )))
        },
        ptr::null_mut(),
    )
}

// ---------------------------------------------------------------------------
// Entry enumeration
// ---------------------------------------------------------------------------

/// Callback for `sutram_list_entries`: invoked once per walked entry with
/// a single-line JSON object (entry) or an `{"error":…}` object (lenient
/// walk errors). The `json` pointer is valid only for the call duration;
/// `user` is the caller's opaque pointer, passed through verbatim.
pub type SutramEntryCb = Option<unsafe extern "C" fn(user: *mut c_void, json: *const c_char)>;

/// Walk all entries (live + deleted + orphans), invoking `cb` once per
/// item. Returns the number of callback invocations, or -1 on error.
#[no_mangle]
pub unsafe extern "C" fn sutram_list_entries(
    fs: *mut SutramFs,
    cb: SutramEntryCb,
    user: *mut c_void,
) -> i64 {
    ffi(
        || {
            if fs.is_null() {
                return Err("fs handle is NULL".into());
            }
            let cb = cb.ok_or("callback must not be NULL")?;
            // SAFETY: valid owned handle; read-only access. `user` is
            // opaque to us — forwarded verbatim, never dereferenced.
            let m = unsafe { &*fs };
            let n = core::for_each_entry(&m.inner, |item| {
                let line = match item {
                    Ok(e) => json::entry_json(e),
                    Err(msg) => json::error_json(&msg),
                };
                let c = match CString::new(line) {
                    Ok(c) => c,
                    Err(_) => CString::new("{\"error\":\"encoding failed\"}").unwrap_or_default(),
                };
                // SAFETY: `c` is a valid NUL-terminated string alive for
                // the duration of the call; the callback contract says
                // the pointer is borrowed.
                unsafe { cb(user, c.as_ptr()) };
            });
            Ok(n as i64)
        },
        -1,
    )
}

/// Buffered variant: returns at most `max_entries` entries as one JSONL
/// string (newline-separated JSON objects), truncated at `max_bytes`
/// output. Free with `sutram_free_string`. NULL on error.
#[no_mangle]
pub unsafe extern "C" fn sutram_list_jsonl(
    fs: *mut SutramFs,
    max_entries: u64,
    max_bytes: u64,
) -> *mut c_char {
    ffi(
        || {
            if fs.is_null() {
                return Err("fs handle is NULL".into());
            }
            // SAFETY: valid owned handle; read-only access.
            let m = unsafe { &*fs };
            let mut out = String::new();
            let mut n = 0u64;
            core::for_each_entry(&m.inner, |item| {
                if n >= max_entries || out.len() as u64 >= max_bytes {
                    return;
                }
                let line = match item {
                    Ok(e) => json::entry_json(e),
                    Err(msg) => json::error_json(&msg),
                };
                out.push_str(&line);
                out.push('\n');
                n += 1;
            });
            Ok(into_raw_string(out))
        },
        ptr::null_mut(),
    )
}

// ---------------------------------------------------------------------------
// File data
// ---------------------------------------------------------------------------

/// Read an entry's content by path. Writes the byte count to
/// `*out_len` (may be less than the file size when `max_bytes` truncates).
/// Returns a buffer freed with `sutram_free_bytes(ptr, len)`, or NULL on
/// error (entry missing, not a file, read failure).
#[no_mangle]
pub unsafe extern "C" fn sutram_read_file(
    fs: *mut SutramFs,
    entry_path: *const c_char,
    max_bytes: u64,
    out_len: *mut u64,
) -> *mut u8 {
    ffi(
        || {
            if fs.is_null() {
                return Err("fs handle is NULL".into());
            }
            if out_len.is_null() {
                return Err("out_len must not be NULL".into());
            }
            let path = cstr_lossy(entry_path).ok_or("entry_path must be a valid C string")?;
            // SAFETY: valid owned handle; read-only access.
            let m = unsafe { &*fs };
            let data = core::read_file_by_path(&m.inner, &path, max_bytes)?;
            // SAFETY: `out_len` checked non-NULL above; caller owns it.
            unsafe { *out_len = data.len() as u64 };
            let boxed = data.into_boxed_slice();
            Ok(Box::into_raw(boxed) as *mut u8)
        },
        ptr::null_mut(),
    )
}

/// Free a buffer from `sutram_read_file`. `len` must be the value written
/// to `out_len`. NULL-safe.
#[no_mangle]
pub unsafe extern "C" fn sutram_free_bytes(p: *mut u8, len: u64) {
    if p.is_null() {
        return;
    }
    // SAFETY: `p` came from Box<[u8]>::into_raw in sutram_read_file with
    // exactly `len` elements — rebuilding the boxed slice is sound.
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(p, len as usize)));
    }));
}

/// Free a string returned by this library (`sutram_detect`,
/// `sutram_info_json`, `sutram_list_jsonl`). NULL-safe.
#[no_mangle]
pub unsafe extern "C" fn sutram_free_string(p: *mut c_char) {
    if p.is_null() {
        return;
    }
    // SAFETY: `p` came from CString::into_raw above; reclaim and drop.
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(CString::from_raw(p));
    }));
}
