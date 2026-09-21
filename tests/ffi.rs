//! FFI round-trip tests against a synthetic FAT32 image written to a
//! temp directory — exercises the exported C surface exactly as a C
//! consumer would (raw pointers, callbacks, frees).

mod common;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use sutram_capi::ffi::*;

fn image_path() -> PathBuf {
    // Unique file per call: tests run in parallel and each rewrites the
    // image — a shared path would be read mid-write by another test.
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!("sutram-capi-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(format!("fat32-{}.img", N.fetch_add(1, Ordering::SeqCst)));
    std::fs::write(&p, common::build()).unwrap();
    p
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take_string(p: *mut c_char) -> String {
    assert!(!p.is_null());
    let s = CStr::from_ptr(p).to_str().unwrap().to_owned();
    sutram_free_string(p);
    s
}

#[test]
fn version_and_detect() {
    unsafe {
        assert!(!sutram_version().is_null());
        let img = c(image_path().to_str().unwrap());
        let json = take_string(sutram_detect(img.as_ptr()));
        assert!(json.contains("\"filesystem\":\"fat\""), "{json}");
        assert!(json.contains("\"candidates\""), "{json}");
        // Garbage path → NULL + error message.
        let bad = c("/nonexistent/definitely-not-here.img");
        assert!(sutram_detect(bad.as_ptr()).is_null());
        assert!(!sutram_last_error().is_null());
    }
}

#[test]
fn open_info_close() {
    unsafe {
        let img = c(image_path().to_str().unwrap());
        let fs = sutram_open_image(img.as_ptr());
        assert!(!fs.is_null(), "{}", {
            let e = sutram_last_error();
            if e.is_null() {
                "?".into()
            } else {
                CStr::from_ptr(e).to_string_lossy().into_owned()
            }
        });
        assert_eq!(
            CStr::from_ptr(sutram_fs_type(fs)).to_str().unwrap(),
            "fat"
        );
        let info = take_string(sutram_info_json(fs));
        assert!(info.contains("\"fs_type\":\"FAT32\""), "{info}");
        assert!(info.contains("\"label\":\"CAPITEST\""), "{info}");
        sutram_close(fs);
        // NULL close is a no-op.
        sutram_close(std::ptr::null_mut());
    }
}

static CALL_COUNT: AtomicU64 = AtomicU64::new(0);
static SAW_HELLO: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" fn count_cb(_user: *mut c_void, json: *const c_char) {
    CALL_COUNT.fetch_add(1, Ordering::SeqCst);
    let s = CStr::from_ptr(json).to_str().unwrap();
    if s.contains("HELLO.TXT") {
        SAW_HELLO.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn list_entries_callback() {
    unsafe {
        let img = c(image_path().to_str().unwrap());
        let fs = sutram_open_image(img.as_ptr());
        assert!(!fs.is_null());
        CALL_COUNT.store(0, Ordering::SeqCst);
        SAW_HELLO.store(0, Ordering::SeqCst);
        let n = sutram_list_entries(fs, Some(count_cb), std::ptr::null_mut());
        assert!(n >= 3, "expected ≥3 entries, got {n}");
        assert_eq!(n as u64, CALL_COUNT.load(Ordering::SeqCst));
        assert!(SAW_HELLO.load(Ordering::SeqCst) >= 1);
        sutram_close(fs);
    }
}

#[test]
fn list_jsonl_bounded() {
    unsafe {
        let img = c(image_path().to_str().unwrap());
        let fs = sutram_open_image(img.as_ptr());
        assert!(!fs.is_null());
        let jsonl = take_string(sutram_list_jsonl(fs, 1_000_000, 1 << 20));
        assert!(jsonl.contains("\"path\":\"/HELLO.TXT\""), "{jsonl}");
        assert!(jsonl.contains("\"status\":\"live\""), "{jsonl}");
        assert!(jsonl.contains("deleted"), "{jsonl}"); // _OLD.TXT
        // Bounded: max_entries=1 → exactly one line.
        let one = take_string(sutram_list_jsonl(fs, 1, 1 << 20));
        assert_eq!(one.lines().count(), 1);
        sutram_close(fs);
    }
}

#[test]
fn read_file_round_trip() {
    unsafe {
        let img = c(image_path().to_str().unwrap());
        let fs = sutram_open_image(img.as_ptr());
        assert!(!fs.is_null());
        let mut len: u64 = 0;
        let p = c("/HELLO.TXT");
        let buf = sutram_read_file(fs, p.as_ptr(), 1 << 20, &mut len);
        assert!(!buf.is_null(), "{}", {
            let e = sutram_last_error();
            if e.is_null() {
                "?".into()
            } else {
                CStr::from_ptr(e).to_string_lossy().into_owned()
            }
        });
        assert_eq!(len, 12);
        let data = std::slice::from_raw_parts(buf, len as usize);
        assert_eq!(data, b"hello world!");
        sutram_free_bytes(buf, len);

        // Nested path.
        let p = c("SUBDIR/INNER.TXT");
        let mut len2: u64 = 0;
        let buf2 = sutram_read_file(fs, p.as_ptr(), 1 << 20, &mut len2);
        assert!(!buf2.is_null());
        assert_eq!(std::slice::from_raw_parts(buf2, len2 as usize), b"NEST");
        sutram_free_bytes(buf2, len2);

        // Missing path → NULL + error.
        let p = c("/NOPE.BIN");
        let mut len3: u64 = 0;
        assert!(sutram_read_file(fs, p.as_ptr(), 1 << 20, &mut len3).is_null());
        assert!(!sutram_last_error().is_null());
        sutram_close(fs);
    }
}

#[test]
fn null_safety() {
    unsafe {
        // Every entry point tolerates NULLs without UB/panic.
        assert!(sutram_detect(std::ptr::null()).is_null());
        assert!(sutram_open_image(std::ptr::null()).is_null());
        assert!(sutram_open_image_ex(std::ptr::null(), std::ptr::null(), -1).is_null());
        assert!(sutram_fs_type(std::ptr::null_mut()).is_null());
        assert!(sutram_info_json(std::ptr::null_mut()).is_null());
        assert_eq!(
            sutram_list_entries(std::ptr::null_mut(), Some(count_cb), std::ptr::null_mut()),
            -1
        );
        assert_eq!(
            sutram_list_entries(std::ptr::null_mut(), None, std::ptr::null_mut()),
            -1
        );
        assert!(sutram_list_jsonl(std::ptr::null_mut(), 10, 10).is_null());
        let mut len = 0u64;
        assert!(sutram_read_file(
            std::ptr::null_mut(),
            std::ptr::null(),
            0,
            &mut len
        )
        .is_null());
        sutram_free_bytes(std::ptr::null_mut(), 0);
        sutram_free_string(std::ptr::null_mut());
    }
}
