/*
 * sutram.h — C API for the SUTRAM-FS forensic filesystem parser family.
 *
 * Link against the `sutram_capi` cdylib (libsutram_capi.{so,dylib,dll}).
 *
 * Ownership rules
 * ---------------
 *   char* / uint8_t* returned by this library → free with
 *     sutram_free_string / sutram_free_bytes (never free(3)).
 *   SutramFs* handles → sutram_close.
 *   const char* marked "borrowed" → never freed by the caller; valid
 *     until the next call on the same thread (sutram_last_error) or
 *     until the owning handle is closed (sutram_fs_type).
 *   Callback `user` pointers are forwarded verbatim, never dereferenced.
 *
 * Error reporting
 * ---------------
 * Functions returning NULL (or -1 for sutram_list_entries) leave a
 * thread-local message readable via sutram_last_error().
 *
 * Thread safety: distinct handles may be used on distinct threads; a
 * single handle must not be shared unsynchronised (the underlying
 * filesystem objects are Send+Sync but walks are stateful).
 */
#ifndef SUTRAM_H
#define SUTRAM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque mounted-filesystem handle. */
typedef struct SutramFs SutramFs;

/** Library version string — borrowed, do not free. */
const char *sutram_version(void);

/**
 * Last error on this thread — borrowed, do not free.
 * NULL when the previous call succeeded. Valid until the next sutram_*
 * call on the same thread.
 */
const char *sutram_last_error(void);

/**
 * Probe all filesystem parsers against `path`.
 * Returns a JSON string (free with sutram_free_string):
 *   {"filesystem":"fat"|null,"confidence":"certain"|null,
 *    "candidates":[["ntfs","none"],["exfat","low"],…]}
 * NULL on error.
 */
char *sutram_detect(const char *path);

/**
 * Open `path` and mount it with the best-detected parser.
 * Equivalent to sutram_open_image_ex(path, NULL, -1).
 * NULL on error.
 */
SutramFs *sutram_open_image(const char *path);

/**
 * Open `path` with explicit options.
 *   fs_name   parser short name ("fat","ntfs","ext4","btrfs","f2fs",
 *             "xfs","hfs","apfs","exfat") or NULL for auto-detect.
 *   partition 0-based partition index, or -1 for the whole image.
 * NULL on error.
 */
SutramFs *sutram_open_image_ex(const char *path,
                               const char *fs_name,
                               int64_t partition);

/** Close a handle from sutram_open_image*. NULL-safe. */
void sutram_close(SutramFs *fs);

/**
 * Short name of the parser that mounted this image — borrowed, valid
 * while `fs` is open. NULL when `fs` is NULL.
 */
const char *sutram_fs_type(SutramFs *fs);

/**
 * Volume info as a JSON string (free with sutram_free_string):
 *   {"parser":…,"fs_type":…,"label":…,"uuid":…,"block_size":…,
 *    "total_blocks":…,"free_blocks":…,"total_nodes":…,"meta":{…}}
 * NULL on error.
 */
char *sutram_info_json(SutramFs *fs);

/**
 * Called once per walked entry with a single-line JSON object:
 *   {"path":…,"name":…,"entry_id":…,"kind":"file"|"directory"|"symlink"|
 *    "other","size":…,"disk_offset":…,"allocated_ranges":[[off,len],…],
 *    "status":"live"|{"deleted":{"recovery":"intact"|"partial"|
 *    "unrecoverable"|"unknown",…}},
 *    "timestamps":{"modified":{"value_ns":…,"raw_value":…,
 *    "raw_encoding":…,"granularity_ns":…}|null,…},
 *    "meta":{…},"magic":{"declared":…,"detected":…,"mismatch":…,
 *    "severity":…,"reasons":[…]}|null}
 * Lenient-mode walk errors arrive as {"error":"…"} objects.
 * `json` is valid only for the duration of the call.
 */
typedef void (*sutram_entry_cb)(void *user, const char *json);

/**
 * Stream all entries (live + deleted + orphans) through `cb`.
 * Returns the number of callback invocations, or -1 on error.
 */
int64_t sutram_list_entries(SutramFs *fs, sutram_entry_cb cb, void *user);

/**
 * Buffered listing: up to `max_entries` entries as newline-separated
 * JSON objects, truncated at `max_bytes` of output. Free the result
 * with sutram_free_string. NULL on error.
 */
char *sutram_list_jsonl(SutramFs *fs, uint64_t max_entries, uint64_t max_bytes);

/**
 * Read an entry's content by path (leading '/' optional).
 * Writes the byte count to *out_len — for deleted entries this is the
 * recoverable extent bytes; for any file it is capped at max_bytes.
 * Returns a buffer freed with sutram_free_bytes(ptr, *out_len), or NULL
 * on error (missing entry, not a file, read failure).
 */
uint8_t *sutram_read_file(SutramFs *fs,
                          const char *entry_path,
                          uint64_t max_bytes,
                          uint64_t *out_len);

/** Free a buffer from sutram_read_file. `len` = the *out_len value. */
void sutram_free_bytes(uint8_t *p, uint64_t len);

/** Free a string returned by this library. NULL-safe. */
void sutram_free_string(char *p);

#ifdef __cplusplus
}
#endif

#endif /* SUTRAM_H */
