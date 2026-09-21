//! # sutram-fsd
//!
//! gRPC daemon (`sutramfsd`) exposing the whole SUTRAM-FS parser family
//! over the network. One service, six calls, mirroring the
//! [`sutram_fs::FsParser`] / [`sutram_fs::FileSystem`] trait surface:
//!
//! ```text
//! Detect(ImageRef)                  -> Detections
//! Mount(ImageRef, MountOptions)     -> MountHandle
//! Walk(MountHandle, filters)        -> stream FsEntryProto
//! Read(MountHandle, path, off, len) -> stream ReadChunk
//! Info(MountHandle)                 -> FsInfoProto
//! Unmount(MountHandle)              -> UnmountReply
//! ```
//!
//! ## Design notes
//!
//! * **Registry** — [`registry()`] returns all nine parsers as
//!   `Box<dyn FsParser>`; `Mount` either honours a client-supplied parser
//!   name or picks the strongest `detect()` confidence.
//! * **Handles** — mounts live in a [`HandleTable`] keyed by opaque ids
//!   with sliding-TTL eviction; a background sweeper (spawned by
//!   [`SutramFsService::spawn_sweeper`]) drops expired mounts.
//! * **Evidence correlation** — request metadata keys `x-evidence-id` and
//!   `x-job-id` are recorded on the mount and echoed in response `meta`
//!   maps (unary calls) and response headers (streaming calls).
//! * **Streaming** — `Walk`/`Read` pump through bounded `mpsc` channels
//!   from blocking worker threads; `Read` chunks are clamped to
//!   [`MAX_READ_CHUNK`].
//!
//! The forensic contract is inherited verbatim from the parser layer:
//! read-only `ByteSource`s, lenient-by-default walks with interleaved
//! error records (`FsEntryProto.error`), full provenance in
//! `disk_offset`/`allocated_ranges`.

#![forbid(unsafe_code)]

/// Generated protobuf/gRPC types (`proto/sutramfs.proto`, package
/// `sutramfs.v1`).
pub mod pb {
    tonic::include_proto!("sutramfs.v1");
}

pub mod convert;
pub mod handles;
pub mod registry;
pub mod service;
pub mod source;

pub use handles::{HandleTable, Mount};
pub use registry::registry;
pub use service::{SutramFsService, DEFAULT_READ_CHUNK, MAX_READ_CHUNK};
