// Convert proto-loader messages (uint64 as strings, defaults present) into the
// plain-JSON types the client consumes.

import { u64 } from "./grpc";
import type { FsEntry, FsInfo, MountInfo, TimestampVal, Timestamps } from "./types";

function ts(v: any): TimestampVal {
  return {
    has_value: !!v?.has_value,
    unix_nanos: u64(v?.unix_nanos),
    raw_value: u64(v?.raw_value),
    raw_encoding: v?.raw_encoding ?? "",
    granularity_nanos: u64(v?.granularity_nanos),
  };
}

function timestamps(v: any): Timestamps {
  return {
    modified: ts(v?.modified),
    accessed: ts(v?.accessed),
    created: ts(v?.created),
    changed: ts(v?.changed),
    deleted: ts(v?.deleted),
  };
}

export function convertEntry(e: any): FsEntry {
  return {
    path: e.path ?? "",
    name: e.name ?? "",
    entry_id: u64(e.entry_id),
    kind: e.kind ?? "other",
    size: u64(e.size),
    disk_offset: u64(e.disk_offset),
    allocated_ranges: (e.allocated_ranges ?? []).map((r: any) => ({
      offset: u64(r.offset),
      len: u64(r.len),
    })),
    timestamps: timestamps(e.timestamps),
    status: e.status ?? "",
    recovery: e.recovery ?? "",
    recovered_bytes: u64(e.recovered_bytes),
    total_bytes: u64(e.total_bytes),
    meta: e.meta ?? {},
    magic: {
      present: !!e.magic?.present,
      declared: e.magic?.declared ?? "",
      detected: e.magic?.detected ?? "",
      mismatch: !!e.magic?.mismatch,
      severity: e.magic?.severity ?? "info",
      reasons: e.magic?.reasons ?? [],
    },
    error: e.error ?? "",
  };
}

export function convertInfo(i: any): FsInfo {
  return {
    fs_type: i.fs_type ?? "",
    label: i.label ?? "",
    uuid: i.uuid ?? "",
    block_size: u64(i.block_size),
    total_blocks: u64(i.total_blocks),
    free_blocks: i.has_free_blocks ? u64(i.free_blocks) : null,
    total_nodes: i.has_total_nodes ? u64(i.total_nodes) : null,
    fs_meta: i.fs_meta ?? {},
  };
}

export function convertMount(h: any): Omit<MountInfo, "image" | "offset" | "length"> {
  return {
    id: h.id ?? "",
    parser: h.parser ?? "",
    fs_type: h.fs_type ?? "",
    expires_at_unix: u64(h.expires_at_unix),
  };
}
