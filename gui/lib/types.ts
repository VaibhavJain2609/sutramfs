// Shared types between API routes and client components.
// Field names mirror proto/sutramfs.proto (snake_case).

export interface Detection {
  parser: string;
  confidence: string; // "none" | "low" | "medium" | "high" | "certain"
}

export interface MountInfo {
  id: string;
  parser: string;
  fs_type: string;
  expires_at_unix: number;
  image: string; // server-local path the mount was opened from (client-side echo)
  offset: number;
  length: number;
  label?: string;
}

export interface FsInfo {
  fs_type: string;
  label: string;
  uuid: string;
  block_size: number;
  total_blocks: number;
  free_blocks: number | null;
  total_nodes: number | null;
  fs_meta: Record<string, string>;
}

export interface TimestampVal {
  has_value: boolean;
  unix_nanos: number;
  raw_value: number;
  raw_encoding: string;
  granularity_nanos: number;
}

export interface Timestamps {
  modified: TimestampVal;
  accessed: TimestampVal;
  created: TimestampVal;
  changed: TimestampVal;
  deleted: TimestampVal;
}

export interface MagicVerdict {
  present: boolean;
  declared: string;
  detected: string;
  mismatch: boolean;
  severity: string; // "info" | "suspicious" | "high"
  reasons: string[];
}

export interface Range {
  offset: number;
  len: number;
}

export interface FsEntry {
  path: string;
  name: string;
  entry_id: number;
  kind: string; // "file" | "directory" | "symlink" | "other"
  size: number;
  disk_offset: number;
  allocated_ranges: Range[];
  timestamps: Timestamps;
  status: string; // "live" | "deleted"
  recovery: string; // "" | "intact" | "partially_overwritten" | "unrecoverable" | "unknown"
  recovered_bytes: number;
  total_bytes: number;
  meta: Record<string, string>;
  magic: MagicVerdict;
  error: string;
  mount?: string; // client-side: mount handle id this entry was walked from
}

export interface Partition {
  index: number;
  offset: number;
  size: number;
  table: string; // "Mbr" | "Gpt" | ...
  kind: string; // type GUID or MBR type hex
  label: string;
}

export interface AndroidPartition {
  name: string;
  size: number;
  role: string;
  group: string;
  readonly: boolean;
}

export interface AndroidLayout {
  container: string;
  crypto: { kind: string; partition: string; note: string }[];
  partitions: AndroidPartition[];
  warnings: string[];
}

export interface CarveHit {
  offset: number;
  len: number;
  kind: string;
}
