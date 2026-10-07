export function fmtBytes(n: number): string {
  if (!Number.isFinite(n)) return "-";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return i === 0 ? `${v} B` : `${v.toFixed(1)} ${units[i]}`;
}

export function fmtTs(nanos: number, has: boolean): string {
  if (!has || !nanos) return "-";
  const ms = nanos / 1e6;
  const d = new Date(ms);
  return d.toISOString().replace("T", " ").replace("Z", "");
}

export function fmtHex(n: number): string {
  return "0x" + n.toString(16);
}

export function statusColor(status: string, recovery: string): string {
  if (status === "deleted") {
    if (recovery === "intact") return "var(--color-orphan)";
    return "var(--color-deleted)";
  }
  return "var(--color-live)";
}

export function statusLabel(status: string, recovery: string): string {
  if (status !== "deleted") return status || "live";
  return recovery ? `deleted/${recovery}` : "deleted";
}

export function isTextPreview(bytes: Uint8Array): boolean {
  const n = Math.min(bytes.length, 512);
  let bad = 0;
  for (let i = 0; i < n; i++) {
    const b = bytes[i];
    if (b === 0) return false;
    if (b < 0x09 || (b > 0x0d && b < 0x20)) bad++;
  }
  return bad / Math.max(n, 1) < 0.05;
}
