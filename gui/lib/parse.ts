// Parsers for the sutramfs CLI's human-readable output. The CLI has no JSON
// mode for parts/android/carve, so we parse its fixed println! formats from
// sutram-cli/src/main.rs. If the CLI format changes, update the regexes here.

import type { AndroidLayout, CarveHit, Partition } from "./types";

// `#{:<2} {:>12} {:>12} {:<8} {} {}` — index, offset, size, table, kind, label
const PART_RE = /^#(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s*(.*)$/;

export function parseParts(stdout: string): Partition[] {
  const parts: Partition[] = [];
  for (const line of stdout.split("\n")) {
    const m = PART_RE.exec(line.trim());
    if (!m) continue;
    parts.push({
      index: Number(m[1]),
      offset: Number(m[2]),
      size: Number(m[3]),
      table: m[4],
      kind: m[5],
      label: m[6].trim(),
    });
  }
  return parts;
}

// container: {:?}
// crypto:    {:?} {} — {}
// {:<20} {:>10} bytes  role={:?} group={} {ro?}
// warning:   {}
const AND_PART_RE = /^(\S+)\s+(\d+) bytes\s+role=(\S+)\s+group=(\S+)\s*(.*)$/;

export function parseAndroid(stdout: string): AndroidLayout {
  const layout: AndroidLayout = {
    container: "",
    crypto: [],
    partitions: [],
    warnings: [],
  };
  for (const line of stdout.split("\n")) {
    const l = line.trimEnd();
    if (l.startsWith("container:")) {
      layout.container = l.slice("container:".length).trim();
    } else if (l.startsWith("crypto:")) {
      const rest = l.slice("crypto:".length).trim();
      const m = /^(\S+)\s+(\S+)\s+—\s+(.*)$/.exec(rest);
      if (m)
        layout.crypto.push({ kind: m[1], partition: m[2], note: m[3].trim() });
    } else if (l.startsWith("warning:")) {
      layout.warnings.push(l.slice("warning:".length).trim());
    } else {
      const m = AND_PART_RE.exec(l.trim());
      if (m) {
        layout.partitions.push({
          name: m[1],
          size: Number(m[2]),
          role: m[3],
          group: m[4],
          readonly: m[5].includes("ro"),
        });
      }
    }
  }
  return layout;
}

// `{:#x}  {:>8}  {:?}` — hex offset, len, kind debug
const CARVE_RE = /^(0x[0-9a-fA-F]+)\s+(\d+)\s+(.+)$/;

export function parseCarve(stdout: string): CarveHit[] {
  const hits: CarveHit[] = [];
  for (const line of stdout.split("\n")) {
    const m = CARVE_RE.exec(line.trim());
    if (!m) continue;
    hits.push({
      offset: parseInt(m[1], 16),
      len: Number(m[2]),
      kind: m[3].trim(),
    });
  }
  return hits;
}
