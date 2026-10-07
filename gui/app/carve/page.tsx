"use client";

import { useMemo, useState } from "react";
import { useMounts } from "@/lib/mounts";
import { useToast } from "@/lib/toast";
import { useActivity } from "@/lib/activity";
import { fmtBytes, fmtHex } from "@/lib/format";
import type { CarveHit } from "@/lib/types";
import {
  Button, Empty, Err, iconBtn, input, Panel, ProgressBar, select, Spinner,
} from "@/components/ui";
import { Icon } from "@/lib/icons";
import HexView from "@/components/hex-view";

const PARSERS = ["", "fat", "exfat", "ext4", "btrfs", "f2fs", "xfs", "hfs", "ntfs", "apfs"];
const KIND_COLORS = [
  "var(--color-accent)", "var(--color-live)", "var(--color-orphan)",
  "var(--color-accent2)", "var(--color-symlink)", "#4dd0e1", "#f06292", "var(--color-dim)",
];

function HitPreview({ image, hit }: { image: string; hit: CarveHit }) {
  const [bytes, setBytes] = useState<Uint8Array | null>(null);
  const [open, setOpen] = useState(false);
  return (
    <div className="flex items-center gap-1">
      <button
        className={iconBtn}
        title="hex preview"
        onClick={async () => {
          if (!open && !bytes) {
            const r = await fetch(
              `/api/fs/read?path=${encodeURIComponent(image)}&offset=${hit.offset}&len=${Math.min(hit.len, 2048)}`,
            );
            if (r.ok) setBytes(new Uint8Array(await r.arrayBuffer()));
          }
          setOpen((o) => !o);
        }}
      >
        <Icon name="eye" size={12} />
      </button>
      <a
        className={iconBtn}
        title="download carved bytes"
        href={`/api/fs/read?path=${encodeURIComponent(image)}&offset=${hit.offset}&len=${Math.min(hit.len, 8 * 1024 * 1024)}&download=1`}
      >
        <Icon name="download" size={12} />
      </a>
      {open && bytes && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/60" onClick={() => setOpen(false)}>
          <div
            className="mono max-h-[70vh] w-[620px] overflow-auto rounded-lg border border-[var(--color-edge)] bg-[var(--color-panel)] p-3"
            onClick={(e) => e.stopPropagation()}
          >
            <p className="mb-2 text-[11px] text-[var(--color-dim)]">
              {hit.kind} @ {fmtHex(hit.offset)} ({fmtBytes(hit.len)})
            </p>
            <HexView bytes={bytes} />
          </div>
        </div>
      )}
    </div>
  );
}

export default function CarvePage() {
  const { mounts } = useMounts();
  const toast = useToast();
  const { setStatus } = useActivity();
  const images = [...new Set(mounts.map((m) => m.image))];
  const [image, setImage] = useState("");
  const [partition, setPartition] = useState("");
  const [type, setType] = useState("");
  const [mode, setMode] = useState<"unallocated" | "range" | "all">("unallocated");
  const [offset, setOffset] = useState("");
  const [len, setLen] = useState("");
  const [align, setAlign] = useState("512");
  const [hits, setHits] = useState<CarveHit[] | null>(null);
  const [log, setLog] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [kindFilter, setKindFilter] = useState<string | null>(null);

  const run = async () => {
    if (!image.trim()) return;
    setBusy(true);
    setErr(null);
    setHits(null);
    setLog("");
    setKindFilter(null);
    setStatus("carving…");
    try {
      const qs = new URLSearchParams({ image: image.trim() });
      if (partition) qs.set("partition", partition);
      if (type) qs.set("type", type);
      if (mode === "unallocated") qs.set("unallocated", "1");
      if (mode === "range") {
        if (offset) qs.set("offset", offset);
        if (len) qs.set("len", len);
      }
      if (align) qs.set("align", align);
      const res = await fetch(`/api/carve?${qs}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      setHits(data.hits);
      setLog(data.log);
      toast.push(`${data.hits.length} carve hits`, "success");
    } catch (e: any) {
      setErr(e.message);
      toast.push(e.message, "error");
    } finally {
      setBusy(false);
      setStatus("");
    }
  };

  const byKind = useMemo(() => {
    const m = new Map<string, number>();
    for (const h of hits ?? []) m.set(h.kind, (m.get(h.kind) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [hits]);

  const visible = hits ? (kindFilter ? hits.filter((h) => h.kind === kindFilter) : hits) : [];

  const field = (label: string, node: React.ReactNode) => (
    <label className="block">
      <span className="mb-1 block text-[11px] text-[var(--color-faint)]">{label}</span>
      {node}
    </label>
  );

  return (
    <div className="mx-auto max-w-5xl space-y-4 p-4">
      <Panel title="Signature carve">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          <div className="col-span-2 md:col-span-4">
            {field("image", (
              <>
                <input
                  className={`${input} mono`}
                  list="sutram-images"
                  placeholder="/path/to/disk.img"
                  value={image}
                  onChange={(e) => setImage(e.target.value)}
                />
                <datalist id="sutram-images">
                  {images.map((i) => <option key={i} value={i} />)}
                </datalist>
              </>
            ))}
          </div>
          {field("partition #", <input className={input} value={partition} onChange={(e) => setPartition(e.target.value)} placeholder="0-based" />)}
          {field("parser", (
            <select className={`${select} w-full`} value={type} onChange={(e) => setType(e.target.value)}>
              {PARSERS.map((p) => <option key={p} value={p}>{p || "auto"}</option>)}
            </select>
          ))}
          {field("region", (
            <select className={`${select} w-full`} value={mode} onChange={(e) => setMode(e.target.value as any)}>
              <option value="unallocated">unallocated</option>
              <option value="range">byte range</option>
              <option value="all">whole image</option>
            </select>
          ))}
          {field("align", <input className={input} value={align} onChange={(e) => setAlign(e.target.value)} />)}
          {mode === "range" && (
            <>
              {field("offset", <input className={input} value={offset} onChange={(e) => setOffset(e.target.value)} placeholder="0" />)}
              {field("length", <input className={input} value={len} onChange={(e) => setLen(e.target.value)} placeholder="to end" />)}
            </>
          )}
        </div>
        <div className="mt-3 flex items-center gap-3">
          <Button variant="primary" icon="pickaxe" onClick={run} disabled={busy || !image.trim()}>
            {busy ? <Spinner size={12} /> : null} carve
          </Button>
          {log && <span className="mono text-[11px] text-[var(--color-faint)]">{log}</span>}
        </div>
        <Err msg={err} />
      </Panel>

      {hits && byKind.length > 0 && (
        <Panel title="Hit distribution">
          <div className="space-y-1.5">
            {byKind.map(([k, n], i) => (
              <button
                key={k}
                onClick={() => setKindFilter(kindFilter === k ? null : k)}
                className={`flex w-full items-center gap-3 text-left cursor-pointer ${kindFilter && kindFilter !== k ? "opacity-35" : ""}`}
              >
                <span className="mono w-24 truncate text-[11.5px]">{k}</span>
                <ProgressBar value={n} max={byKind[0][1]} color={KIND_COLORS[i % KIND_COLORS.length]} className="flex-1" />
                <span className="w-12 text-right text-[11px] text-[var(--color-dim)]">{n}</span>
              </button>
            ))}
          </div>
        </Panel>
      )}

      {hits && (
        <Panel title={`Hits (${visible.length}${kindFilter ? ` — ${kindFilter}` : ""})`} pad={false}>
          {visible.length === 0 ? (
            <Empty icon="pickaxe" title="no signature hits" hint="try a different region or alignment" />
          ) : (
            <div className="max-h-[50vh] overflow-auto">
              <table className="w-full text-left text-[12px]">
                <thead className="sticky top-0 bg-[var(--color-panel)] text-[var(--color-faint)]">
                  <tr className="border-b border-[var(--color-edge)]">
                    <th className="px-3.5 py-1.5 font-medium">offset</th>
                    <th className="px-1 py-1.5 font-medium text-right">length</th>
                    <th className="px-1 py-1.5 font-medium">signature</th>
                    <th className="w-20 px-1 py-1.5" />
                  </tr>
                </thead>
                <tbody>
                  {visible.slice(0, 2000).map((h, i) => (
                    <tr key={i} className="border-b border-[var(--color-edge)]/40 hover:bg-[var(--color-panel2)]">
                      <td className="mono px-3.5 py-1">{fmtHex(h.offset)}</td>
                      <td className="mono px-1 py-1 text-right">{fmtBytes(h.len)}</td>
                      <td className="px-1 py-1">{h.kind}</td>
                      <td className="px-1 py-0.5"><HitPreview image={image.trim()} hit={h} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      )}
    </div>
  );
}
