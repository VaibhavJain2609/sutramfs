"use client";

import { useMemo, useRef, useState } from "react";
import { streamNdjson } from "@/lib/api";
import { useMounts } from "@/lib/mounts";
import { useToast } from "@/lib/toast";
import { useActivity } from "@/lib/activity";
import { fmtHex } from "@/lib/format";
import {
  Badge, btn, Button, Empty, Err, input, Panel, ProgressBar, Spinner, Toggle,
} from "@/components/ui";
import { Icon } from "@/lib/icons";

// NTFS dead-filesystem recovery: scan for orphaned FILE/INDX records
// (`sutramfs remnants`), then build a restore plan (`sutramfs rebuild`).

export default function RecoveryPage() {
  const { mounts } = useMounts();
  const toast = useToast();
  const { setStatus } = useActivity();
  const images = [...new Set(mounts.map((m) => m.image))];
  const [image, setImage] = useState("");
  const [offset, setOffset] = useState("");
  const [len, setLen] = useState("");
  const [alignedOnly, setAlignedOnly] = useState(false);
  const [excludeLive, setExcludeLive] = useState(true);
  const [under, setUnder] = useState("");

  const [scanning, setScanning] = useState(false);
  const [scanErr, setScanErr] = useState<string | null>(null);
  const [scanLog, setScanLog] = useState<string[]>([]);
  const [remnants, setRemnants] = useState<any[]>([]);
  const remnantsRef = useRef<string[]>([]);
  const abortRef = useRef<AbortController | null>(null);
  const logRef = useRef<HTMLDivElement>(null);

  const [rebuilding, setRebuilding] = useState(false);
  const [plan, setPlan] = useState<any[] | null>(null);
  const [rebuildErr, setRebuildErr] = useState<string | null>(null);
  const [rebuildLog, setRebuildLog] = useState("");

  const pushLog = (l: string) => {
    setScanLog((p) => [...p.slice(-300), l]);
    requestAnimationFrame(() => {
      logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
    });
  };

  const scan = async () => {
    if (!image.trim()) return;
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setScanning(true);
    setScanErr(null);
    setScanLog([]);
    setRemnants([]);
    setPlan(null);
    remnantsRef.current = [];
    setStatus("scanning for NTFS remnants…");
    try {
      const qs = new URLSearchParams({ image: image.trim() });
      if (offset) qs.set("offset", offset);
      if (len) qs.set("len", len);
      if (alignedOnly) qs.set("aligned_only", "1");
      if (excludeLive) qs.set("exclude_live_mft", "1");
      const lines: any[] = [];
      await streamNdjson(`/api/remnants?${qs}`, {
        signal: ac.signal,
        onEntry: (e) => {
          remnantsRef.current.push(JSON.stringify(e));
          lines.push(e);
          if (lines.length % 20 === 0) setRemnants([...lines]);
        },
        onLog: pushLog,
        onError: setScanErr,
        onDone: (code) => pushLog(`-- scan finished (exit ${code})`),
      });
      setRemnants(lines);
      toast.push(`${lines.length} remnant records`, "success");
    } catch (e: any) {
      if (e.name !== "AbortError") {
        setScanErr(e.message);
        toast.push(e.message, "error");
      }
    } finally {
      setScanning(false);
      setStatus("");
    }
  };

  const rebuild = async () => {
    if (!image.trim()) return;
    setRebuilding(true);
    setRebuildErr(null);
    setPlan(null);
    setRebuildLog("");
    setStatus("rebuilding tree…");
    try {
      const res = await fetch("/api/rebuild", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          image: image.trim(),
          offset: offset || undefined,
          len: len || undefined,
          under: under || undefined,
          remnantsJsonl:
            remnantsRef.current.length > 0
              ? remnantsRef.current.join("\n")
              : undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      setPlan(data.plan);
      setRebuildLog(data.log);
      toast.push(`${data.plan.length} plan rows`, "success");
    } catch (e: any) {
      setRebuildErr(e.message);
      toast.push(e.message, "error");
    } finally {
      setRebuilding(false);
      setStatus("");
    }
  };

  const byKind = useMemo(() => {
    const m = new Map<string, number>();
    for (const r of remnants) {
      const k = r.kind ?? r.record_type ?? "unknown";
      m.set(k, (m.get(k) ?? 0) + 1);
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [remnants]);

  const planCols = plan
    ? [...new Set(plan.flatMap((r) => Object.keys(r)))].filter((k) => k !== "raw")
    : [];

  const exportPlan = () => {
    if (!plan) return;
    const url = URL.createObjectURL(
      new Blob([plan.map((r) => JSON.stringify(r)).join("\n")], { type: "application/json" }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = "sutramfs-restore-plan.jsonl";
    a.click();
    URL.revokeObjectURL(url);
  };

  const field = (label: string, node: React.ReactNode) => (
    <label className="block">
      <span className="mb-1 block text-[11px] text-[var(--color-faint)]">{label}</span>
      {node}
    </label>
  );

  return (
    <div className="mx-auto max-w-6xl space-y-4 p-4">
      <Panel title="NTFS remnants scan">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          <div className="col-span-2 md:col-span-4">
            {field("image", (
              <>
                <input className={`${input} mono`} list="sutram-images" placeholder="/path/to/disk.img"
                  value={image} onChange={(e) => setImage(e.target.value)} />
                <datalist id="sutram-images">
                  {images.map((i) => <option key={i} value={i} />)}
                </datalist>
              </>
            ))}
          </div>
          {field("offset", <input className={input} value={offset} onChange={(e) => setOffset(e.target.value)} placeholder="0" />)}
          {field("length", <input className={input} value={len} onChange={(e) => setLen(e.target.value)} placeholder="to end" />)}
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-2">
          <Toggle checked={alignedOnly} onChange={setAlignedOnly} label="aligned records only" />
          <Toggle checked={excludeLive} onChange={setExcludeLive} label="exclude live $MFT" />
          <span className="flex-1" />
          {scanning ? (
            <Button icon="stop" onClick={() => abortRef.current?.abort()}>stop</Button>
          ) : (
            <Button variant="primary" icon="search" onClick={scan} disabled={!image.trim()}>
              scan
            </Button>
          )}
        </div>
        <Err msg={scanErr} />
        {scanLog.length > 0 && (
          <div
            ref={logRef}
            className="mono mt-3 max-h-36 overflow-auto rounded-md border border-[var(--color-edge)] bg-[var(--color-bg)] p-2 text-[11px] text-[var(--color-dim)]"
          >
            {scanLog.map((l, i) => <div key={i}>{l}</div>)}
            {scanning && <div className="text-[var(--color-accent)]">▌</div>}
          </div>
        )}
      </Panel>

      {remnants.length > 0 && (
        <Panel
          title={`Remnants (${remnants.length})`}
          right={
            <div className="flex items-center gap-2">
              {byKind.map(([k, n]) => (
                <Badge key={k}>{k}: {n}</Badge>
              ))}
            </div>
          }
          pad={false}
        >
          <div className="max-h-64 overflow-auto">
            <table className="w-full text-left text-[12px]">
              <thead className="sticky top-0 bg-[var(--color-panel)] text-[var(--color-faint)]">
                <tr className="border-b border-[var(--color-edge)]">
                  <th className="px-3.5 py-1.5 font-medium">offset</th>
                  <th className="px-1 py-1.5 font-medium">kind</th>
                  <th className="px-1 py-1.5 font-medium">name / path</th>
                </tr>
              </thead>
              <tbody>
                {remnants.slice(0, 2000).map((r, i) => (
                  <tr key={i} className="border-b border-[var(--color-edge)]/40 hover:bg-[var(--color-panel2)]">
                    <td className="mono px-3.5 py-1">
                      {r.offset !== undefined ? fmtHex(Number(r.offset)) : "-"}
                    </td>
                    <td className="px-1 py-1">{r.kind ?? r.record_type ?? "-"}</td>
                    <td className="mono max-w-0 truncate px-1 py-1" title={r.path ?? r.name ?? ""}>
                      {r.path ?? r.name ?? "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {remnants.length > 2000 && (
              <p className="p-2 text-[11px] text-[var(--color-faint)]">
                …and {(remnants.length - 2000).toLocaleString()} more
              </p>
            )}
          </div>
        </Panel>
      )}

      <Panel title="Restore plan">
        <div className="flex flex-wrap items-end gap-3">
          {field("rebuild under", (
            <input className={`${input} w-64 mono`} value={under} onChange={(e) => setUnder(e.target.value)} placeholder="/" />
          ))}
          <Button
            variant="primary" icon="recycle"
            onClick={rebuild}
            disabled={rebuilding || !image.trim()}
          >
            {rebuilding ? <Spinner size={12} /> : null}
            {remnants.length ? "rebuild from scan" : "rebuild (fresh scan)"}
          </Button>
          {plan && (
            <Button icon="export" onClick={exportPlan}>export jsonl</Button>
          )}
        </div>
        <Err msg={rebuildErr} />
        {rebuildLog && (
          <pre className="mono mt-2 text-[11px] text-[var(--color-dim)]">{rebuildLog}</pre>
        )}
        {plan && (
          <div className="mt-3 max-h-96 overflow-auto rounded-md border border-[var(--color-edge)]">
            {planCols.length > 0 ? (
              <table className="w-full text-left text-[12px]">
                <thead className="sticky top-0 bg-[var(--color-panel2)] text-[var(--color-faint)]">
                  <tr>
                    {planCols.map((c) => (
                      <th key={c} className="px-2 py-1.5 font-medium">{c}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {plan.slice(0, 2000).map((r, i) => (
                    <tr key={i} className="border-t border-[var(--color-edge)]/40">
                      {planCols.map((c) => (
                        <td key={c} className="mono max-w-0 truncate px-2 py-1" title={String(r[c] ?? "")}>
                          {typeof r[c] === "object" ? JSON.stringify(r[c]) : String(r[c] ?? "")}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <pre className="mono whitespace-pre-wrap p-3 text-[11px]">
                {JSON.stringify(plan.slice(0, 50), null, 2)}
              </pre>
            )}
          </div>
        )}
        {plan && plan.length === 0 && (
          <Empty icon="recycle" title="empty plan" hint="no reconstructible directories found" />
        )}
      </Panel>
    </div>
  );
}
