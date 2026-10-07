"use client";

import { Suspense, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { streamNdjson } from "@/lib/api";
import { useMounts } from "@/lib/mounts";
import { useActivity } from "@/lib/activity";
import { fmtBytes, fmtTs } from "@/lib/format";
import type { FsEntry } from "@/lib/types";
import { Badge, Button, Empty, Err, Panel, ProgressBar, Spinner } from "@/components/ui";
import { Icon } from "@/lib/icons";
import MountPicker from "@/components/mount-picker";

function ReportInner() {
  const params = useSearchParams();
  const { get } = useMounts();
  const { setStatus } = useActivity();
  const [mount, setMount] = useState(params.get("m") ?? "");
  const [entries, setEntries] = useState<FsEntry[]>([]);
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const run = async () => {
    if (!mount) return;
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setEntries([]);
    setErr(null);
    setRunning(true);
    try {
      await streamNdjson(`/api/walk?handle=${encodeURIComponent(mount)}`, {
        signal: ac.signal,
        onEntry: (e) => setEntries((p) => [...p, e]),
        onError: setErr,
      });
    } catch (e: any) {
      if (e.name !== "AbortError") setErr(e.message);
    } finally {
      setRunning(false);
      setStatus("");
    }
  };

  const m = mount ? get(mount) : undefined;

  const stats = useMemo(() => {
    const s = {
      total: entries.length,
      live: 0,
      deleted: 0,
      errors: 0,
      files: 0,
      dirs: 0,
      symlinks: 0,
      bytes: 0,
      recoverable: 0,
      magicMismatches: [] as FsEntry[],
      byRecovery: {} as Record<string, number>,
      bySeverity: {} as Record<string, number>,
      minTs: Infinity,
      maxTs: 0,
    };
    for (const e of entries) {
      if (e.error) {
        s.errors++;
        continue;
      }
      if (e.status === "deleted") {
        s.deleted++;
        s.byRecovery[e.recovery || "unknown"] =
          (s.byRecovery[e.recovery || "unknown"] || 0) + 1;
        s.recoverable += e.recovered_bytes || 0;
      } else s.live++;
      if (e.kind === "file") {
        s.files++;
        s.bytes += e.size;
      } else if (e.kind === "directory") s.dirs++;
      else if (e.kind === "symlink") s.symlinks++;
      if (e.magic.mismatch) {
        s.magicMismatches.push(e);
        s.bySeverity[e.magic.severity || "info"] =
          (s.bySeverity[e.magic.severity || "info"] || 0) + 1;
      }
      for (const t of Object.values(e.timestamps)) {
        if (t?.has_value && t.unix_nanos > 0) {
          if (t.unix_nanos < s.minTs) s.minTs = t.unix_nanos;
          if (t.unix_nanos > s.maxTs) s.maxTs = t.unix_nanos;
        }
      }
    }
    return s;
  }, [entries]);

  const row = (k: string, v: React.ReactNode) => (
    <tr>
      <td className="py-1 pr-6 text-[var(--color-dim)]">{k}</td>
      <td className="mono">{v}</td>
    </tr>
  );

  return (
    <div className="mx-auto max-w-4xl space-y-4 p-4">
      <Panel title="Generate report" className="no-print">
        <div className="flex items-center gap-2">
          <MountPicker value={mount} onChange={setMount} />
          {running ? (
            <Button icon="stop" onClick={() => abortRef.current?.abort()}>stop</Button>
          ) : (
            <Button variant="primary" icon="file-text" onClick={run} disabled={!mount}>
              generate
            </Button>
          )}
          {entries.length > 0 && (
            <Button icon="export" onClick={() => window.print()}>print / pdf</Button>
          )}
        </div>
        <Err msg={err} />
      </Panel>

      {running && entries.length === 0 && (
        <div className="flex items-center gap-2 p-6 text-[var(--color-dim)]">
          <Spinner /> collecting census…
        </div>
      )}

      {entries.length > 0 && m && (
        <div className="space-y-4">
          <div className="rounded-lg border border-[var(--color-edge)] bg-[var(--color-panel)] p-5">
            <div className="flex items-center gap-3">
              <Icon name="shield" size={22} className="text-[var(--color-accent)]" />
              <div>
                <h1 className="text-[16px] font-bold">SUTRAM-FS evidence summary</h1>
                <p className="mono text-[11px] text-[var(--color-dim)]">
                  {new Date().toISOString()}
                </p>
              </div>
            </div>
          </div>

          <Panel title="Acquisition">
            <table className="text-[12.5px]"><tbody>
              {row("image", m.image)}
              {row("window", `offset ${m.offset}, length ${m.length || "to end"}`)}
              {row("filesystem", `${m.fs_type} (parser: ${m.parser})`)}
              {row("mount id", m.id)}
            </tbody></table>
          </Panel>

          <Panel title="Census">
            <div className="mb-3 flex flex-wrap gap-1.5">
              <Badge color="var(--color-accent)">{stats.total} entries</Badge>
              <Badge color="var(--color-live)">{stats.live} live</Badge>
              <Badge color="var(--color-deleted)">{stats.deleted} deleted</Badge>
              {stats.errors > 0 && <Badge color="var(--color-warn)">{stats.errors} error records</Badge>}
            </div>
            <table className="text-[12.5px]"><tbody>
              {row("files / dirs / symlinks", `${stats.files} / ${stats.dirs} / ${stats.symlinks}`)}
              {row("logical file bytes", fmtBytes(stats.bytes))}
              {row("recoverable deleted bytes", fmtBytes(stats.recoverable))}
              {row("timestamp span", stats.minTs !== Infinity ? `${fmtTs(stats.minTs, true)} → ${fmtTs(stats.maxTs, true)}` : "-")}
            </tbody></table>
          </Panel>

          {stats.deleted > 0 && (
            <Panel title="Recovery states">
              <div className="space-y-1.5">
                {Object.entries(stats.byRecovery).map(([k, v]) => (
                  <div key={k} className="flex items-center gap-3">
                    <span className="w-40 text-[11.5px]">{k}</span>
                    <ProgressBar
                      value={v}
                      max={stats.deleted}
                      color={k === "intact" ? "var(--color-orphan)" : "var(--color-deleted)"}
                      className="flex-1"
                    />
                    <span className="w-12 text-right text-[11px] text-[var(--color-dim)]">{v}</span>
                  </div>
                ))}
              </div>
            </Panel>
          )}

          {stats.magicMismatches.length > 0 && (
            <Panel title={`Extension↔magic mismatches (${stats.magicMismatches.length})`} pad={false}>
              <div className="flex gap-1.5 px-3.5 py-2">
                {Object.entries(stats.bySeverity).map(([k, v]) => (
                  <Badge key={k} color={k === "high" ? "var(--color-deleted)" : "var(--color-warn)"}>
                    {k}: {v}
                  </Badge>
                ))}
              </div>
              <table className="w-full text-left text-[12px]">
                <thead className="text-[var(--color-faint)]">
                  <tr className="border-t border-[var(--color-edge)]">
                    <th className="px-3.5 py-1.5 font-medium">path</th>
                    <th className="px-1 py-1.5 font-medium">declared</th>
                    <th className="px-1 py-1.5 font-medium">detected</th>
                    <th className="w-24 px-1 py-1.5 font-medium">severity</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.magicMismatches.slice(0, 500).map((e, i) => (
                    <tr key={i} className="border-t border-[var(--color-edge)]/40">
                      <td className="mono max-w-0 truncate px-3.5 py-1" title={e.path}>{e.path}</td>
                      <td className="px-1 py-1">{e.magic.declared}</td>
                      <td className="px-1 py-1">{e.magic.detected}</td>
                      <td
                        className="px-1 py-1"
                        style={{ color: e.magic.severity === "high" ? "var(--color-deleted)" : "var(--color-warn)" }}
                      >
                        {e.magic.severity}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          )}
        </div>
      )}

      {!running && entries.length === 0 && (
        <Empty icon="file-text" title="no report yet" hint="select a mount and generate" />
      )}
    </div>
  );
}

export default function ReportPage() {
  return (
    <Suspense>
      <ReportInner />
    </Suspense>
  );
}
