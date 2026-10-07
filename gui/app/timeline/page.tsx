"use client";

import { Suspense, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { streamNdjson } from "@/lib/api";
import { useMounts } from "@/lib/mounts";
import { useActivity } from "@/lib/activity";
import { fmtTs } from "@/lib/format";
import { Button, Empty, Err, input, Panel, select, Spinner } from "@/components/ui";
import { Icon } from "@/lib/icons";
import MountPicker from "@/components/mount-picker";

interface Event {
  nanos: number;
  type: string;
  path: string;
  status: string;
}

const TYPES = ["created", "modified", "accessed", "changed", "deleted"] as const;
const TYPE_COLOR: Record<string, string> = {
  created: "var(--color-live)",
  modified: "var(--color-accent)",
  accessed: "var(--color-dim)",
  changed: "var(--color-accent2)",
  deleted: "var(--color-deleted)",
};

const PAGE = 1000;

function TimelineInner() {
  const params = useSearchParams();
  const router = useRouter();
  const { mounts } = useMounts();
  const { setStatus } = useActivity();
  const [mount, setMount] = useState(params.get("m") ?? "");
  const [events, setEvents] = useState<Event[]>([]);
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [enabled, setEnabled] = useState<Set<string>>(new Set(TYPES));
  const [textFilter, setTextFilter] = useState("");
  const [range, setRange] = useState<[number, number] | null>(null);
  const [shown, setShown] = useState(PAGE);
  const abortRef = useRef<AbortController | null>(null);

  const run = async () => {
    if (!mount) return;
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setEvents([]);
    setErr(null);
    setRange(null);
    setShown(PAGE);
    setRunning(true);
    try {
      let n = 0;
      await streamNdjson(`/api/walk?handle=${encodeURIComponent(mount)}`, {
        signal: ac.signal,
        onEntry: (e) => {
          const evs: Event[] = [];
          for (const t of TYPES) {
            const ts = e.timestamps[t];
            if (ts?.has_value && ts.unix_nanos > 0)
              evs.push({ nanos: ts.unix_nanos, type: t, path: e.path, status: e.status });
          }
          n++;
          if (n % 25 === 0) setStatus(`scanning… ${n.toLocaleString()} entries`);
          if (evs.length) setEvents((prev) => [...prev, ...evs]);
        },
        onError: setErr,
      });
    } catch (e: any) {
      if (e.name !== "AbortError") setErr(e.message);
    } finally {
      setRunning(false);
      setStatus("");
    }
  };

  const filtered = useMemo(() => {
    const f = textFilter.toLowerCase();
    return events
      .filter(
        (e) =>
          enabled.has(e.type) &&
          (!f || e.path.toLowerCase().includes(f)) &&
          (!range || (e.nanos >= range[0] && e.nanos < range[1])),
      )
      .sort((a, b) => a.nanos - b.nanos);
  }, [events, enabled, textFilter, range]);

  const buckets = useMemo(() => {
    if (!events.length) return [];
    const sorted = [...events].sort((a, b) => a.nanos - b.nanos);
    const min = sorted[0].nanos;
    const max = sorted[sorted.length - 1].nanos;
    const span = Math.max(max - min, 1);
    const N = Math.min(120, Math.max(20, Math.floor(Math.sqrt(events.length))));
    const size = Math.ceil(span / N);
    const counts = new Array(N).fill(0);
    for (const e of sorted) counts[Math.min(N - 1, Math.floor((e.nanos - min) / size))]++;
    const peak = Math.max(...counts, 1);
    return counts.map((c, i) => ({
      count: c,
      start: min + i * size,
      end: min + (i + 1) * size,
      pct: (c / peak) * 100,
    }));
  }, [events]);

  const exportCsv = () => {
    const csv =
      "time_utc,event,status,path\n" +
      filtered
        .map(
          (e) =>
            `${new Date(e.nanos / 1e6).toISOString()},${e.type},${e.status},"${e.path.replace(/"/g, '""')}"`,
        )
        .join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "sutramfs-timeline.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  const visible = filtered.slice(0, shown);

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-[var(--color-edge)] bg-[var(--color-panel)] px-3 py-2">
        <MountPicker value={mount} onChange={setMount} />
        {running ? (
          <Button icon="stop" onClick={() => abortRef.current?.abort()}>stop</Button>
        ) : (
          <Button variant="primary" icon="activity" onClick={run} disabled={!mount}>
            build timeline
          </Button>
        )}
        <div className="flex items-center gap-1">
          {TYPES.map((t) => (
            <button
              key={t}
              onClick={() => {
                const next = new Set(enabled);
                next.has(t) ? next.delete(t) : next.add(t);
                setEnabled(next);
              }}
              className={`rounded border px-1.5 py-0.5 text-[10.5px] capitalize cursor-pointer transition-opacity ${
                enabled.has(t) ? "opacity-100" : "opacity-35"
              }`}
              style={{ color: TYPE_COLOR[t], borderColor: "var(--color-edge)" }}
            >
              {t}
            </button>
          ))}
        </div>
        <input
          className={`${input} w-44`}
          placeholder="filter paths…"
          value={textFilter}
          onChange={(e) => setTextFilter(e.target.value)}
        />
        {range && (
          <Button variant="ghost" icon="x" onClick={() => setRange(null)}>
            clear range
          </Button>
        )}
        <span className="ml-auto text-[11px] text-[var(--color-dim)]">
          {filtered.length.toLocaleString()} events
        </span>
        {filtered.length > 0 && (
          <Button icon="export" onClick={exportCsv}>csv</Button>
        )}
      </div>
      <Err msg={err} />

      {buckets.length > 0 && (
        <div className="border-b border-[var(--color-edge)] bg-[var(--color-panel)] px-3 py-2">
          <div className="flex h-16 items-end gap-px">
            {buckets.map((b, i) => (
              <button
                key={i}
                title={`${fmtTs(b.start, true)} — ${b.count} events`}
                onClick={() =>
                  setRange((r) =>
                    r && r[0] === b.start && r[1] === b.end ? null : [b.start, b.end],
                  )
                }
                className="min-w-0 flex-1 cursor-pointer rounded-t transition-colors"
                style={{
                  height: `${Math.max(3, b.pct)}%`,
                  background:
                    range && range[0] === b.start
                      ? "var(--color-accent)"
                      : "var(--color-edge2)",
                }}
              />
            ))}
          </div>
          <div className="mt-1 flex justify-between text-[10px] text-[var(--color-faint)]">
            <span>{buckets.length ? fmtTs(buckets[0].start, true).slice(0, 10) : ""}</span>
            <span>{buckets.length ? fmtTs(buckets[buckets.length - 1].end, true).slice(0, 10) : ""}</span>
          </div>
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full text-left text-[12px]">
          <thead className="sticky top-0 bg-[var(--color-panel)] text-[var(--color-faint)]">
            <tr className="border-b border-[var(--color-edge)]">
              <th className="w-52 px-3 py-1.5 font-medium">time (UTC)</th>
              <th className="w-24 px-1 py-1.5 font-medium">event</th>
              <th className="w-20 px-1 py-1.5 font-medium">status</th>
              <th className="px-1 py-1.5 font-medium">path</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((e, i) => (
              <tr
                key={i}
                className="cursor-pointer border-b border-[var(--color-edge)]/40 hover:bg-[var(--color-panel2)]"
                onClick={() =>
                  router.push(
                    `/browse?m=${encodeURIComponent(mount)}&focus=${encodeURIComponent(e.path)}`,
                  )
                }
                title="open in browser"
              >
                <td className="mono whitespace-nowrap px-3 py-1">{fmtTs(e.nanos, true)}</td>
                <td className="px-1 py-1" style={{ color: TYPE_COLOR[e.type] }}>{e.type}</td>
                <td className="px-1 py-1 text-[var(--color-dim)]">{e.status}</td>
                <td className="mono max-w-0 truncate px-1 py-1" title={e.path}>{e.path}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length > shown && (
          <button
            className="m-3 rounded-md border border-[var(--color-edge)] px-3 py-1.5 text-[12px] text-[var(--color-dim)] cursor-pointer"
            onClick={() => setShown((s) => s + PAGE)}
          >
            show more ({(filtered.length - shown).toLocaleString()} remaining)
          </button>
        )}
        {!running && events.length === 0 && (
          <Empty
            icon="activity"
            title="no events"
            hint="pick a mount and build a timeline — MACBD timestamps become plottable events"
          />
        )}
        {running && events.length === 0 && (
          <div className="flex items-center gap-2 p-6 text-[var(--color-dim)]">
            <Spinner /> scanning timestamps…
          </div>
        )}
      </div>
    </div>
  );
}

export default function TimelinePage() {
  return (
    <Suspense>
      <TimelineInner />
    </Suspense>
  );
}
