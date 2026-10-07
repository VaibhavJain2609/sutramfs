"use client";

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { api, streamNdjson } from "@/lib/api";
import { useMounts } from "@/lib/mounts";
import { useToast } from "@/lib/toast";
import { useActivity } from "@/lib/activity";
import { fmtBytes, fmtHex, fmtTs, statusColor, statusLabel } from "@/lib/format";
import type { FsEntry } from "@/lib/types";
import {
  Badge, btn, Button, Empty, Err, iconBtn, input, Panel, select, Spinner,
} from "@/components/ui";
import { Icon } from "@/lib/icons";
import Preview from "@/components/preview";
import DirTree from "@/components/dir-tree";

const PAGE = 400;
type SortKey = "path" | "size" | "mtime" | "status";
type ExportFmt = "csv" | "json" | "bodyfile";

function tsRow(label: string, t: { has_value: boolean; unix_nanos: number; raw_encoding: string; raw_value: number }) {
  if (!t.has_value) return null;
  return (
    <tr key={label}>
      <td className="py-0.5 pr-3 text-[var(--color-dim)]">{label}</td>
      <td className="mono">{fmtTs(t.unix_nanos, t.has_value)}</td>
      <td className="pl-3 text-[10.5px] text-[var(--color-faint)]">
        {t.raw_encoding}
      </td>
    </tr>
  );
}

const HASH_ORDER = ["sha256", "sha512", "sha1", "md5", "blake2b512"];

function HashView({ mount, entry }: { mount: string; entry: FsEntry }) {
  const toast = useToast();
  const [h, setH] = useState<Record<string, string | number> | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setH(null);
    setErr(null);
    let cancelled = false;
    setLoading(true);
    api
      .hash(mount, entry.path)
      .then((r) => !cancelled && setH(r))
      .catch((e) => !cancelled && setErr(e.message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [mount, entry.path]);

  const row = (label: string, v: string) => (
    <div className="flex items-center gap-2" key={label}>
      <span className="w-11 shrink-0 text-[var(--color-dim)]">{label}</span>
      <span className="mono min-w-0 flex-1 truncate" title={v}>
        {v}
      </span>
      <button
        className={iconBtn}
        title={`copy ${label}`}
        onClick={() => {
          navigator.clipboard.writeText(v);
          toast.push(`${label} copied`, "success");
        }}
      >
        <Icon name="copy" size={11} />
      </button>
    </div>
  );

  return (
    <div>
      <h3 className="mb-1 text-[10.5px] font-semibold uppercase tracking-wide text-[var(--color-faint)]">
        hashes
      </h3>
      {loading && (
        <div className="flex items-center gap-2 text-[11px] text-[var(--color-dim)]">
          <Spinner size={11} /> hashing {fmtBytes(entry.size)}…
        </div>
      )}
      {err && <p className="text-[11px] text-[var(--color-deleted)]">{err}</p>}
      {h && (
        <div className="space-y-0.5 text-[11.5px]">
          {HASH_ORDER.filter((k) => typeof h[k] === "string").map((k) =>
            row(k, h[k] as string),
          )}
          {h.bytes !== entry.size && (
            <p className="pt-0.5 text-[10.5px] text-[var(--color-warn)]">
              hashed {fmtBytes(h.bytes as number)} of {fmtBytes(entry.size)} — partial read
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function Detail({ mount, entry, onClose }: { mount: string; entry: FsEntry; onClose: () => void }) {
  const toast = useToast();
  return (
    <div className="space-y-3.5">
      <div>
        <div className="flex items-center justify-between">
          <div className="flex flex-wrap items-center gap-1.5">
            <Badge color={statusColor(entry.status, entry.recovery)}>
              {statusLabel(entry.status, entry.recovery)}
            </Badge>
            <Badge>{entry.kind}</Badge>
            {entry.magic.mismatch && (
              <Badge color="var(--color-deleted)">magic mismatch</Badge>
            )}
          </div>
          <button className={iconBtn} onClick={onClose}><Icon name="x" size={13} /></button>
        </div>
        <p className="mono mt-2 break-all text-[13px] font-medium">{entry.path}</p>
        <div className="mt-1 flex gap-1">
          <button
            className={iconBtn}
            title="copy path"
            onClick={() => {
              navigator.clipboard.writeText(entry.path);
              toast.push("path copied", "success");
            }}
          >
            <Icon name="copy" size={12} />
          </button>
        </div>
      </div>

      {entry.error && <Err msg={entry.error} />}

      {entry.kind === "file" && entry.path && <HashView mount={mount} entry={entry} />}

      <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-[12px]">
        <span className="text-[var(--color-dim)]">size</span>
        <span className="mono">{fmtBytes(entry.size)}</span>
        <span className="text-[var(--color-dim)]">disk offset</span>
        <span className="mono">{fmtHex(entry.disk_offset)}</span>
        <span className="text-[var(--color-dim)]">entry id</span>
        <span className="mono">{entry.entry_id}</span>
        {entry.status === "deleted" && entry.total_bytes > 0 && (
          <>
            <span className="text-[var(--color-dim)]">recoverable</span>
            <span className="mono text-[var(--color-orphan)]">
              {fmtBytes(entry.recovered_bytes)} / {fmtBytes(entry.total_bytes)}
            </span>
          </>
        )}
      </div>

      <div>
        <h3 className="mb-1 text-[10.5px] font-semibold uppercase tracking-wide text-[var(--color-faint)]">timestamps</h3>
        <table className="text-[11.5px]"><tbody>
          {tsRow("modified", entry.timestamps.modified)}
          {tsRow("accessed", entry.timestamps.accessed)}
          {tsRow("created", entry.timestamps.created)}
          {tsRow("changed", entry.timestamps.changed)}
          {tsRow("deleted", entry.timestamps.deleted)}
        </tbody></table>
      </div>

      {entry.allocated_ranges.length > 0 && (
        <div>
          <h3 className="mb-1 text-[10.5px] font-semibold uppercase tracking-wide text-[var(--color-faint)]">
            extents ({entry.allocated_ranges.length})
          </h3>
          <div className="mono max-h-24 overflow-auto text-[11px] text-[var(--color-dim)]">
            {entry.allocated_ranges.map((r, i) => (
              <div key={i}>{fmtHex(r.offset)} + {fmtBytes(r.len)}</div>
            ))}
          </div>
        </div>
      )}

      {Object.keys(entry.meta).length > 0 && (
        <div>
          <h3 className="mb-1 text-[10.5px] font-semibold uppercase tracking-wide text-[var(--color-faint)]">metadata</h3>
          <div className="text-[11.5px]">
            {Object.entries(entry.meta).map(([k, v]) => (
              <div key={k} className="flex gap-2">
                <span className="text-[var(--color-dim)]">{k}</span>
                <span className="mono min-w-0 truncate" title={v}>{v}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {entry.magic.present && (
        <div>
          <h3 className="mb-1 text-[10.5px] font-semibold uppercase tracking-wide text-[var(--color-faint)]">magic verdict</h3>
          <div className="text-[11.5px]">
            declared: {entry.magic.declared || "(none)"} · detected: {entry.magic.detected || "(none)"}
          </div>
          {entry.magic.reasons.map((r, i) => (
            <div key={i} className="mt-0.5 text-[11px] text-[var(--color-warn)]">· {r}</div>
          ))}
        </div>
      )}

      {entry.kind === "file" && (
        <div>
          <h3 className="mb-1 text-[10.5px] font-semibold uppercase tracking-wide text-[var(--color-faint)]">content</h3>
          <Preview mount={mount} path={entry.path} size={entry.size} />
        </div>
      )}
    </div>
  );
}

function exportEntries(entries: FsEntry[], fmt: ExportFmt) {
  let content = "";
  let mime = "text/plain";
  let ext = "txt";
  if (fmt === "csv") {
    mime = "text/csv";
    ext = "csv";
    content =
      "mount,path,kind,size,status,recovery,modified,created,accessed,disk_offset\n" +
      entries
        .map((e) =>
          [
            e.mount ?? "", `"${e.path.replace(/"/g, '""')}"`, e.kind, e.size, e.status,
            e.recovery,
            e.timestamps.modified.has_value ? new Date(e.timestamps.modified.unix_nanos / 1e6).toISOString() : "",
            e.timestamps.created.has_value ? new Date(e.timestamps.created.unix_nanos / 1e6).toISOString() : "",
            e.timestamps.accessed.has_value ? new Date(e.timestamps.accessed.unix_nanos / 1e6).toISOString() : "",
            e.disk_offset,
          ].join(","),
        )
        .join("\n");
  } else if (fmt === "json") {
    mime = "application/json";
    ext = "json";
    content = JSON.stringify(entries, null, 2);
  } else {
    ext = "bodyfile";
    const sec = (n: number) => Math.floor(n / 1e9);
    content = entries
      .map((e) => {
        const t = e.timestamps;
        return `0|${e.path}|${e.entry_id}|0|0|0|${e.size}|${t.accessed.has_value ? sec(t.accessed.unix_nanos) : 0}|${t.modified.has_value ? sec(t.modified.unix_nanos) : 0}|${t.changed.has_value ? sec(t.changed.unix_nanos) : 0}|${t.created.has_value ? sec(t.created.unix_nanos) : 0}`;
      })
      .join("\n");
  }
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = `sutramfs-walk.${ext}`;
  a.click();
  URL.revokeObjectURL(url);
}

function BrowseInner() {
  const params = useSearchParams();
  const { mounts } = useMounts();
  const toast = useToast();
  const { setStatus: setActivity } = useActivity();

  const [active, setActive] = useState<Set<string>>(
    () => new Set((params.get("m") ?? "").split(",").filter(Boolean)),
  );
  const [status, setStatus] = useState("all");
  const [kind, setKind] = useState("all");
  const [entries, setEntries] = useState<FsEntry[]>([]);
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [selected, setSelected] = useState<FsEntry | null>(null);
  const [dirPrefix, setDirPrefix] = useState("");
  const [search, setSearch] = useState("");
  const [useRegex, setUseRegex] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>("path");
  const [sortAsc, setSortAsc] = useState(true);
  const [shown, setShown] = useState(PAGE);
  const [checked, setChecked] = useState<Set<number>>(new Set());
  const [showTree, setShowTree] = useState(true);
  const abortRef = useRef<AbortController | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const pendingFocus = params.get("focus");

  const initRef = useRef(false);
  useEffect(() => {
    if (initRef.current || mounts.length === 0) return;
    initRef.current = true;
    setActive((a) => (a.size ? a : new Set(mounts.map((m) => m.id))));
  }, [mounts]);

  const shortTag = useCallback(
    (id: string) => {
      const m = mounts.find((x) => x.id === id);
      if (m?.label) return m.label.split(" ")[0];
      if (m?.fs_type) return m.fs_type;
      return id.split("-").slice(0, 2).join("-");
    },
    [mounts],
  );

  const run = useCallback(async () => {
    const ids = [...active];
    if (!ids.length) return;
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setEntries([]);
    setSelected(null);
    setChecked(new Set());
    setErr(null);
    setRunning(true);
    setShown(PAGE);
    const errs: string[] = [];
    let n = 0;
    try {
      await Promise.all(
        ids.map((id) => {
          const qs = new URLSearchParams({ handle: id, status, kind });
          return streamNdjson(`/api/walk?${qs}`, {
            signal: ac.signal,
            onEntry: (e) => {
              n++;
              if (n % 25 === 0) setActivity(`walking… ${n.toLocaleString()} entries`);
              setEntries((prev) => [...prev, { ...e, mount: id }]);
            },
            onError: (m) => errs.push(`${shortTag(id)}: ${m}`),
          });
        }),
      );
      if (errs.length) setErr(errs.join(" · "));
      setActivity("");
      if (n === 0 && !errs.length) toast.push("walk complete — no entries", "info");
    } catch (e: any) {
      if (e.name !== "AbortError") {
        setErr(e.message);
        toast.push(e.message, "error");
      }
    } finally {
      setRunning(false);
      setActivity("");
    }
  }, [active, status, kind, setActivity, toast, shortTag]);

  // jump from timeline: ?m=..&focus=/path
  useEffect(() => {
    if (active.size && pendingFocus && entries.length === 0 && !running) {
      run();
    }
  }, [active.size, pendingFocus, entries.length, running, run]);
  useEffect(() => {
    if (pendingFocus && entries.length) {
      const hit = entries.find((e) => e.path === pendingFocus);
      if (hit) {
        setSelected(hit);
        setSearch(pendingFocus);
      }
    }
  }, [pendingFocus, entries]);

  const filtered = useMemo(() => {
    let list = entries;
    if (dirPrefix) {
      const p = dirPrefix === "/" ? "" : dirPrefix;
      list = list.filter((e) => e.path === p || e.path.startsWith(p + "/"));
    }
    if (search) {
      if (useRegex) {
        try {
          const re = new RegExp(search, "i");
          list = list.filter((e) => re.test(e.path));
        } catch { /* bad regex — show all */ }
      } else {
        const f = search.toLowerCase();
        list = list.filter((e) => e.path.toLowerCase().includes(f));
      }
    }
    const dir = sortAsc ? 1 : -1;
    return [...list].sort((a, b) => {
      switch (sortKey) {
        case "size": return (a.size - b.size) * dir;
        case "mtime":
          return ((a.timestamps.modified.unix_nanos || 0) - (b.timestamps.modified.unix_nanos || 0)) * dir;
        case "status": return a.status.localeCompare(b.status) * dir;
        default: return a.path.localeCompare(b.path) * dir;
      }
    });
  }, [entries, dirPrefix, search, useRegex, sortKey, sortAsc]);

  const visible = filtered.slice(0, shown);

  const counts = useMemo(() => {
    let live = 0, deleted = 0, errors = 0;
    for (const e of entries) {
      if (e.error) errors++;
      else if (e.status === "deleted") deleted++;
      else live++;
    }
    return { live, deleted, errors };
  }, [entries]);

  const selIdx = selected ? filtered.indexOf(selected) : -1;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement).tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
      if (e.key === "/") {
        e.preventDefault();
        searchRef.current?.focus();
      } else if (e.key === "j" || e.key === "k") {
        if (!filtered.length) return;
        const next =
          e.key === "j"
            ? Math.min(selIdx + 1, filtered.length - 1)
            : Math.max(selIdx - 1, 0);
        setSelected(filtered[next < 0 ? 0 : next]);
      } else if (e.key === "Escape") {
        setSelected(null);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [filtered, selIdx]);

  const toggleSort = (k: SortKey) => {
    if (sortKey === k) setSortAsc((a) => !a);
    else {
      setSortKey(k);
      setSortAsc(true);
    }
  };

  const sortIcon = (k: SortKey) =>
    sortKey === k ? (sortAsc ? "arrow-up" : "arrow-down") : null;

  const toggleCheck = (i: number) => {
    const next = new Set(checked);
    next.has(i) ? next.delete(i) : next.add(i);
    setChecked(next);
  };

  const checkedEntries = filtered.filter((_, i) => checked.has(i));

  const headerBtn = (k: SortKey, label: string, cls = "") => (
    <button
      onClick={() => toggleSort(k)}
      className={`flex items-center gap-1 font-medium hover:text-[var(--color-fg)] cursor-pointer ${cls}`}
    >
      {label}
      {sortIcon(k) && <Icon name={sortIcon(k)!} size={10} />}
    </button>
  );

  return (
    <div className="flex min-h-0 flex-1">
      {showTree && (
        <div className="resize-x w-56 shrink-0 overflow-auto border-r border-[var(--color-edge)] bg-[var(--color-panel)]">
          <div className="sticky top-0 flex items-center justify-between border-b border-[var(--color-edge)] bg-[var(--color-panel)] px-2.5 py-1.5">
            <span className="text-[10.5px] font-semibold uppercase tracking-wide text-[var(--color-faint)]">directories</span>
            {dirPrefix && (
              <button className="text-[10.5px] text-[var(--color-accent)] cursor-pointer" onClick={() => setDirPrefix("")}>
                clear
              </button>
            )}
          </div>
          {entries.length === 0 ? (
            <p className="p-3 text-[11px] text-[var(--color-faint)]">walk to populate</p>
          ) : (
            <DirTree entries={entries} selected={dirPrefix} onSelect={setDirPrefix} />
          )}
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex flex-wrap items-center gap-2 border-b border-[var(--color-edge)] bg-[var(--color-panel)] px-3 py-2">
          <button className={iconBtn} title="toggle tree" onClick={() => setShowTree((s) => !s)}>
            <Icon name="list" size={14} />
          </button>
          <div className="flex items-center gap-1">
            {mounts.length === 0 && (
              <a
                href="/"
                className="flex items-center gap-1.5 text-[12.5px] text-[var(--color-dim)] hover:text-[var(--color-fg)]"
              >
                <Icon name="hard-drive" size={13} />
                no mounts — open an image
              </a>
            )}
            {mounts.map((m) => {
              const on = active.has(m.id);
              return (
                <button
                  key={m.id}
                  onClick={() =>
                    setActive((a) => {
                      const next = new Set(a);
                      on ? next.delete(m.id) : next.add(m.id);
                      return next;
                    })
                  }
                  className={`flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] cursor-pointer transition-colors ${
                    on
                      ? "border-[var(--color-accent)] bg-[var(--color-accent)]/15 text-[var(--color-accent)]"
                      : "border-[var(--color-edge)] text-[var(--color-dim)] hover:text-[var(--color-fg)]"
                  }`}
                  title={`${m.fs_type} — ${m.label ?? m.image}\n${m.id}`}
                >
                  <span className="mono text-[10px]">{m.fs_type}</span>
                  {shortTag(m.id)}
                </button>
              );
            })}
          </div>
          <select className={select} value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="all">all</option>
            <option value="live">live</option>
            <option value="deleted">deleted</option>
          </select>
          <select className={select} value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="all">any kind</option>
            <option value="file">files</option>
            <option value="directory">dirs</option>
            <option value="symlink">symlinks</option>
          </select>
          {running ? (
            <Button icon="stop" onClick={() => abortRef.current?.abort()}>stop</Button>
          ) : (
            <Button variant="primary" icon="play" onClick={run} disabled={!active.size}>walk</Button>
          )}
          <div className="relative">
            <Icon name="search" size={12} className="absolute left-2 top-1/2 -translate-y-1/2 text-[var(--color-faint)]" />
            <input
              ref={searchRef}
              className={`${input} w-44 pl-7`}
              placeholder="filter paths ( / )"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <button
            className={`rounded px-1.5 py-1 text-[10.5px] cursor-pointer ${useRegex ? "bg-[var(--color-accent)]/15 text-[var(--color-accent)]" : "text-[var(--color-faint)]"}`}
            onClick={() => setUseRegex((r) => !r)}
            title="regex filter"
          >
            .*
          </button>
          <span className="ml-auto flex items-center gap-3 text-[11px] text-[var(--color-dim)]">
            <span>{filtered.length.toLocaleString()} shown</span>
            <span className="text-[var(--color-live)]">{counts.live} live</span>
            <span className="text-[var(--color-deleted)]">{counts.deleted} del</span>
            {counts.errors > 0 && <span className="text-[var(--color-warn)]">{counts.errors} err</span>}
          </span>
          {checked.size > 0 && (
            <div className="flex items-center gap-1.5">
              <Badge color="var(--color-accent)">{checked.size} selected</Badge>
              {(["csv", "json", "bodyfile"] as ExportFmt[]).map((f) => (
                <button
                  key={f}
                  className="text-[11px] text-[var(--color-accent)] hover:underline cursor-pointer"
                  onClick={() => exportEntries(checkedEntries, f)}
                >
                  {f}
                </button>
              ))}
              <button className={iconBtn} onClick={() => setChecked(new Set())}>
                <Icon name="x" size={12} />
              </button>
            </div>
          )}
        </div>
        <Err msg={err} />

        <div className="flex min-h-0 flex-1">
          <div className="min-w-0 flex-1 overflow-auto">
            <table className="w-full text-left text-[12px]">
              <thead className="sticky top-0 z-10 bg-[var(--color-panel)] text-[var(--color-faint)]">
                <tr className="border-b border-[var(--color-edge)]">
                  <th className="w-7 px-2 py-1.5" />
                  <th className="w-24 px-1 py-1.5">status</th>
                  <th className="px-1 py-1.5">{headerBtn("path", "path")}</th>
                  <th className="w-20 px-1 py-1.5 text-right">{headerBtn("size", "size", "ml-auto")}</th>
                  <th className="w-44 px-1 py-1.5">{headerBtn("mtime", "modified")}</th>
                  <th className="w-16 px-1 py-1.5">kind</th>
                  <th className="w-8" />
                </tr>
              </thead>
              <tbody>
                {visible.map((e, i) => {
                  const isSel = selected === e;
                  return (
                    <tr
                      key={i}
                      onClick={() => setSelected(isSel ? null : e)}
                      className={`cursor-pointer border-b border-[var(--color-edge)]/40 hover:bg-[var(--color-panel2)] ${
                        isSel ? "bg-[var(--color-accent)]/10" : ""
                      } ${e.status === "deleted" ? (e.recovery === "intact" ? "row-deleted-intact" : "row-deleted") : ""}`}
                    >
                      <td className="px-2 py-1" onClick={(ev) => ev.stopPropagation()}>
                        <input
                          type="checkbox"
                          className="accent-[var(--color-accent)] cursor-pointer"
                          checked={checked.has(i)}
                          onChange={() => toggleCheck(i)}
                        />
                      </td>
                      <td className="px-1 py-1">
                        <span
                          className="text-[11px]"
                          style={{ color: statusColor(e.status, e.recovery) }}
                        >
                          {e.error ? "error" : statusLabel(e.status, e.recovery)}
                        </span>
                      </td>
                      <td className="mono max-w-0 truncate px-1 py-1" title={e.path}>
                        {active.size > 1 && e.mount && (
                          <span className="mr-1 rounded bg-[var(--color-panel3)] px-1 text-[10px] text-[var(--color-dim)]">
                            {shortTag(e.mount)}
                          </span>
                        )}
                        {e.path || "(record)"}
                        {e.magic.mismatch && (
                          <Icon name="alert-triangle" size={11} className="ml-1 inline text-[var(--color-deleted)]" />
                        )}
                      </td>
                      <td className="mono px-1 py-1 text-right text-[var(--color-dim)]">
                        {e.size ? fmtBytes(e.size) : ""}
                      </td>
                      <td className="mono px-1 py-1 text-[11px] text-[var(--color-dim)]">
                        {fmtTs(e.timestamps.modified.unix_nanos, e.timestamps.modified.has_value)}
                      </td>
                      <td className="px-1 py-1 text-[var(--color-faint)]">{e.kind}</td>
                      <td className="px-1 py-1" onClick={(ev) => ev.stopPropagation()}>
                        {e.kind === "file" && (
                          <a className={iconBtn} href={api.readUrl(e.mount ?? "", e.path, "&download=1")} title="download">
                            <Icon name="download" size={12} />
                          </a>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {filtered.length > shown && (
              <button
                className="m-3 rounded-md border border-[var(--color-edge)] px-3 py-1.5 text-[12px] text-[var(--color-dim)] hover:border-[var(--color-accent)] cursor-pointer"
                onClick={() => setShown((s) => s + PAGE * 2)}
              >
                show more ({filtered.length - shown} remaining)
              </button>
            )}
            {!running && entries.length === 0 && (
              <Empty icon="folder-open" title="no entries yet" hint="select a mount and press walk — or press / to search" />
            )}
            {running && entries.length === 0 && (
              <div className="flex items-center gap-2 p-6 text-[var(--color-dim)]">
                <Spinner /> streaming entries…
              </div>
            )}
          </div>

          {selected && (
            <div className="resize-x w-[380px] shrink-0 overflow-auto border-l border-[var(--color-edge)] bg-[var(--color-panel)] p-3.5">
              <Detail mount={selected.mount ?? ""} entry={selected} onClose={() => setSelected(null)} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function BrowsePage() {
  return (
    <Suspense>
      <div className="flex min-h-0 flex-1 flex-col">
        <BrowseInner />
      </div>
    </Suspense>
  );
}
