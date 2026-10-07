"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Icon } from "@/lib/icons";
import { fmtBytes } from "@/lib/format";
import { Button, Empty, Err, iconBtn, input } from "./ui";

interface FsEnt {
  name: string;
  path: string;
  dir: boolean;
  size: number;
  mtime: number;
}

// Modal browser for the *server-local* filesystem (this app runs on the same
// machine as the evidence images).
export default function FilePicker({
  open,
  onPick,
  onClose,
}: {
  open: boolean;
  onPick: (path: string) => void;
  onClose: () => void;
}) {
  const [dir, setDir] = useState("");
  const [parent, setParent] = useState("");
  const [entries, setEntries] = useState<FsEnt[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [manual, setManual] = useState("");
  const filterRef = useRef<HTMLInputElement>(null);

  const load = useCallback(async (p?: string) => {
    try {
      const res = await fetch(`/api/fs/list?path=${encodeURIComponent(p ?? "")}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      setDir(data.path);
      setParent(data.parent);
      setEntries(data.entries);
      setErr(null);
    } catch (e: any) {
      setErr(e.message);
    }
  }, []);

  useEffect(() => {
    if (open) {
      setFilter("");
      setManual("");
      load().then(() => filterRef.current?.focus());
    }
  }, [open, load]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  const visible = filter
    ? entries.filter((e) => e.name.toLowerCase().includes(filter.toLowerCase()))
    : entries;

  const go = (p: string) => {
    setFilter("");
    load(p);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      onClick={onClose}
    >
      <div
        className="flex h-[70vh] w-[560px] flex-col overflow-hidden rounded-lg border border-[var(--color-edge)] bg-[var(--color-panel)] shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 border-b border-[var(--color-edge)] px-3 py-2">
          <button className={iconBtn} onClick={() => go(parent)} title="up">
            <Icon name="arrow-left" size={14} />
          </button>
          <span className="mono min-w-0 flex-1 truncate text-[12px] text-[var(--color-dim)]" title={dir}>
            {dir || "…"}
          </span>
          <button className={iconBtn} onClick={onClose} title="close">
            <Icon name="x" size={14} />
          </button>
        </div>
        <div className="border-b border-[var(--color-edge)] px-3 py-2">
          <input
            ref={filterRef}
            className={input}
            placeholder="filter…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
        <div className="min-h-0 flex-1 overflow-auto">
          {visible.map((e) => (
            <button
              key={e.path}
              onClick={() => (e.dir ? go(e.path) : onPick(e.path))}
              onDoubleClick={() => e.dir && go(e.path)}
              className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-[12.5px] hover:bg-[var(--color-panel3)] cursor-pointer"
            >
              <Icon
                name={e.dir ? "folder" : "file"}
                size={14}
                className={e.dir ? "text-[var(--color-accent)]" : "text-[var(--color-dim)]"}
              />
              <span className="min-w-0 flex-1 truncate">{e.name}</span>
              {!e.dir && (
                <span className="text-[11px] text-[var(--color-faint)]">
                  {fmtBytes(e.size)}
                </span>
              )}
            </button>
          ))}
          {!err && visible.length === 0 && (
            <Empty title="empty directory" />
          )}
          {err && <Err msg={err} />}
        </div>
        <div className="flex gap-2 border-t border-[var(--color-edge)] p-2.5">
          <input
            className={input}
            placeholder="or type a full path and press enter"
            value={manual}
            onChange={(e) => setManual(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && manual.trim()) onPick(manual.trim());
            }}
          />
          <Button
            variant="primary"
            disabled={!manual.trim()}
            onClick={() => onPick(manual.trim())}
          >
            open
          </Button>
        </div>
      </div>
    </div>
  );
}
