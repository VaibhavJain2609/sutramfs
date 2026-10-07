"use client";

import { useMemo, useState } from "react";
import { Icon } from "@/lib/icons";
import type { FsEntry } from "@/lib/types";

interface DirNode {
  path: string;
  name: string;
  children: Map<string, DirNode>;
  deleted: number;
  files: number;
}

// Directory tree built client-side from walked entry paths. Clicking a node
// scopes the table (and re-walk prefix) to that subtree.
export default function DirTree({
  entries,
  selected,
  onSelect,
}: {
  entries: FsEntry[];
  selected: string;
  onSelect: (prefix: string) => void;
}) {
  const [open, setOpen] = useState<Set<string>>(new Set(["/"]));

  const root = useMemo(() => {
    const r: DirNode = { path: "/", name: "/", children: new Map(), deleted: 0, files: 0 };
    for (const e of entries) {
      const parts = e.path.split("/").filter(Boolean);
      let node = r;
      let acc = "";
      for (let i = 0; i < parts.length; i++) {
        acc += "/" + parts[i];
        let child = node.children.get(parts[i]);
        if (!child) {
          child = { path: acc, name: parts[i], children: new Map(), deleted: 0, files: 0 };
          node.children.set(parts[i], child);
        }
        node = child;
      }
      // annotate the full path's node; propagate counts to ancestors
      if (e.status === "deleted") node.deleted++;
      if (e.kind === "file") node.files++;
    }
    // aggregate counts upward
    const agg = (n: DirNode): [number, number] => {
      let d = n.deleted,
        f = n.files;
      for (const c of n.children.values()) {
        const [cd, cf] = agg(c);
        d += cd;
        f += cf;
      }
      n.deleted = d;
      n.files = f;
      return [d, f];
    };
    agg(r);
    return r;
  }, [entries]);

  const toggle = (p: string) => {
    const next = new Set(open);
    next.has(p) ? next.delete(p) : next.add(p);
    setOpen(next);
  };

  const render = (n: DirNode, depth: number): React.ReactNode => {
    const kids = [...n.children.values()].sort((a, b) =>
      a.name.localeCompare(b.name),
    );
    const isOpen = open.has(n.path);
    const isSel = selected === n.path || selected === n.path + "/";
    return (
      <div key={n.path}>
        <div
          className={`flex cursor-pointer items-center gap-1 rounded px-1 py-0.5 hover:bg-[var(--color-panel3)] ${
            isSel ? "bg-[var(--color-accent)]/15 text-[var(--color-accent)]" : ""
          }`}
          style={{ paddingLeft: 4 + depth * 12 }}
          onClick={() => onSelect(n.path === "/" ? "" : n.path)}
        >
          <button
            className="shrink-0 text-[var(--color-faint)] cursor-pointer"
            onClick={(e) => {
              e.stopPropagation();
              toggle(n.path);
            }}
          >
            {kids.length > 0 ? (
              <Icon name={isOpen ? "chevron-down" : "chevron-right"} size={11} />
            ) : (
              <span className="inline-block w-[11px]" />
            )}
          </button>
          <Icon name={isOpen ? "folder-open" : "folder"} size={12} className="shrink-0 text-[var(--color-dim)]" />
          <span className="min-w-0 flex-1 truncate text-[11.5px]">{n.name}</span>
          {n.deleted > 0 && (
            <span className="text-[10px] text-[var(--color-deleted)]">+{n.deleted}d</span>
          )}
          {n.files > 0 && (
            <span className="text-[10px] text-[var(--color-faint)]">{n.files}</span>
          )}
        </div>
        {isOpen && kids.map((k) => render(k, depth + 1))}
      </div>
    );
  };

  if (entries.length === 0) return null;
  return <div className="py-1">{render(root, 0)}</div>;
}
