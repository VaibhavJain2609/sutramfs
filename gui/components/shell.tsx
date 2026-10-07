"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { useMounts } from "@/lib/mounts";
import { useActivity } from "@/lib/activity";
import { api } from "@/lib/api";
import { Icon, type IconName } from "@/lib/icons";
import { Kbd, iconBtn } from "./ui";

const NAV: { href: string; label: string; icon: IconName }[] = [
  { href: "/", label: "Image", icon: "hard-drive" },
  { href: "/browse", label: "Browse", icon: "folder" },
  { href: "/timeline", label: "Timeline", icon: "activity" },
  { href: "/carve", label: "Carve", icon: "pickaxe" },
  { href: "/recovery", label: "Recovery", icon: "recycle" },
  { href: "/report", label: "Report", icon: "file-text" },
];

function HealthDot() {
  const [ok, setOk] = useState<boolean | null>(null);
  useEffect(() => {
    let live = true;
    const check = () =>
      api
        .health()
        .then((h) => live && setOk(h.daemon === "connected"))
        .catch(() => live && setOk(false));
    check();
    const t = setInterval(check, 15000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, []);
  const color =
    ok === null
      ? "var(--color-dim)"
      : ok
        ? "var(--color-live)"
        : "var(--color-deleted)";
  return (
    <span
      title={ok ? "sutramfsd connected" : "sutramfsd unavailable"}
      className="inline-block h-2 w-2 rounded-full pulse-dot"
      style={{ background: color }}
    />
  );
}

const SHORTCUTS: [string, string][] = [
  ["j / k", "move selection in tables"],
  ["enter", "open detail pane"],
  ["esc", "close pane / modal"],
  ["/", "focus search filter"],
];

export default function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { mounts } = useMounts();
  const { status } = useActivity();
  const [collapsed, setCollapsed] = useState(false);
  const [help, setHelp] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "?" && !(e.target instanceof HTMLInputElement) && !(e.target instanceof HTMLTextAreaElement)) {
        setHelp((h) => !h);
      }
      if (e.key === "Escape") setHelp(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="flex h-screen overflow-hidden">
      <aside
        className="no-print flex shrink-0 flex-col border-r border-[var(--color-edge)] bg-[var(--color-panel)] transition-all"
        style={{ width: collapsed ? 52 : 176 }}
      >
        <div className="flex items-center gap-2 border-b border-[var(--color-edge)] px-3 py-3">
          <Icon name="shield" size={17} className="shrink-0 text-[var(--color-accent)]" />
          {!collapsed && (
            <span className="text-[13px] font-bold tracking-tight">
              sutram<span className="text-[var(--color-accent)]">fs</span>
            </span>
          )}
        </div>
        <nav className="flex-1 space-y-0.5 p-2">
          {NAV.map((n) => {
            const active = pathname === n.href;
            return (
              <Link
                key={n.href}
                href={n.href}
                title={collapsed ? n.label : undefined}
                className={`flex items-center gap-2.5 rounded-md px-2.5 py-2 text-[12.5px] transition-colors ${
                  active
                    ? "bg-[var(--color-accent)]/15 text-[var(--color-accent)] font-medium"
                    : "text-[var(--color-dim)] hover:bg-[var(--color-panel3)] hover:text-[var(--color-fg)]"
                }`}
              >
                <Icon name={n.icon} size={15} className="shrink-0" />
                {!collapsed && n.label}
              </Link>
            );
          })}
        </nav>
        <div className="border-t border-[var(--color-edge)] p-2 space-y-0.5">
          <button
            className={`${iconBtn} w-full ${collapsed ? "" : "justify-start gap-2.5 px-2.5"} `}
            onClick={() => setHelp(true)}
            title="keyboard shortcuts"
          >
            <Icon name="keyboard" size={15} />
            {!collapsed && <span className="text-[12.5px]">shortcuts</span>}
          </button>
          <button
            className={`${iconBtn} w-full ${collapsed ? "" : "justify-start gap-2.5 px-2.5"}`}
            onClick={() => setCollapsed((c) => !c)}
            title={collapsed ? "expand" : "collapse"}
          >
            <Icon name={collapsed ? "chevron-right" : "chevron-left"} size={15} />
            {!collapsed && <span className="text-[12.5px]">collapse</span>}
          </button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <main className="flex min-h-0 flex-1 flex-col overflow-auto">{children}</main>
        <footer className="no-print flex items-center gap-4 border-t border-[var(--color-edge)] bg-[var(--color-panel)] px-3 py-1.5 text-[11px] text-[var(--color-dim)]">
          <span className="flex items-center gap-1.5">
            <HealthDot /> sutramfsd
          </span>
          <span className="flex items-center gap-1.5">
            <Icon name="hard-drive" size={11} />
            {mounts.length} mount{mounts.length === 1 ? "" : "s"}
          </span>
          <span className="ml-auto flex items-center gap-2 truncate">
            {status && (
              <>
                <span className="pulse-dot inline-block h-1.5 w-1.5 rounded-full bg-[var(--color-accent)]" />
                {status}
              </>
            )}
          </span>
        </footer>
      </div>

      {help && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 no-print"
          onClick={() => setHelp(false)}
        >
          <div
            className="w-80 rounded-lg border border-[var(--color-edge)] bg-[var(--color-panel)] p-4"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="mb-3 text-[13px] font-semibold">Keyboard shortcuts</h3>
            <table className="w-full">
              <tbody>
                {SHORTCUTS.map(([k, d]) => (
                  <tr key={k}>
                    <td className="py-1 pr-3"><Kbd>{k}</Kbd></td>
                    <td className="text-[var(--color-dim)] text-[12px]">{d}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
