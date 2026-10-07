import React from "react";
import { Icon, type IconName } from "@/lib/icons";

export function Panel({
  title,
  right,
  children,
  className = "",
  pad = true,
}: {
  title?: string;
  right?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  pad?: boolean;
}) {
  return (
    <section
      className={`panel-print rounded-lg border border-[var(--color-edge)] bg-[var(--color-panel)] shadow-[0_1px_2px_rgba(0,0,0,0.3)] ${className}`}
    >
      {title && (
        <header className="flex items-center justify-between border-b border-[var(--color-edge)] px-3.5 py-2">
          <h2 className="text-[var(--color-dim)] uppercase tracking-[0.08em] text-[10.5px] font-semibold">
            {title}
          </h2>
          {right}
        </header>
      )}
      <div className={pad ? "p-3.5" : ""}>{children}</div>
    </section>
  );
}

export function Badge({
  children,
  color,
  className = "",
}: {
  children: React.ReactNode;
  color?: string;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10.5px] font-medium leading-none border ${className}`}
      style={{
        color: color ?? "var(--color-dim)",
        borderColor: `color-mix(in srgb, ${color ?? "var(--color-edge2)"} 60%, transparent)`,
        background: `color-mix(in srgb, ${color ?? "var(--color-edge2)"} 12%, transparent)`,
      }}
    >
      {children}
    </span>
  );
}

const btnBase =
  "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-[12px] font-medium transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed select-none";

export const btn = `${btnBase} border border-[var(--color-edge)] bg-[var(--color-panel2)] text-[var(--color-fg)] hover:bg-[var(--color-panel3)] hover:border-[var(--color-edge2)]`;
export const btnPrimary = `${btnBase} border border-[var(--color-accent)]/60 bg-[var(--color-accent)]/15 text-[var(--color-accent)] hover:bg-[var(--color-accent)]/25`;
export const btnDanger = `${btnBase} border border-[var(--color-deleted)]/50 bg-[var(--color-deleted)]/10 text-[var(--color-deleted)] hover:bg-[var(--color-deleted)]/20`;
export const btnGhost = `${btnBase} text-[var(--color-dim)] hover:text-[var(--color-fg)] hover:bg-[var(--color-panel3)]`;
export const iconBtn =
  "inline-flex items-center justify-center rounded-md p-1.5 text-[var(--color-dim)] hover:text-[var(--color-fg)] hover:bg-[var(--color-panel3)] cursor-pointer transition-colors";

export function Button({
  icon,
  variant = "default",
  className = "",
  children,
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  icon?: IconName;
  variant?: "default" | "primary" | "danger" | "ghost";
}) {
  const cls =
    variant === "primary"
      ? btnPrimary
      : variant === "danger"
        ? btnDanger
        : variant === "ghost"
          ? btnGhost
          : btn;
  return (
    <button className={`${cls} ${className}`} {...rest}>
      {icon && <Icon name={icon} size={13} />}
      {children}
    </button>
  );
}

export const input =
  "w-full rounded-md border border-[var(--color-edge)] bg-[var(--color-bg)] px-2.5 py-1.5 text-[12.5px] outline-none transition-colors focus:border-[var(--color-accent)] placeholder:text-[var(--color-faint)]";

export const select =
  "rounded-md border border-[var(--color-edge)] bg-[var(--color-panel2)] px-2 py-1.5 text-[12px] outline-none transition-colors focus:border-[var(--color-accent)] cursor-pointer";

export function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
}) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className="flex items-center gap-2 cursor-pointer group"
    >
      <span
        className={`relative inline-flex h-4 w-7 items-center rounded-full transition-colors ${
          checked ? "bg-[var(--color-accent)]" : "bg-[var(--color-edge2)]"
        }`}
      >
        <span
          className={`inline-block h-3 w-3 rounded-full bg-white transition-transform ${
            checked ? "translate-x-3.5" : "translate-x-0.5"
          }`}
        />
      </span>
      <span className="text-[12px] text-[var(--color-dim)] group-hover:text-[var(--color-fg)]">
        {label}
      </span>
    </button>
  );
}

export function Spinner({ size = 14 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      className="animate-spin"
      aria-hidden
    >
      <circle
        cx="12"
        cy="12"
        r="10"
        stroke="var(--color-edge2)"
        strokeWidth="3"
      />
      <path
        d="M12 2a10 10 0 0 1 10 10"
        stroke="var(--color-accent)"
        strokeWidth="3"
        strokeLinecap="round"
      />
    </svg>
  );
}

export function ProgressBar({
  value,
  max,
  color = "var(--color-accent)",
  className = "",
}: {
  value: number;
  max: number;
  color?: string;
  className?: string;
}) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0;
  return (
    <div
      className={`h-1.5 w-full overflow-hidden rounded-full bg-[var(--color-edge)] ${className}`}
    >
      <div
        className="h-full rounded-full transition-all"
        style={{ width: `${pct}%`, background: color }}
      />
    </div>
  );
}

export function Empty({
  icon = "folder-open",
  title,
  hint,
}: {
  icon?: IconName;
  title: string;
  hint?: string;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-10 text-center">
      <Icon name={icon} size={28} className="text-[var(--color-faint)]" />
      <p className="text-[var(--color-dim)]">{title}</p>
      {hint && <p className="text-[11.5px] text-[var(--color-faint)]">{hint}</p>}
    </div>
  );
}

export function Err({ msg }: { msg: string | null }) {
  if (!msg) return null;
  return (
    <div className="fadein mt-2 flex items-start gap-2 rounded-md border border-[var(--color-deleted)]/40 bg-[var(--color-deleted)]/10 p-2.5 text-[12px] text-[var(--color-deleted)]">
      <Icon name="alert-triangle" size={14} className="mt-0.5 shrink-0" />
      <pre className="whitespace-pre-wrap font-sans">{msg}</pre>
    </div>
  );
}

export function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="rounded border border-[var(--color-edge2)] bg-[var(--color-panel3)] px-1 py-0.5 text-[10px] text-[var(--color-dim)]">
      {children}
    </kbd>
  );
}
