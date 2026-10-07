"use client";

import { useMounts } from "@/lib/mounts";
import { select } from "./ui";
import { Icon } from "@/lib/icons";

export default function MountPicker({
  value,
  onChange,
}: {
  value: string;
  onChange: (id: string) => void;
}) {
  const { mounts } = useMounts();
  if (mounts.length === 0) {
    return (
      <a
        href="/"
        className="flex items-center gap-1.5 text-[12.5px] text-[var(--color-dim)] hover:text-[var(--color-fg)]"
      >
        <Icon name="hard-drive" size={13} />
        no mounts — open an image
      </a>
    );
  }
  return (
    <select
      className={select}
      value={value}
      onChange={(e) => onChange(e.target.value)}
    >
      <option value="">select mount…</option>
      {mounts.map((m) => (
        <option key={m.id} value={m.id}>
          {m.fs_type} — {m.label}
        </option>
      ))}
    </select>
  );
}
