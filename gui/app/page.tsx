"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { useMounts } from "@/lib/mounts";
import { useToast } from "@/lib/toast";
import { useActivity } from "@/lib/activity";
import { fmtBytes, fmtHex } from "@/lib/format";
import type { AndroidLayout, Detection, MountInfo, Partition } from "@/lib/types";
import {
  Badge, btn, Button, Empty, Err, iconBtn, input, Panel, select, Spinner, Toggle,
} from "@/components/ui";
import { Icon } from "@/lib/icons";
import FilePicker from "@/components/file-picker";
import HexView from "@/components/hex-view";

const CONF: Record<string, { v: number; color: string }> = {
  certain: { v: 100, color: "var(--color-live)" },
  high: { v: 80, color: "var(--color-live)" },
  medium: { v: 55, color: "var(--color-orphan)" },
  low: { v: 25, color: "var(--color-dim)" },
  none: { v: 0, color: "var(--color-edge)" },
};

const RECENTS_KEY = "sutramfs.recent-images";

function useRecents(): [string[], (p: string) => void] {
  const [recents, setRecents] = useState<string[]>([]);
  useEffect(() => {
    try {
      setRecents(JSON.parse(localStorage.getItem(RECENTS_KEY) ?? "[]"));
    } catch { /* ignore */ }
  }, []);
  const push = (p: string) => {
    const next = [p, ...recents.filter((r) => r !== p)].slice(0, 8);
    setRecents(next);
    try {
      localStorage.setItem(RECENTS_KEY, JSON.stringify(next));
    } catch { /* ignore */ }
  };
  return [recents, push];
}

function Ttl({ unix }: { unix: number }) {
  const [, tick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, []);
  const left = Math.max(0, unix - Math.floor(Date.now() / 1000));
  const m = Math.floor(left / 60);
  const s = left % 60;
  return (
    <span
      className="mono text-[11px]"
      style={{ color: left < 120 ? "var(--color-deleted)" : "var(--color-dim)" }}
    >
      {m}:{String(s).padStart(2, "0")}
    </span>
  );
}

const PART_COLORS = [
  "var(--color-accent)", "var(--color-accent2)", "var(--color-live)",
  "var(--color-orphan)", "var(--color-symlink)", "#4dd0e1", "#f06292",
];

interface DeviceInfo {
  path: string;
  raw_node: string;
  is_raw: boolean;
  readable: boolean;
  device: {
    bus: string;
    size: number;
    internal: boolean;
    mounted: boolean;
    mount_point: string;
    fs_name: string;
    fs_visible: string;
    writable_volume: boolean;
    media_type: string;
  };
}

function CopyCmd({ cmd }: { cmd: string }) {
  const toast = useToast();
  return (
    <button
      className="mono inline-flex cursor-pointer items-center gap-1.5 rounded border border-[var(--color-edge2)] bg-[var(--color-bg)] px-1.5 py-0.5 text-[11px] text-[var(--color-accent)] hover:border-[var(--color-accent)]"
      onClick={() => {
        navigator.clipboard.writeText(cmd);
        toast.push("command copied", "success");
      }}
      title="copy"
    >
      {cmd} <Icon name="copy" size={10} />
    </button>
  );
}

export default function ImagePage() {
  const router = useRouter();
  const { mounts, add, remove } = useMounts();
  const toast = useToast();
  const { setStatus } = useActivity();
  const [recents, pushRecent] = useRecents();

  const [path, setPath] = useState("");
  const [pickerOpen, setPickerOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [detections, setDetections] = useState<Detection[] | null>(null);
  const [parts, setParts] = useState<Partition[] | null>(null);
  const [selParts, setSelParts] = useState<Set<number>>(new Set());
  const [android, setAndroid] = useState<AndroidLayout | null>(null);
  const [parser, setParser] = useState("");
  const [strict, setStrict] = useState(false);
  const [checkMagic, setCheckMagic] = useState(true);
  const [orphans, setOrphans] = useState(true);
  const [hexPeek, setHexPeek] = useState<Uint8Array | null>(null);
  const [device, setDevice] = useState<DeviceInfo | null>(null);

  // Block-device awareness: when the path is a /dev/ node, fetch transport +
  // mount diagnostics so the user confirms posture before probing.
  useEffect(() => {
    const p = path.trim();
    if (!p.startsWith("/dev/")) {
      setDevice(null);
      return;
    }
    const t = setTimeout(async () => {
      try {
        const res = await fetch(`/api/fs/device?path=${encodeURIComponent(p)}`);
        const data = await res.json();
        setDevice(res.ok ? data : null);
      } catch {
        setDevice(null);
      }
    }, 350);
    return () => clearTimeout(t);
  }, [path]);

  const probe = async (p = path) => {
    const target = p.trim();
    if (!target) return;
    setPath(target);
    setBusy(true);
    setErr(null);
    setDetections(null);
    setParts(null);
    setSelParts(new Set());
    setAndroid(null);
    setHexPeek(null);
    setStatus("probing image…");
    try {
      const [d, pt, a, hx] = await Promise.allSettled([
        api.detect(target),
        api.parts(target),
        api.android(target),
        fetch(`/api/fs/read?path=${encodeURIComponent(target)}&offset=0&len=512`)
          .then((r) => (r.ok ? r.arrayBuffer() : null)),
      ]);
      if (d.status === "fulfilled") {
        setDetections(d.value.results);
        pushRecent(target);
      } else setErr(d.reason?.message ?? "detect failed");
      if (pt.status === "fulfilled") setParts(pt.value.partitions);
      if (a.status === "fulfilled") {
        const l = a.value.layout;
        if (l.container || l.partitions.length) setAndroid(l);
      }
      if (hx.status === "fulfilled" && hx.value)
        setHexPeek(new Uint8Array(hx.value));
    } finally {
      setBusy(false);
      setStatus("");
    }
  };

  const mount = async (offset = 0, length = 0, label?: string) => {
    setBusy(true);
    setErr(null);
    setStatus("mounting…");
    try {
      const res = await api.mount({
        path: path.trim(), offset, length, parser,
        strict, check_magic: checkMagic, include_orphans: orphans,
      });
      add({ ...res.mount, label });
      toast.push(`mounted ${res.mount.fs_type} (${res.mount.parser})`, "success");
      router.push(`/browse?m=${encodeURIComponent(res.mount.id)}`);
    } catch (e: any) {
      setErr(e.message);
      toast.push(e.message, "error");
    } finally {
      setBusy(false);
      setStatus("");
    }
  };

  const mountSelected = async () => {
    const ps = (parts ?? []).filter((p) => selParts.has(p.index));
    if (!ps.length) return;
    setBusy(true);
    setErr(null);
    setStatus(`mounting ${ps.length} partitions…`);
    const ok: MountInfo[] = [];
    const fails: string[] = [];
    await Promise.all(
      ps.map(async (p) => {
        try {
          const res = await api.mount({
            path: path.trim(), offset: p.offset, length: p.size, parser,
            strict, check_magic: checkMagic, include_orphans: orphans,
          });
          const m: MountInfo = { ...res.mount, label: `part${p.index} ${path.split("/").pop()}` };
          add(m);
          ok.push(m);
        } catch (e: any) {
          fails.push(`part${p.index}: ${e.message}`);
        }
      }),
    );
    setBusy(false);
    setStatus("");
    if (fails.length) {
      setErr(fails.join(" · "));
      toast.push(fails.join(" · "), "error");
    }
    if (ok.length) {
      toast.push(`mounted ${ok.length} partition${ok.length > 1 ? "s" : ""}`, "success");
      router.push(`/browse?m=${ok.map((m) => m.id).join(",")}`);
    }
  };

  const togglePart = (i: number) =>
    setSelParts((s) => {
      const next = new Set(s);
      next.has(i) ? next.delete(i) : next.add(i);
      return next;
    });

  const unmount = async (m: MountInfo) => {
    try {
      await api.unmount(m.id);
      toast.push(`unmounted ${m.label}`, "info");
    } catch {
      /* handle may already be expired */
    }
    remove(m.id);
  };

  const totalSize = useMemo(
    () => (parts ?? []).reduce((a, p) => Math.max(a, p.offset + p.size), 0),
    [parts],
  );

  return (
    <div className="mx-auto max-w-5xl space-y-4 p-4">
      <Panel title="Evidence image">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Icon
              name="hard-drive" size={14}
              className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--color-faint)]"
            />
            <input
              className={`${input} pl-8 mono`}
              placeholder="/path/to/disk.img"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && probe()}
            />
          </div>
          <Button icon="folder-open" onClick={() => setPickerOpen(true)}>
            browse…
          </Button>
          <Button
            variant="primary" icon={busy ? undefined : "zap"}
            onClick={() => probe()} disabled={busy || !path.trim()}
          >
            {busy ? <Spinner size={12} /> : null} probe
          </Button>
        </div>

        {recents.length > 0 && (
          <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] text-[var(--color-faint)]">recent:</span>
            {recents.map((r) => (
              <button
                key={r}
                onClick={() => probe(r)}
                className="mono max-w-64 truncate rounded border border-[var(--color-edge)] bg-[var(--color-panel2)] px-1.5 py-0.5 text-[11px] text-[var(--color-dim)] hover:border-[var(--color-accent)] hover:text-[var(--color-fg)] cursor-pointer"
                title={r}
              >
                {r.split("/").pop()}
              </button>
            ))}
          </div>
        )}
        <Err msg={err} />
      </Panel>

      {device && (
        <Panel title="Device diagnostics">
          <div className="flex flex-wrap items-center gap-1.5">
            {device.device.bus && <Badge color="var(--color-accent)">{device.device.bus}</Badge>}
            {device.device.size > 0 && <Badge>{fmtBytes(device.device.size)}</Badge>}
            <Badge>{device.device.internal ? "internal" : "external"}</Badge>
            {device.device.fs_visible && <Badge>{device.device.fs_visible}</Badge>}
            {device.device.mounted ? (
              <Badge color="var(--color-warn)">mounted</Badge>
            ) : (
              <Badge color="var(--color-live)">unmounted</Badge>
            )}
            {device.readable ? (
              <Badge color="var(--color-live)">readable</Badge>
            ) : (
              <Badge color="var(--color-deleted)">no read access</Badge>
            )}
          </div>

          <div className="mt-3 space-y-2 text-[12px]">
            {!device.is_raw && (
              <p className="flex flex-wrap items-center gap-2 text-[var(--color-dim)]">
                <Icon name="zap" size={13} className="text-[var(--color-accent)]" />
                buffered block node — use the raw device for ~10x faster reads:
                <button
                  className="mono text-[var(--color-accent)] underline cursor-pointer"
                  onClick={() => setPath(device.raw_node)}
                >
                  {device.raw_node}
                </button>
              </p>
            )}

            {device.device.mounted && (
              <p className="flex flex-wrap items-center gap-2">
                <Icon name="alert-triangle" size={13} className="text-[var(--color-warn)]" />
                <span>
                  volume is <b>mounted</b> at{" "}
                  <span className="mono">{device.device.mount_point}</span>
                  {device.device.writable_volume && " and writable"}
                  {" — the live filesystem can change under analysis. For write-blocker posture:"}
                </span>
                <CopyCmd cmd={`sudo diskutil unmount ${device.device.node ?? device.path}`} />
              </p>
            )}

            {!device.readable && (
              <p className="flex flex-wrap items-center gap-2">
                <Icon name="alert-triangle" size={13} className="text-[var(--color-deleted)]" />
                <span>
                  this process can't read {device.path} (macOS restricts raw
                  devices to root). Grant read access:
                </span>
                <CopyCmd cmd={`sudo chmod o+r ${device.raw_node}`} />
                <span className="text-[var(--color-faint)]">
                  or run sutramfsd under sudo — the GUI connects to an existing daemon.
                </span>
              </p>
            )}
          </div>
        </Panel>
      )}

      {detections && (
        <Panel
          title="Filesystem detection"
          right={
            <div className="flex items-center gap-2 text-[11px]">
              <span className="text-[var(--color-faint)]">parser:</span>
              <select className={select} value={parser} onChange={(e) => setParser(e.target.value)}>
                <option value="">auto</option>
                {detections.filter((d) => d.confidence !== "none").map((d) => (
                  <option key={d.parser} value={d.parser}>{d.parser}</option>
                ))}
              </select>
            </div>
          }
        >
          <div className="space-y-1.5">
            {[...detections]
              .sort(
                (a, b) =>
                  (CONF[b.confidence]?.v ?? 0) - (CONF[a.confidence]?.v ?? 0),
              )
              .map((d) => {
                const c = CONF[d.confidence] ?? CONF.none;
                const dead = d.confidence === "none";
                return (
                  <div key={d.parser} className={`flex items-center gap-3 ${dead ? "opacity-40" : ""}`}>
                    <span className={`mono w-12 text-[12px] ${dead ? "text-[var(--color-faint)]" : ""}`}>
                      {d.parser}
                    </span>
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-[var(--color-edge)]">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{ width: `${c.v}%`, background: c.color }}
                      />
                    </div>
                    <span
                      className="w-16 text-right text-[11px]"
                      style={{ color: dead ? "var(--color-faint)" : c.color }}
                    >
                      {d.confidence}
                    </span>
                  </div>
                );
              })}
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-[var(--color-edge)] pt-3">
            <Toggle checked={strict} onChange={setStrict} label="strict mode" />
            <Toggle checked={checkMagic} onChange={setCheckMagic} label="magic checks" />
            <Toggle checked={orphans} onChange={setOrphans} label="include orphans" />
            <span className="flex-1" />
            <Button variant="primary" icon="play" onClick={() => mount()} disabled={busy}>
              mount whole image
            </Button>
          </div>
        </Panel>
      )}

      {parts && parts.length > 0 && (
        <Panel
          title={`Partition map (${parts.length})`}
          pad={false}
          right={
            <Button
              variant="primary" icon="play" disabled={busy || selParts.size === 0}
              onClick={mountSelected}
            >
              mount selected{selParts.size > 0 ? ` (${selParts.size})` : ""}
            </Button>
          }
        >
          <div className="flex h-7 w-full overflow-hidden">
            {parts.map((p, i) => (
              <div
                key={p.index}
                title={`#${p.index} ${fmtBytes(p.size)} @ ${fmtHex(p.offset)}`}
                className="h-full border-r border-[var(--color-bg)] transition-opacity hover:opacity-75"
                style={{
                  width: `${Math.max(1.5, (p.size / Math.max(totalSize, 1)) * 100)}%`,
                  background: PART_COLORS[i % PART_COLORS.length],
                }}
              />
            ))}
          </div>
          <table className="w-full text-left text-[12px]">
            <thead className="text-[var(--color-faint)]">
              <tr>
                <th className="w-8 px-3.5 py-1.5">
                  <input
                    type="checkbox"
                    className="accent-[var(--color-accent)] cursor-pointer"
                    checked={selParts.size === parts.length && parts.length > 0}
                    onChange={() =>
                      setSelParts(
                        selParts.size === parts.length
                          ? new Set()
                          : new Set(parts.map((p) => p.index)),
                      )
                    }
                  />
                </th>
                <th className="px-1 py-1.5 font-medium">#</th>
                <th className="font-medium">offset</th>
                <th className="font-medium">size</th>
                <th className="font-medium">table</th>
                <th className="font-medium">type</th>
                <th className="font-medium">label</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {parts.map((p, i) => (
                <tr key={p.index} className="border-t border-[var(--color-edge)]/60 hover:bg-[var(--color-panel2)]">
                  <td className="px-3.5 py-1.5">
                    <input
                      type="checkbox"
                      className="accent-[var(--color-accent)] cursor-pointer"
                      checked={selParts.has(p.index)}
                      onChange={() => togglePart(p.index)}
                    />
                  </td>
                  <td className="px-1 py-1.5">
                    <span
                      className="mr-1.5 inline-block h-2 w-2 rounded-sm align-middle"
                      style={{ background: PART_COLORS[i % PART_COLORS.length] }}
                    />
                    {p.index}
                  </td>
                  <td className="mono" title={fmtHex(p.offset)}>{fmtBytes(p.offset)}</td>
                  <td className="mono">{fmtBytes(p.size)}</td>
                  <td>{p.table}</td>
                  <td className="mono max-w-56 truncate text-[var(--color-dim)]" title={p.kind}>{p.kind}</td>
                  <td>{p.label}</td>
                  <td className="pr-3 text-right">
                    <Button
                      icon="play" disabled={busy}
                      onClick={() => mount(p.offset, p.size, `part${p.index} ${path.split("/").pop()}`)}
                    >
                      mount
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}

      {android && (
        <Panel title={`Android — ${android.container}`}>
          {android.crypto.map((c, i) => (
            <p key={i} className="flex items-center gap-2 text-[var(--color-warn)]">
              <Icon name="shield" size={13} /> {c.kind} on {c.partition} — {c.note}
            </p>
          ))}
          {android.partitions.length > 0 && (
            <table className="mt-2 w-full text-left text-[12px]">
              <thead className="text-[var(--color-faint)]">
                <tr><th className="py-1 font-medium">name</th><th className="font-medium">size</th><th className="font-medium">role</th><th className="font-medium">group</th></tr>
              </thead>
              <tbody>
                {android.partitions.map((p) => (
                  <tr key={p.name} className="border-t border-[var(--color-edge)]/60">
                    <td className="mono py-1">{p.name}</td>
                    <td className="mono">{fmtBytes(p.size)}</td>
                    <td><Badge>{p.role}</Badge></td>
                    <td className="text-[var(--color-dim)]">{p.group}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {android.warnings.map((w, i) => (
            <p key={i} className="mt-1 flex items-center gap-2 text-[var(--color-warn)]">
              <Icon name="alert-triangle" size={12} /> {w}
            </p>
          ))}
        </Panel>
      )}

      {hexPeek && (
        <Panel title="Sector 0 (hex peek)">
          <div className="mono max-h-48 overflow-auto"><HexView bytes={hexPeek} /></div>
        </Panel>
      )}

      <Panel title={`Mounts (${mounts.length})`} pad={false}>
        {mounts.length === 0 ? (
          <Empty title="no active mounts" hint="probe an image and mount it" />
        ) : (
          <div className="grid grid-cols-1 gap-2 p-3 sm:grid-cols-2">
            {mounts.map((m) => (
              <div
                key={m.id}
                className="fadein rounded-md border border-[var(--color-edge)] bg-[var(--color-panel2)] p-3"
              >
                <div className="flex items-center gap-2">
                  <Badge color="var(--color-live)">{m.fs_type}</Badge>
                  <span className="min-w-0 flex-1 truncate text-[12.5px] font-medium">{m.label}</span>
                  <Ttl unix={m.expires_at_unix} />
                </div>
                <p className="mono mt-1 truncate text-[11px] text-[var(--color-faint)]" title={m.image}>
                  {m.image}
                </p>
                <div className="mt-2 flex gap-1.5">
                  <Button icon="folder" onClick={() => router.push(`/browse?m=${encodeURIComponent(m.id)}`)}>
                    browse
                  </Button>
                  <Button icon="activity" variant="ghost" onClick={() => router.push(`/timeline?m=${encodeURIComponent(m.id)}`)}>
                    timeline
                  </Button>
                  <span className="flex-1" />
                  <button className={iconBtn} onClick={() => unmount(m)} title="unmount">
                    <Icon name="eject" size={13} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>

      <FilePicker
        open={pickerOpen}
        onClose={() => setPickerOpen(false)}
        onPick={(p) => {
          setPickerOpen(false);
          probe(p);
        }}
      />
    </div>
  );
}
