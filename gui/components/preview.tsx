"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { isTextPreview } from "@/lib/format";
import HexView from "./hex-view";
import { btn, iconBtn, Spinner } from "./ui";
import { Icon } from "@/lib/icons";

const IMG_EXT = /\.(png|jpe?g|gif|bmp|webp|ico|svg)$/i;
const IMG_MAGIC: [number[], string][] = [
  [[0x89, 0x50, 0x4e, 0x47], "image/png"],
  [[0xff, 0xd8, 0xff], "image/jpeg"],
  [[0x47, 0x49, 0x46], "image/gif"],
  [[0x42, 0x4d], "image/bmp"],
];

type Tab = "auto" | "hex" | "text" | "image";

export default function Preview({
  mount,
  path,
  size,
}: {
  mount: string;
  path: string;
  size: number;
}) {
  const [tab, setTab] = useState<Tab>("auto");
  const [bytes, setBytes] = useState<Uint8Array | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setBytes(null);
    setErr(null);
    setTab("auto");
    if (size === 0) return;
    let cancelled = false;
    setLoading(true);
    fetch(api.readUrl(mount, path, "&preview=1&len=262144"))
      .then(async (r) => {
        if (!r.ok) {
          const d = await r.json().catch(() => ({}));
          throw new Error(d.error || `HTTP ${r.status}`);
        }
        return r.arrayBuffer();
      })
      .then((b) => !cancelled && setBytes(new Uint8Array(b)))
      .catch((e) => !cancelled && setErr(e.message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [mount, path, size]);

  const isImage = useMemo(() => {
    if (!bytes || bytes.length < 4) return false;
    if (IMG_EXT.test(path)) return true;
    return IMG_MAGIC.some(([sig]) => sig.every((b, i) => bytes[i] === b));
  }, [bytes, path]);

  const textLike = bytes ? isTextPreview(bytes) : false;
  const effective: Tab =
    tab === "auto" ? (isImage ? "image" : textLike ? "text" : "hex") : tab;

  const blobUrl = useMemo(() => {
    if (!bytes || effective !== "image") return null;
    const mime =
      IMG_MAGIC.find(([sig]) => sig.every((b, i) => bytes[i] === b))?.[1] ??
      "image/png";
    return URL.createObjectURL(new Blob([bytes as BlobPart], { type: mime }));
  }, [bytes, effective]);

  useEffect(() => () => {
    if (blobUrl) URL.revokeObjectURL(blobUrl);
  }, [blobUrl]);

  return (
    <div>
      <div className="mb-2 flex items-center gap-1">
        {(["auto", "hex", "text", "image"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`rounded px-2 py-0.5 text-[11px] capitalize cursor-pointer ${
              effective === t && tab !== "auto"
                ? "bg-[var(--color-accent)]/15 text-[var(--color-accent)]"
                : tab === t
                  ? "bg-[var(--color-accent)]/15 text-[var(--color-accent)]"
                  : "text-[var(--color-dim)] hover:text-[var(--color-fg)]"
            }`}
          >
            {t}
          </button>
        ))}
        <span className="ml-auto" />
        <a className={btn} href={api.readUrl(mount, path, "&download=1")}>
          <Icon name="download" size={12} /> download
        </a>
      </div>
      {loading && (
        <div className="flex items-center gap-2 text-[var(--color-dim)]">
          <Spinner size={12} /> reading…
        </div>
      )}
      {err && <p className="text-[var(--color-deleted)] text-[12px]">{err}</p>}
      {bytes && bytes.length === 0 && (
        <p className="text-[var(--color-dim)]">no recoverable bytes</p>
      )}
      {bytes && bytes.length > 0 && (
        <div className="max-h-72 overflow-auto rounded-md border border-[var(--color-edge)] bg-[var(--color-bg)] p-2">
          {effective === "image" && blobUrl ? (
            <img src={blobUrl} alt={path} className="max-w-full" />
          ) : effective === "text" ? (
            <pre className="mono whitespace-pre-wrap break-all text-[11.5px]">
              {new TextDecoder().decode(bytes)}
            </pre>
          ) : (
            <HexView bytes={bytes} />
          )}
        </div>
      )}
    </div>
  );
}
