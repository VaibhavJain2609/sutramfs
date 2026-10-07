"use client";

import type { FsEntry } from "./types";

async function jsonOrThrow(res: Response) {
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

export const api = {
  detect: (path: string) =>
    fetch("/api/detect", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ path }),
    }).then(jsonOrThrow),

  parts: (image: string) =>
    fetch(`/api/parts?image=${encodeURIComponent(image)}`).then(jsonOrThrow),

  android: (image: string) =>
    fetch(`/api/android?image=${encodeURIComponent(image)}`).then(jsonOrThrow),

  mount: (body: {
    path: string;
    offset?: number;
    length?: number;
    parser?: string;
    strict?: boolean;
    check_magic?: boolean;
    include_orphans?: boolean;
  }) =>
    fetch("/api/mount", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }).then(jsonOrThrow),

  unmount: (id: string) =>
    fetch("/api/unmount", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id }),
    }).then(jsonOrThrow),

  readUrl: (handle: string, path: string, extra = "") =>
    `/api/read?handle=${encodeURIComponent(handle)}&path=${encodeURIComponent(path)}${extra}`,

  hash: (handle: string, path: string) =>
    fetch(
      `/api/hash?handle=${encodeURIComponent(handle)}&path=${encodeURIComponent(path)}`,
    ).then(jsonOrThrow),

  health: () => fetch("/api/health").then(jsonOrThrow),
};

export interface WalkCallbacks {
  onEntry?: (e: FsEntry) => void;
  onLog?: (line: string) => void;
  onDone?: (code: number) => void;
  onError?: (msg: string) => void;
  signal?: AbortSignal;
}

/** Consume an NDJSON endpoint (walk or remnants) incrementally. */
export async function streamNdjson(
  url: string,
  cb: WalkCallbacks,
): Promise<void> {
  const res = await fetch(url, { signal: cb.signal });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let idx: number;
    while ((idx = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (!line) continue;
      let obj: any;
      try {
        obj = JSON.parse(line);
      } catch {
        continue;
      }
      if (obj.__error) cb.onError?.(obj.__error);
      else if (obj.__log) cb.onLog?.(obj.__log);
      else if (obj.__done) cb.onDone?.(obj.code);
      else cb.onEntry?.(obj as FsEntry);
    }
  }
}
