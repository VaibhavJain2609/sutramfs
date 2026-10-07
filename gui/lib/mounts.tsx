"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import type { MountInfo } from "./types";

// Active mounts live in sessionStorage so a page refresh keeps them (until
// the daemon-side TTL evicts the handle).

interface MountsCtx {
  mounts: MountInfo[];
  add: (m: MountInfo) => void;
  remove: (id: string) => void;
  get: (id: string) => MountInfo | undefined;
}

const Ctx = createContext<MountsCtx>({
  mounts: [],
  add: () => {},
  remove: () => {},
  get: () => undefined,
});

const KEY = "sutramfs.mounts";

export function MountsProvider({ children }: { children: React.ReactNode }) {
  const [mounts, setMounts] = useState<MountInfo[]>([]);

  useEffect(() => {
    try {
      const raw = sessionStorage.getItem(KEY);
      if (raw) setMounts(JSON.parse(raw));
    } catch {
      /* ignore */
    }
  }, []);

  const persist = (next: MountInfo[]) => {
    setMounts(next);
    try {
      sessionStorage.setItem(KEY, JSON.stringify(next));
    } catch {
      /* ignore */
    }
  };

  const add = useCallback(
    (m: MountInfo) =>
      persist([
        ...mounts.filter((x) => x.id !== m.id),
        { ...m, label: m.label ?? `${m.fs_type} @ ${m.image}` },
      ]),
    [mounts],
  );

  const remove = useCallback(
    (id: string) => persist(mounts.filter((x) => x.id !== id)),
    [mounts],
  );

  const get = useCallback((id: string) => mounts.find((x) => x.id === id), [mounts]);

  return (
    <Ctx.Provider value={{ mounts, add, remove, get }}>
      {children}
    </Ctx.Provider>
  );
}

export function useMounts() {
  return useContext(Ctx);
}
