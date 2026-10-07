"use client";

import { createContext, useCallback, useContext, useRef, useState } from "react";
import { Icon } from "./icons";

type Kind = "info" | "success" | "error";
interface Toast {
  id: number;
  kind: Kind;
  msg: string;
}

const Ctx = createContext<{ push: (msg: string, kind?: Kind) => void }>({
  push: () => {},
});

export function useToast() {
  return useContext(Ctx);
}

const COLORS: Record<Kind, string> = {
  info: "var(--color-accent)",
  success: "var(--color-live)",
  error: "var(--color-deleted)",
};
const ICONS: Record<Kind, "info" | "check" | "alert-triangle"> = {
  info: "info",
  success: "check",
  error: "alert-triangle",
};

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);

  const push = useCallback((msg: string, kind: Kind = "info") => {
    const id = nextId.current++;
    setToasts((t) => [...t, { id, kind, msg }].slice(-5));
    setTimeout(
      () => setToasts((t) => t.filter((x) => x.id !== id)),
      kind === "error" ? 8000 : 4000,
    );
  }, []);

  return (
    <Ctx.Provider value={{ push }}>
      {children}
      <div className="fixed bottom-10 right-4 z-50 flex w-80 flex-col gap-2 no-print">
        {toasts.map((t) => (
          <div
            key={t.id}
            className="fadein flex items-start gap-2 rounded-lg border bg-[var(--color-panel3)] p-2.5 text-[12px] shadow-lg"
            style={{ borderColor: `color-mix(in srgb, ${COLORS[t.kind]} 40%, transparent)` }}
          >
            <Icon name={ICONS[t.kind]} size={14} className="mt-0.5 shrink-0" />
            <span className="break-words">{t.msg}</span>
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}
