"use client";

import { createContext, useCallback, useContext, useState } from "react";

// One-line status shown in the shell's status bar while work is running.
const Ctx = createContext<{
  status: string;
  setStatus: (s: string) => void;
}>({ status: "", setStatus: () => {} });

export function useActivity() {
  return useContext(Ctx);
}

export function ActivityProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState("");
  const set = useCallback((s: string) => setStatus(s), []);
  return <Ctx.Provider value={{ status, setStatus: set }}>{children}</Ctx.Provider>;
}
