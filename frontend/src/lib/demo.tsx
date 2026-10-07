import { createContext, useContext, useState, type ReactNode } from "react";
import type { DemoMode } from "@/api";

const Ctx = createContext<{ mode: DemoMode; setMode: (m: DemoMode) => void }>({ mode: "attack", setMode: () => {} });

export function DemoProvider({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<DemoMode>("attack");
  return <Ctx.Provider value={{ mode, setMode }}>{children}</Ctx.Provider>;
}
export const useDemoMode = () => useContext(Ctx);
