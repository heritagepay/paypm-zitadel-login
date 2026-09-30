"use client";
import { ThemeProvider as ThemeP } from "next-themes";
import { ReactNode } from "react";

export function ThemeProvider({ children }: { children: ReactNode }) {
  return (
    <ThemeP attribute="class" defaultTheme="light" forcedTheme="light" enableSystem={false} storageKey="cp-theme">
      {children}
    </ThemeP>
  );
}
