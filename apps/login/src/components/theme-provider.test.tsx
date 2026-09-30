import { render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ThemeProvider } from "./theme-provider";

describe("PayPM Login theme", () => {
  const storedTheme = new Map<string, string>();

  beforeEach(() => {
    vi.stubGlobal("localStorage", {
      getItem: (key: string) => storedTheme.get(key) ?? null,
      setItem: (key: string, value: string) => storedTheme.set(key, value),
      removeItem: (key: string) => storedTheme.delete(key),
      clear: () => storedTheme.clear(),
    });
    localStorage.setItem("cp-theme", "dark");
    document.documentElement.classList.add("dark");
    vi.stubGlobal("matchMedia", () => ({
      matches: true,
      media: "(prefers-color-scheme: dark)",
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    }));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    storedTheme.clear();
    document.documentElement.classList.remove("dark", "light");
  });

  it("stays light even with a saved dark choice and a dark system preference", async () => {
    const { getByText } = render(
      <ThemeProvider>
        <span>PayPM login</span>
      </ThemeProvider>,
    );

    expect(getByText("PayPM login")).toBeTruthy();
    await waitFor(() => {
      expect(document.documentElement.classList.contains("light")).toBe(true);
      expect(document.documentElement.classList.contains("dark")).toBe(false);
    });
  });
});
