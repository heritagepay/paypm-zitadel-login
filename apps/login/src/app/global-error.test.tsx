import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import englishMessages from "../../locales/en.json";
import frenchMessages from "../../locales/fr.json";
import GlobalError from "./global-error";

vi.mock("@/lib/paypm-font", () => ({ paypmFont: { className: "paypm-test-font" } }));

beforeEach(() => {
  vi.spyOn(navigator, "language", "get").mockReturnValue("en-US");
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  document.documentElement.removeAttribute("lang");
  document.documentElement.removeAttribute("class");
  document.documentElement.removeAttribute("style");
});

describe("Global error boundary", () => {
  it("should provide standalone light recovery without failed root providers", () => {
    const reset = vi.fn();
    const error = Object.assign(new Error("INTERNAL upstream credential: private-value"), {
      digest: "private-trace-digest",
    });
    const { getByRole, getByText, queryByText } = render(<GlobalError error={error} reset={reset} />, {
      container: document,
      baseElement: document,
    });

    expect(document.documentElement).toHaveAttribute("lang", "en");
    expect(document.documentElement).toHaveClass("paypm-test-font");
    expect(document.documentElement).toHaveStyle({ colorScheme: "light" });
    expect(document.querySelector('meta[name="color-scheme"]')).toHaveAttribute("content", "light");
    expect(getByRole("heading", { level: 1, name: englishMessages.paypmAuth.unavailableTitle })).toBeVisible();
    expect(getByRole("alert")).toHaveTextContent(englishMessages.paypmAuth.unavailableDescription);
    expect(getByText("PayPM")).toBeVisible();
    expect(document.documentElement.innerHTML).not.toContain(error.message);
    expect(document.documentElement.innerHTML).not.toContain(error.digest);
    expect(queryByText("Login Error")).toBeNull();
    expect(reset).not.toHaveBeenCalled();

    fireEvent.click(getByRole("button", { name: englishMessages.paypmAuth.tryAgain }));
    expect(reset).toHaveBeenCalledOnce();
  });

  it("should recognize French browser locales without a translation provider", () => {
    vi.spyOn(navigator, "language", "get").mockReturnValue("fr-CI");
    const { getByRole } = render(<GlobalError error={new Error("private-value")} reset={vi.fn()} />, {
      container: document,
      baseElement: document,
    });

    expect(document.documentElement).toHaveAttribute("lang", "fr");
    expect(getByRole("heading", { level: 1, name: frenchMessages.paypmAuth.unavailableTitle })).toBeVisible();
    expect(getByRole("combobox", { name: frenchMessages.paypmAuth.language })).toHaveValue("fr");
    expect(document.title).toBe(`${frenchMessages.paypmAuth.unavailableTitle} · PayPM`);
  });

  it("should allow a local native language choice and keep retry available", () => {
    const reset = vi.fn();
    const { getByRole } = render(<GlobalError error={new Error("private-value")} reset={reset} />, {
      container: document,
      baseElement: document,
    });
    const selector = getByRole("combobox", { name: englishMessages.paypmAuth.language });
    fireEvent.change(selector, { target: { value: "fr" } });

    expect(document.documentElement).toHaveAttribute("lang", "fr");
    expect(getByRole("combobox", { name: frenchMessages.paypmAuth.language })).toHaveValue("fr");
    expect(getByRole("alert")).toHaveTextContent(frenchMessages.paypmAuth.unavailableDescription);
    expect(document.title).toBe(`${frenchMessages.paypmAuth.unavailableTitle} · PayPM`);
    fireEvent.click(getByRole("button", { name: frenchMessages.paypmAuth.tryAgain }));
    expect(reset).toHaveBeenCalledOnce();

    fireEvent.change(selector, { target: { value: "en" } });
    expect(document.documentElement).toHaveAttribute("lang", "en");
    expect(getByRole("heading", { level: 1, name: englishMessages.paypmAuth.unavailableTitle })).toBeVisible();
  });

  it("should use the supported English fallback for another browser language", () => {
    vi.spyOn(navigator, "language", "get").mockReturnValue("de-DE");
    const { getByRole } = render(<GlobalError error={new Error("private-value")} reset={vi.fn()} />, {
      container: document,
      baseElement: document,
    });

    expect(document.documentElement).toHaveAttribute("lang", "en");
    expect(getByRole("button", { name: englishMessages.paypmAuth.tryAgain })).toBeVisible();
  });
});
