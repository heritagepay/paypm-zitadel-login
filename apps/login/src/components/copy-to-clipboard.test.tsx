import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { NextIntlClientProvider } from "next-intl";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import en from "../../locales/en.json";
import fr from "../../locales/fr.json";
import { CopyToClipboard } from "./copy-to-clipboard";
const mocks = vi.hoisted(() => ({ copy: vi.fn() }));
vi.mock("copy-to-clipboard", () => ({ default: mocks.copy }));
const view = (locale: "en" | "fr" = "en") => (
  <NextIntlClientProvider locale={locale} messages={locale === "fr" ? fr : en}>
    <CopyToClipboard value="browser-fixture://setup" />
  </NextIntlClientProvider>
);
beforeEach(() => {
  vi.resetAllMocks();
  vi.useFakeTimers();
  mocks.copy.mockReturnValue(true);
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});
describe("accessible truthful setup-link copy", () => {
  it.each(["en", "fr"] as const)("names the native control and announces confirmed copy in %s", (locale) => {
    const t = locale === "fr" ? fr : en;
    render(view(locale));
    const button = screen.getByRole("button", { name: t.paypmAuth.copySetupLink });
    fireEvent.click(button);
    expect(mocks.copy).toHaveBeenCalledWith("browser-fixture://setup");
    expect(screen.getByRole("status")).toHaveTextContent(t.paypmAuth.setupLinkCopied);
    expect(button.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
    act(() => vi.advanceTimersByTime(1000));
    expect(screen.getByRole("status")).toBeEmptyDOMElement();
  });
  it.each([false, "throw"] as const)("keeps failed %s copy truthful and permits retry", (result) => {
    if (result === "throw")
      mocks.copy.mockImplementationOnce(() => {
        throw new Error("opaque clipboard failure");
      });
    else mocks.copy.mockReturnValueOnce(false);
    render(view("fr"));
    const button = screen.getByRole("button");
    fireEvent.click(button);
    expect(screen.getByRole("status")).toHaveTextContent(fr.paypmAuth.setupLinkCopyError);
    expect(screen.getByRole("status")).not.toHaveTextContent(fr.paypmAuth.setupLinkCopied);
    fireEvent.click(button);
    expect(screen.getByRole("status")).toHaveTextContent(fr.paypmAuth.setupLinkCopied);
  });
  it("cleans the transient confirmation timer on unmount", () => {
    const { unmount } = render(view());
    fireEvent.click(screen.getByRole("button"));
    expect(vi.getTimerCount()).toBe(1);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});
