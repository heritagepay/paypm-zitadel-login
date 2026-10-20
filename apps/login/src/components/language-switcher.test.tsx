import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { NextIntlClientProvider } from "next-intl";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import en from "../../locales/en.json";
import fr from "../../locales/fr.json";
import { LanguageSwitcher } from "./language-switcher";

const mocks = vi.hoisted(() => ({ setLanguageCookie: vi.fn(), refresh: vi.fn() }));
vi.mock("@/lib/cookies", () => ({ setLanguageCookie: mocks.setLanguageCookie }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: mocks.refresh }) }));
const languages = [
  { code: "en", name: "English" },
  { code: "fr", name: "Français" },
];
const view = (locale: "en" | "fr" = "en", options = languages) => (
  <NextIntlClientProvider locale={locale} messages={locale === "fr" ? fr : en}>
    <LanguageSwitcher languages={options} />
  </NextIntlClientProvider>
);
beforeEach(() => {
  vi.resetAllMocks();
  mocks.setLanguageCookie.mockResolvedValue(undefined);
});
afterEach(cleanup);

describe("server-confirmed language selection", () => {
  test("uses accessible full language names and current provider locale", () => {
    render(view("fr"));
    expect(screen.getByRole("combobox", { name: "Langue" })).toHaveValue("fr");
    expect(screen.getByRole("option", { name: "English" })).toBeInTheDocument();
  });

  test("writes a valid selection then refreshes without claiming an unconfirmed locale", async () => {
    const { rerender } = render(view());
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "fr" } });
    await waitFor(() => expect(mocks.refresh).toHaveBeenCalledOnce());
    expect(mocks.setLanguageCookie).toHaveBeenCalledWith("fr");
    expect(screen.getByRole("combobox")).toHaveValue("en");
    rerender(view("fr"));
    expect(screen.getByRole("combobox", { name: "Langue" })).toHaveValue("fr");
  });

  test("serializes pending writes and exposes pending semantics", async () => {
    let resolveWrite!: () => void;
    mocks.setLanguageCookie.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          resolveWrite = resolve;
        }),
    );
    render(view());
    const select = screen.getByRole("combobox");
    fireEvent.change(select, { target: { value: "fr" } });
    expect(select).toBeDisabled();
    expect(select.parentElement).toHaveAttribute("aria-busy", "true");
    fireEvent.change(select, { target: { value: "fr" } });
    expect(mocks.setLanguageCookie).toHaveBeenCalledOnce();
    await act(async () => resolveWrite());
    expect(select).not.toBeDisabled();
  });

  test.each(["en", "fr"] as const)("keeps locale and exposes retryable write failure in %s", async (locale) => {
    mocks.setLanguageCookie.mockRejectedValueOnce(new Error("provider unavailable"));
    render(view(locale));
    const select = screen.getByRole("combobox");
    const destination = locale === "en" ? "fr" : "en";
    fireEvent.change(select, { target: { value: destination } });
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent((locale === "fr" ? fr : en).paypmAuth.languageError);
    expect(select).toHaveAttribute("aria-describedby", alert.id);
    expect(select).toHaveValue(locale);
    expect(mocks.refresh).not.toHaveBeenCalled();
    mocks.setLanguageCookie.mockResolvedValueOnce(undefined);
    fireEvent.change(select, { target: { value: destination } });
    await waitFor(() => expect(mocks.refresh).toHaveBeenCalledOnce());
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  test("does not write the active locale and disables an empty provider list", () => {
    const { rerender } = render(view());
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "en" } });
    expect(mocks.setLanguageCookie).not.toHaveBeenCalled();
    rerender(view("en", []));
    expect(screen.getByRole("combobox")).toBeDisabled();
  });
});
