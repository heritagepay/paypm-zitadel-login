import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { NextIntlClientProvider } from "next-intl";
import { afterEach, describe, expect, it, vi } from "vitest";
import englishMessages from "../../../locales/en.json";
import frenchMessages from "../../../locales/fr.json";
import LoginError from "./error";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("Login error boundary", () => {
  it.each([
    ["en", englishMessages],
    ["fr", frenchMessages],
  ] as const)("should offer translated recovery in %s and preserve reset", (locale, messages) => {
    const reset = vi.fn();
    const error = new Error("INTERNAL provider failure: client_secret=private-value");
    render(
      <NextIntlClientProvider locale={locale} messages={messages}>
        <LoginError error={error} reset={reset} />
      </NextIntlClientProvider>,
    );

    expect(screen.getByRole("heading", { level: 1, name: messages.paypmAuth.unavailableTitle })).toBeVisible();
    expect(screen.getByRole("alert")).toHaveTextContent(messages.paypmAuth.unavailableDescription);
    expect(screen.getByText("PayPM")).toBeVisible();
    expect(reset).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: messages.paypmAuth.tryAgain }));
    expect(reset).toHaveBeenCalledOnce();
  });

  it("should omit raw exception messages, digests and debug labels", () => {
    const log = vi.spyOn(console, "log");
    const error = Object.assign(new Error("INTERNAL provider failure: client_secret=private-value"), {
      digest: "private-trace-digest",
    });
    const { container } = render(
      <NextIntlClientProvider locale="en" messages={englishMessages}>
        <LoginError error={error} reset={vi.fn()} />
      </NextIntlClientProvider>,
    );

    expect(container.innerHTML).not.toContain(error.message);
    expect(container.innerHTML).not.toContain(error.digest);
    expect(screen.queryByText("Login Error")).toBeNull();
    expect(log).not.toHaveBeenCalled();
  });
});
