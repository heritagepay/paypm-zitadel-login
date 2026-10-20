import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { create, timestampFromDate } from "@zitadel/client";
import { SessionSchema } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { NextIntlClientProvider } from "next-intl";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import en from "../../locales/en.json";
import fr from "../../locales/fr.json";
import { SessionClearItem } from "./session-clear-item";

const mocks = vi.hoisted(() => ({ clear: vi.fn() }));
vi.mock("./session-clear-action", () => ({ clearNativeSession: mocks.clear }));
vi.mock("./avatar", () => ({ Avatar: () => <span aria-hidden="true">A</span> }));
const session = create(SessionSchema, {
  id: "browser-logout-session",
  factors: { user: { id: "browser-user", displayName: "Browser account", loginName: "browser@example.invalid" } },
});
const view = (reload: () => void, locale: "en" | "fr" = "en") => (
  <NextIntlClientProvider locale={locale} messages={locale === "fr" ? fr : en}>
    <SessionClearItem session={session} reload={reload} />
  </NextIntlClientProvider>
);
const deferred = () => {
  let resolve!: (value: unknown) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
};
beforeEach(() => vi.resetAllMocks());
afterEach(cleanup);

describe("truthful native logout control", () => {
  it("guards held requests, exposes pending and reloads only after confirmation", async () => {
    const held = deferred(),
      reload = vi.fn();
    mocks.clear.mockReturnValue(held.promise);
    render(view(reload));
    const button = screen.getByRole("button", { name: `${en.logout.clear}: browser@example.invalid` });
    fireEvent.click(button);
    fireEvent.click(button);
    fireEvent.keyDown(button, { key: "Enter" });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("aria-busy", "true");
    expect(mocks.clear).toHaveBeenCalledTimes(1);
    expect(mocks.clear).toHaveBeenCalledWith({ sessionId: session.id });
    expect(reload).not.toHaveBeenCalled();
    await act(async () => held.resolve({ cleared: true }));
    expect(reload).toHaveBeenCalledTimes(1);
    expect(button).toBeEnabled();
  });
  it.each(["en", "fr"] as const)("retains the row after rejected logout and permits retry in %s", async (locale) => {
    const reload = vi.fn();
    mocks.clear.mockRejectedValueOnce(new Error("opaque provider failure"));
    render(view(reload, locale));
    const button = screen.getByRole("button");
    fireEvent.click(button);
    const t = locale === "fr" ? fr : en;
    expect(await screen.findByRole("alert")).toHaveTextContent(t.paypmAuth.sessionError);
    expect(button).toHaveAccessibleDescription(t.paypmAuth.sessionError);
    expect(button).toBeEnabled();
    expect(screen.queryByText("opaque provider failure")).not.toBeInTheDocument();
    expect(reload).not.toHaveBeenCalled();
    mocks.clear.mockResolvedValueOnce({ cleared: true });
    fireEvent.click(button);
    await waitFor(() => expect(reload).toHaveBeenCalledTimes(1));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
  it.each([undefined, {}, { cleared: false }])("does not remove an unconfirmed session for %j", async (acknowledgement) => {
    const reload = vi.fn();
    mocks.clear.mockResolvedValue(acknowledgement);
    render(view(reload));
    fireEvent.click(screen.getByRole("button"));
    expect(await screen.findByRole("alert")).toHaveTextContent(en.paypmAuth.sessionError);
    expect(reload).not.toHaveBeenCalled();
    expect(screen.getByRole("button")).toBeEnabled();
  });
  it.each(["resolve", "reject"] as const)("ignores late %s after unmount", async (outcome) => {
    const held = deferred(),
      reload = vi.fn();
    mocks.clear.mockReturnValue(held.promise);
    const { unmount } = render(view(reload));
    fireEvent.click(screen.getByRole("button"));
    unmount();
    await act(async () =>
      outcome === "resolve" ? held.resolve({ cleared: true }) : held.reject(new Error("opaque failure")),
    );
    expect(reload).not.toHaveBeenCalled();
  });
  it("uses existing French expired copy and keeps the logout command visible", () => {
    const expired = create(SessionSchema, {
      id: session.id,
      expirationDate: timestampFromDate(new Date(0)),
      factors: { user: session.factors?.user, password: { verifiedAt: timestampFromDate(new Date(0)) } },
    });
    render(
      <NextIntlClientProvider locale="fr" messages={fr}>
        <SessionClearItem session={expired} reload={vi.fn()} />
      </NextIntlClientProvider>,
    );
    expect(screen.getByRole("button")).toHaveTextContent(fr.accounts.expired);
    expect(screen.getByRole("button")).toHaveTextContent(fr.logout.clear);
    expect(screen.getByRole("button")).toHaveAttribute("type", "button");
  });
});
