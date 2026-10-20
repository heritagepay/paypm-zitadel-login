import { ServerActionResponse } from "@/lib/client-utils";
import * as Tooltip from "@radix-ui/react-tooltip";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { create, timestampFromDate } from "@zitadel/client";
import { Session, SessionSchema } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { NextIntlClientProvider } from "next-intl";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import englishMessages from "../../locales/en.json";
import frenchMessages from "../../locales/fr.json";
import { SessionsList } from "./sessions-list";

const { mockClearSession, mockContinueWithSession, mockSendLoginname, mockPush } = vi.hoisted(() => ({
  mockClearSession: vi.fn(),
  mockContinueWithSession: vi.fn(),
  mockSendLoginname: vi.fn(),
  mockPush: vi.fn(),
}));

vi.mock("@/lib/server/session", () => ({
  continueWithSession: mockContinueWithSession,
}));
vi.mock("./session-clear-action", () => ({ clearNativeSession: mockClearSession }));

vi.mock("@/lib/server/loginname", () => ({ sendLoginname: mockSendLoginname }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: mockPush }) }));

function makeSession(id = "session-a", displayName = "Alice", loginName = "alice@example.com"): Session {
  return create(SessionSchema, {
    id,
    changeDate: timestampFromDate(new Date(0)),
    expirationDate: timestampFromDate(new Date(Date.now() + 60 * 60 * 1000)),
    factors: {
      user: { id: `user-${id}`, displayName, loginName, organizationId: "organization-a" },
      password: { verifiedAt: timestampFromDate(new Date(Date.now() - 60 * 1000)) },
    },
  });
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function renderList(sessions: Session[], locale: "en" | "fr" = "en", requestId?: string) {
  const messages = locale === "fr" ? frenchMessages : englishMessages;
  return render(
    <NextIntlClientProvider locale={locale} messages={messages}>
      <Tooltip.Provider>
        <SessionsList sessions={sessions} requestId={requestId} />
      </Tooltip.Provider>
    </NextIntlClientProvider>,
  );
}

beforeEach(() => {
  vi.resetAllMocks();
  vi.spyOn(HTMLFormElement.prototype, "submit").mockImplementation(() => {});
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("Remembered authentication sessions", () => {
  it("should expose separate keyboard-focusable selection and removal buttons", () => {
    renderList([makeSession()]);
    const select = screen.getByRole("button", { name: /Alice.*alice@example.com/ });
    const remove = screen.getByRole("button", {
      name: `${englishMessages.paypmAuth.removeAccount}: alice@example.com`,
    });

    expect(select).toHaveAttribute("type", "button");
    expect(remove).toHaveAttribute("type", "button");
    expect(select.parentElement).toBe(remove.parentElement);
    expect(select.querySelector("button")).toBeNull();
    expect(remove.querySelector("button")).toBeNull();
    expect(remove.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
    select.focus();
    expect(select).toHaveFocus();
    remove.focus();
    expect(remove).toHaveFocus();
    expect(select).toHaveClass("paypm-session-select");
    expect(remove).toHaveClass("paypm-session-remove");
  });

  it("should continue a verified session without mutating its request or account data", async () => {
    const session = Object.freeze(makeSession());
    mockContinueWithSession.mockResolvedValue({ redirect: "/signedin?requestId=request-current" });
    renderList([session], "en", "request-current");
    fireEvent.click(screen.getByRole("button", { name: /Alice.*alice@example.com/ }));

    await waitFor(() => expect(mockPush).toHaveBeenCalledWith("/signedin?requestId=request-current"));
    expect(mockContinueWithSession).toHaveBeenCalledWith({ ...session, requestId: "request-current" });
    expect(mockContinueWithSession.mock.calls[0][0]).not.toBe(session);
    expect(session).not.toHaveProperty("requestId");
    expect(mockSendLoginname).not.toHaveBeenCalled();
    expect(mockClearSession).not.toHaveBeenCalled();
  });

  it("should use the existing identifier flow for an expired verified session", async () => {
    const session = makeSession();
    session.expirationDate = timestampFromDate(new Date(Date.now() - 60 * 1000));
    mockSendLoginname.mockResolvedValue({ redirect: "/password?requestId=request-current" });
    renderList([session], "en", "request-current");
    expect(screen.getByRole("button", { name: /Alice/ })).toHaveTextContent(englishMessages.accounts.expired);
    fireEvent.click(screen.getByRole("button", { name: /Alice.*alice@example.com/ }));

    await waitFor(() => expect(mockPush).toHaveBeenCalledWith("/password?requestId=request-current"));
    expect(mockSendLoginname).toHaveBeenCalledWith({
      loginName: "alice@example.com",
      organization: "organization-a",
      requestId: "request-current",
    });
    expect(mockContinueWithSession).not.toHaveBeenCalled();
  });

  it("should retain SAML fields and automatic submission from the existing response handler", async () => {
    mockContinueWithSession.mockResolvedValue({
      samlData: {
        url: "https://app.example.com/saml",
        fields: { SAMLResponse: "opaque-saml-response", RelayState: "original-request" },
      },
    });
    const { container } = renderList([makeSession()]);
    fireEvent.click(screen.getByRole("button", { name: /Alice.*alice@example.com/ }));

    await waitFor(() => expect(HTMLFormElement.prototype.submit).toHaveBeenCalledOnce());
    const form = container.querySelector("form");
    expect(form).toHaveAttribute("action", "https://app.example.com/saml");
    expect(form).toHaveAttribute("method", "post");
    expect(form?.querySelector('input[name="SAMLResponse"]')).toHaveValue("opaque-saml-response");
    expect(form?.querySelector('input[name="RelayState"]')).toHaveValue("original-request");
  });

  it.each([
    ["en", englishMessages],
    ["fr", frenchMessages],
  ] as const)("should show persistent localized selection failures in %s without raw errors", async (locale, messages) => {
    mockContinueWithSession.mockRejectedValue(new Error("INTERNAL provider-token=private-value"));
    const { container } = renderList([makeSession()], locale);
    const select = screen.getByRole("button", { name: /Alice.*alice@example.com/ });
    fireEvent.click(select);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(messages.paypmAuth.sessionError);
    expect(container.innerHTML).not.toContain("provider-token");
    expect(select).toBeEnabled();
    expect(mockPush).not.toHaveBeenCalled();
    expect(select).toHaveAccessibleDescription(messages.paypmAuth.sessionError);
  });

  it("should show an actionable failure when the server returns no continuation", async () => {
    mockContinueWithSession.mockResolvedValue(undefined);
    renderList([makeSession()]);
    fireEvent.click(screen.getByRole("button", { name: /Alice.*alice@example.com/ }));

    expect(await screen.findByRole("alert")).toHaveTextContent(englishMessages.paypmAuth.sessionError);
    expect(mockPush).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: /Alice.*alice@example.com/ })).toBeEnabled();
  });

  it("should retain the row after clear rejects and offer a retry", async () => {
    mockClearSession.mockRejectedValueOnce(new Error("INTERNAL delete failed"));
    mockClearSession.mockResolvedValueOnce({ cleared: true });
    renderList([makeSession()]);
    const remove = screen.getByRole("button", {
      name: `${englishMessages.paypmAuth.removeAccount}: alice@example.com`,
    });
    fireEvent.click(remove);

    expect(await screen.findByRole("alert")).toHaveTextContent(englishMessages.paypmAuth.sessionError);
    expect(screen.getByRole("button", { name: /Alice.*alice@example.com/ })).toBeVisible();
    expect(remove).toBeEnabled();
    fireEvent.click(remove);

    await waitFor(() => expect(screen.queryByRole("button", { name: /Alice.*alice@example.com/ })).toBeNull());
    expect(screen.getByRole("status")).toHaveTextContent(englishMessages.accounts.noResults);
    expect(mockClearSession).toHaveBeenCalledTimes(2);
    expect(mockContinueWithSession).not.toHaveBeenCalled();
    expect(mockSendLoginname).not.toHaveBeenCalled();
  });

  it.each([undefined, {}, { cleared: false }])(
    "should retain the row without explicit clear confirmation %j",
    async (acknowledgement) => {
      mockClearSession.mockResolvedValue(acknowledgement);
      renderList([makeSession()]);
      fireEvent.click(screen.getByRole("button", { name: `${englishMessages.paypmAuth.removeAccount}: alice@example.com` }));

      expect(await screen.findByRole("alert")).toHaveTextContent(englishMessages.paypmAuth.sessionError);
      expect(screen.getByRole("button", { name: /Alice.*alice@example.com/ })).toBeVisible();
      expect(screen.queryByText(englishMessages.accounts.noResults)).toBeNull();
    },
  );

  it("should block competing account actions and show selection pending until the response settles", async () => {
    const continuation = deferred<ServerActionResponse>();
    mockContinueWithSession.mockReturnValue(continuation.promise);
    renderList([makeSession(), makeSession("session-b", "Bob", "bob@example.com")]);
    const select = screen.getByRole("button", { name: /Alice.*alice@example.com/ });
    fireEvent.click(select);

    expect(select).toHaveAttribute("aria-busy", "true");
    expect(within(select).getByRole("status")).toBeVisible();
    for (const button of screen.getAllByRole("button")) {
      expect(button).toBeDisabled();
      fireEvent.click(button);
    }
    expect(mockContinueWithSession).toHaveBeenCalledOnce();
    expect(mockClearSession).not.toHaveBeenCalled();
    continuation.reject(new Error("Request failed"));

    expect(await screen.findByRole("alert")).toHaveTextContent(englishMessages.paypmAuth.sessionError);
    for (const button of screen.getAllByRole("button")) {
      expect(button).toBeEnabled();
    }
    expect(within(select).queryByRole("status")).toBeNull();
  });

  it("should keep a pending clear row and remove only that row after success", async () => {
    const clearing = deferred<object>();
    mockClearSession.mockReturnValue(clearing.promise);
    renderList([makeSession(), makeSession("session-b", "Bob", "bob@example.com")]);
    const remove = screen.getByRole("button", {
      name: `${englishMessages.paypmAuth.removeAccount}: alice@example.com`,
    });
    fireEvent.click(remove);

    expect(remove).toHaveAttribute("aria-busy", "true");
    expect(within(remove).getByRole("status")).toBeVisible();
    expect(screen.getByRole("button", { name: /Alice.*alice@example.com/ })).toBeVisible();
    for (const button of screen.getAllByRole("button")) {
      expect(button).toBeDisabled();
      fireEvent.click(button);
    }
    expect(mockClearSession).toHaveBeenCalledOnce();
    expect(mockClearSession).toHaveBeenCalledWith({ sessionId: "session-a" });
    expect(mockContinueWithSession).not.toHaveBeenCalled();
    clearing.resolve({ cleared: true });

    await waitFor(() => expect(screen.queryByRole("button", { name: /Alice.*alice@example.com/ })).toBeNull());
    expect(screen.getByRole("button", { name: /Bob.*bob@example.com/ })).toBeEnabled();
    expect(screen.queryByText(englishMessages.accounts.noResults)).toBeNull();
  });

  it("should retain another row's failure state when a preceding row is removed", async () => {
    mockContinueWithSession.mockResolvedValue({ error: "INTERNAL upstream detail" });
    mockClearSession.mockResolvedValue({ cleared: true });
    const { container } = renderList([makeSession(), makeSession("session-b", "Bob", "bob@example.com")]);
    fireEvent.click(screen.getByRole("button", { name: /Bob.*bob@example.com/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent(englishMessages.paypmAuth.sessionError);
    expect(container.innerHTML).not.toContain("upstream detail");
    fireEvent.click(screen.getByRole("button", { name: `${englishMessages.paypmAuth.removeAccount}: alice@example.com` }));

    await waitFor(() => expect(screen.queryByRole("button", { name: /Alice.*alice@example.com/ })).toBeNull());
    expect(screen.getByRole("alert")).toHaveTextContent(englishMessages.paypmAuth.sessionError);
    expect(screen.getByRole("button", { name: /Bob.*bob@example.com/ })).toHaveAccessibleDescription(
      englishMessages.paypmAuth.sessionError,
    );
  });

  it("should show an information message for an actual empty list", () => {
    renderList([]);
    expect(screen.getByRole("status")).toHaveTextContent(englishMessages.accounts.noResults);
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("should show the localized empty state when no supplied session has an account identifier", () => {
    renderList([create(SessionSchema, { id: "unidentified-session" })], "fr");
    expect(screen.getByRole("status")).toHaveTextContent(frenchMessages.accounts.noResults);
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("should translate the expiration tooltip using the real session time", async () => {
    vi.stubGlobal(
      "ResizeObserver",
      class {
        observe = vi.fn();
        unobserve = vi.fn();
        disconnect = vi.fn();
      },
    );
    renderList([makeSession()], "fr");
    fireEvent.focus(screen.getByRole("button", { name: /Alice.*alice@example.com/ }));
    expect(await screen.findByRole("tooltip")).toHaveTextContent(/^Expire /);
  });
});
